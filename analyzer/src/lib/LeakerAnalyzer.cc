/*
 * Copyright (C) 2019 Yueqi (Lewis) Chen, Zhenpeng Lin
 *
 * For licensing details see LICENSE
 */

#include <llvm/IR/TypeFinder.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/Pass.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/Debug.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Constants.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/Analysis/CallGraph.h>
#include <llvm/IR/CFG.h>

#include "LeakerAnalyzer.h"
#include "Annotation.h"

using namespace llvm;
using namespace std;

extern cl::opt<bool> IgnoreReachable;

// doInitialization —— 识别模块中有body定义的StructType并存入 Ctx->moduleStructMap，识别能通过mbuf泄露内核数据的函数——Ctx->LeakAPIs。    initialize moduleStructMap
bool LeakerAnalyzerPass::doInitialization(Module* M) {

    StructTypeSet structTypeSet;
    TypeFinder usedStructTypes;
    usedStructTypes.run(*M, false);                 // 识别module中用到的所有 StructType

    for (TypeFinder::iterator itr = usedStructTypes.begin(), 
            ite = usedStructTypes.end(); itr != ite; itr++) {

        StructType* st = *itr;
        // only deal with non-opaque type
        if (st->isOpaque())                         // 跳过没有body的struct
            continue;
        // OP<<"-------------"<<st->getStructName().str()<<"\n";
        structTypeSet.insert(st);
    }

    Ctx->moduleStructMap.insert(std::make_pair(M, structTypeSet));

    if(Ctx->LeakAPIs.size() == 0){                  // composeMbufLeakAPI —— 若某函数中存在call指令调用了包含mbuf形参的函数，则将其加入到Ctx->LeakAPIs（表示可利用mbuf泄露内核数据的调用点），能到达该泄露点的路径上的函数也加入到 Ctx->LeakAPIs。
        composeMbufLeakAPI();
    }

    return false;
}

// doModulePass —— 确定是否可分配、可泄露，结果存于 allocInstMap 和 leakInstMap。 识别StructType的分配点 - allocInstMap，识别泄露点的len和buf的source struct - leakInstMap (确保分配点和泄露点都不需要特权)。    determine "allocable" and "leakable" to compute allocInstMap and leakInstMap
bool LeakerAnalyzerPass::doModulePass(Module* M) {

    ModuleStructMap::iterator it = Ctx->moduleStructMap.find(M);
    assert(it != Ctx->moduleStructMap.end() && 
            "M is not analyzed in doInitialization");

    // no flexible structure usage in this module
    // TODO Lewis: is this a golden rule?
    // Counter example: leak in M1, struct info in M2 and pass to M1
    if (it->second.size() == 0)
        return false;

	for (Function &F : *M)
        runOnFunction(&F);  // runOnFunction —— 找到能到达F函数的syscall集合——reachableSyscallCache，遍历F中的call指令，analyzeAlloc()——确定分配出来的 StructType 并存入 Ctx->leakStructMap->StructInfo->allocaInst; analyzeLeak()——从call泄露点开始反向数据流分析，找到len和buf的source struct信息，存到 Ctx->leakStructMap -> StructInfo -> SiteInfo 。

    return false;
}
// isPriviledged —— 检查函数F是否被特权设备调用，递归遍历F的调用者
// check if the function is called by a priviledged device
// return true if the function is priviledged.
bool LeakerAnalyzerPass::isPriviledged(llvm::Function *F) {
    return false;
    SmallVector<Function*, 4> workList;
    workList.clear();
    workList.push_back(F);

    FuncSet seen;
    seen.clear();

    while (!workList.empty()) {
        Function* F = workList.pop_back_val();

        // check if the function lies in the deny list  需要特权则返回true
        if (Ctx->devDenyList.find(F) != Ctx->devDenyList.end()) {
            return true;
        }

        if (!seen.insert(F).second)
            continue;

        CallerMap::iterator it = Ctx->Callers.find(F);
        if (it != Ctx->Callers.end()) {
            for (auto calleeInst: it->second) {
                Function* F = calleeInst->getParent()->getParent();
                workList.push_back(F);              // 递归遍历F的调用者
            }
        }
    }
    return false;
}


// runOnFunction —— 找到能到达F函数的syscall集合——reachableSyscallCache，遍历F中的call指令，analyzeAlloc()——确定分配出来的 StructType 并存入 Ctx->leakStructMap->StructInfo->allocaInst; analyzeLeak()——从call泄露点开始反向数据流分析，找到len和buf的source struct信息，存到 Ctx->leakStructMap -> StructInfo -> SiteInfo 。 start analysis from calling to allocation or leak functions
void LeakerAnalyzerPass::runOnFunction(Function *F) {
    flag_debug = 0;
    //if (!F->getName().str().find("x509_cert_parse"))      // 输出可达函数
    //    flag_debug = 3;
    // OP<<"                     -------- Function: "<<F->getName()<<"---------"<<"\n";
// (1) F 必须从用户 syscall 可达
    if(!IgnoreReachable){           
        FuncSet Syscalls = reachableSyscall(F);     // reachableSyscall —— 找到能够到达F函数的syscall集合，存入 reachableSyscallCache。
        if(Syscalls.size() == 0){
            return;
        }
        KA_LOGS(1, F->getName() << " can be reached by " << Syscalls.size() << " syscalls\n");
    }
    // OP<<"                     ******** Function: "<<F->getName()<<"********"<<"\n";
// (2) 跳过boot时的初始化函数
    // skip functions in .init.text which is used only during booting
    if(F->hasSection() && F->getSection().str() == ".init.text")
        return;
    // test to output block name

// (3) 遍历F中的call指令，如果是调用分配函数，则执行 analyzeAlloc(),如果调用泄露函数，则执行 analyzeLeak()。
    for (inst_iterator i = inst_begin(F), e = inst_end(F); i != e; i++) {
        Instruction* I = &*i;
        if (CallInst *callInst = dyn_cast<CallInst>(I)) {
            const Function* callee = callInst->getCalledFunction();
            if (!callee)
                callee = dyn_cast<Function>(callInst->getCalledValue()->stripPointerCasts());
            if (callee) {
                std::string calleeName = callee->getName().str();
                if (isCall2Alloc(calleeName)) {
                    analyzeAlloc(callInst);             // flexible part  analyzeAlloc —— 根据分配点找到分配出来的 StructType,再将 struct name 和对应的分配指令保存到 Ctx->leakStructMap->StructInfo->allocaInst。
                } /*else if (isCall2Leak(calleeName)) {
                    analyzeLeak(callInst, calleeName);  // leakable part  analyzeLeak —— 先根据call泄露点确定len和buf参数 (确保call泄露点不需要特权)，然后进行前向数据流分析，找到len和buf的source struct信息，存到 Ctx->leakStructMap->StructInfo->SiteInfo 。
                }*/ else if (isCall2Free(calleeName)) {
                    if (isInstFromErrBlock(callInst))                 // 改进5：忽略错误处理块中的指令
                        continue;
                    analyzeFree(callInst, calleeName);
                }else {
                    ; // other function
                }
            }
        }
    }
    return;
}
// isCall2Alloc —— 是否为分配函数 allocAPIVec。
bool LeakerAnalyzerPass::isCall2Alloc(std::string calleeName) {
    if (std::find(allocAPIVec.begin(), allocAPIVec.end(), 
            calleeName) != allocAPIVec.end())
        return true;
    else if(calleeName.find("alloc") != std::string::npos
             || calleeName.find("ALLOC") != std::string::npos)
        // aggressive analysis
        return true;    
    return false;
}
// isCall2Leak —— 是否为泄露函数 leakAPIVec。
bool LeakerAnalyzerPass::isCall2Leak(std::string calleeName) {
    if (std::find(leakAPIVec.begin(), leakAPIVec.end(),
            calleeName) != leakAPIVec.end())
        return true;
    else if (calleeName.find("memcpy") != string::npos)
        return true;
    else
        return false;
}
// isCall2Free —— 是否为释放函数 freeAPIVec。
bool LeakerAnalyzerPass::isCall2Free(std::string calleeName) {
    if (std::find(freeAPIVec.begin(), freeAPIVec.end(), 
            calleeName) != freeAPIVec.end())
        return true;
    else if(calleeName.find("free") != std::string::npos
             || calleeName.find("FREE") != std::string::npos)
        // aggressive analysis
        return true;    
    return false;
}

void LeakerAnalyzerPass::backwardUseAnalysis(llvm::Value *V, std::set<llvm::Value *> &DefineSet){
    // TODO: handle reg2mem store load pair
    if(auto *I = dyn_cast<Instruction>(V)){
        KA_LOGS(2, "backward handling " << *I << "\n");
        if(I->isBinaryOp() || dyn_cast<ICmpInst>(I)){
            KA_LOGS(2, *I << " backward Adding " << *V << "\n");
            DefineSet.insert(V);

            for (unsigned i = 0, e = I->getNumOperands(); i != e; i++) {
                Value* Opd = I->getOperand(i);
                KA_LOGS(2, "backward Adding " << *V << "\n");
                DefineSet.insert(V);
                if (dyn_cast<ConstantInt>(Opd))
                    continue;
                backwardUseAnalysis(Opd, DefineSet);
            }

        } else if(dyn_cast<CallInst>(I) ||
                      dyn_cast<SelectInst>(I)){
            KA_LOGS(2, "backward Adding " << *V << "\n");
            DefineSet.insert(V);
        } else if(auto *PN = dyn_cast<PHINode>(I)){

            if(DefineSet.find(V) != DefineSet.end())
                return;

            KA_LOGS(2, "backward Adding " << *V << "\n");
            DefineSet.insert(V);
            // aggressive analysis
            for (unsigned i = 0, e = PN->getNumIncomingValues(); i != e; i++) {
                Value* IV = PN->getIncomingValue(i);
                if (dyn_cast<ConstantInt>(IV))
                    continue;
                backwardUseAnalysis(IV, DefineSet);
            }

        }else if(UnaryInstruction* UI = dyn_cast<UnaryInstruction>(V)){
            KA_LOGS(2, "backward Adding " << *V << "\n");
            DefineSet.insert(V);

            backwardUseAnalysis(UI->getOperand(0), DefineSet);
        }else if(auto *GEP = dyn_cast<GetElementPtrInst>(I)){
            // may come from the same struct
            KA_LOGS(2, "backward Adding " << *V << "\n");
            DefineSet.insert(V);

            backwardUseAnalysis(GEP->getOperand(0), DefineSet);
        }else{
            errs() << "Backward Fatal errors , please handle " << *I << "\n";
            // exit(0);
        }
    }else{
        // argument
        KA_LOGS(2, "Backward Adding " << *V << "\n");
        DefineSet.insert(V);
    }
}

llvm::Value* LeakerAnalyzerPass::getOffset(llvm::GetElementPtrInst *GEP){
    // FIXME: consider using more sophisicated method
    // Use the last indice of GEP
    return GEP->getOperand(GEP->getNumIndices());
}
// isGEPGetPtr —— 判断GEP指令是否从结构中取指针
bool LeakerAnalyzerPass::isGEPGetPtr(llvm::GetElementPtrInst *GEP, llvm::StructType* stType)
{
    if (GEP->getNumOperands() == 3)
    {
        ConstantInt *CI = dyn_cast<ConstantInt>(GEP->getOperand(2));                // 2 or 1 ???????????????????   也就是第2个下标
        assert(CI != nullptr && "GEP's index is not constant");
        uint64_t offset = CI->getZExtValue();

        if (stType->getElementType(offset)->isPointerTy())
            return true;
    } else                                                                          // GEP 有超过3个下标，则为嵌套结构，需递归遍历
    {
        Type* subType = stType;
        for (int i = 2; i <= GEP->getNumOperands() - 1; i++)
        {
            if (const StructType* st = dyn_cast<StructType>(subType))
            {
                ConstantInt *CI = dyn_cast<ConstantInt>(GEP->getOperand(i));
                assert(CI != nullptr && "GEP's index is not constant");
                uint64_t offset = CI->getZExtValue();

                if (st->getElementType(offset)->isPointerTy())                      // pointer
                    return true;
                else
                    subType = st->getElementType(offset);                           // recursion
            } else if (const ArrayType* arrayType = dyn_cast<ArrayType>(subType))
            {
                if (arrayType->getElementType()->isPointerTy())                     // pointer
                    return true;
                else 
                    subType = arrayType->getElementType();                          // recursion
            } else {
                return false;
            }
        }
    }
    return false;
}
// isGEPIndexNegative —— 判断GEP的第2个下标是否为负数，是则返回true
bool LeakerAnalyzerPass::isGEPIndexNegative(llvm::GetElementPtrInst *GEP)
{
    ConstantInt *CI = dyn_cast<ConstantInt>(GEP->getOperand(1));
    if (CI == nullptr)
        return false;
    // assert(CI != nullptr && "GEP's index is not constant");
    int64_t offset = CI->getSExtValue();

    if (offset < 0)
        return true;
    else 
        return false;
    return false;
}

// isInstFromErrBlock —— 判断释放点和GEP指令是否位于错误处理块
bool LeakerAnalyzerPass::isInstFromErrBlock(llvm::Instruction *Inst)
{
    BasicBlock *bb = Inst->getParent();
    for (auto &II : *bb)
    {
        if (llvm::DbgLabelInst *labelInst = dyn_cast<DbgLabelInst>(&II))            // (1) 若第1条指令是 DbgLabelInst, 则表示该基本块有标签名; 补充，有的不是第1条，需遍历每条指令
        {
            // OP<<"Find one!!!\n";
            StringRef bbName(labelInst->getLabel()->getName());
            // if (!bbName.empty())
            //    OP<<"[--]------------Block Name:   "<<bbName.str()<<"\n";
            if (/*(bbName.str().find("out") != llvm::StringRef::npos) || */
                (bbName.str().find("clean") != llvm::StringRef::npos) || 
                (bbName.str().find("err") != llvm::StringRef::npos) || 
                (bbName.str().find("exit") != llvm::StringRef::npos) ||
                (bbName.str().find("fail") != llvm::StringRef::npos) /* ||
                (bbName.str().find("free") != llvm::StringRef::npos)*/)
                return true;
        }
        // else
        //    break;
    }
    for (BasicBlock *predBB : predecessors(bb)) 
    // for (auto it = pred_begin(bb), et = pred_end(bb); it != et; ++it)                                       // (2) 有可能被错误处理块调用，这里我们只分析一层
    {
        // BasicBlock* predBB = *it;
        for (auto &II : *predBB)
        {
            if (llvm::DbgLabelInst *labelInst = dyn_cast<DbgLabelInst>(&II))            
            {
                // OP<<"Find one!!!\n";
                StringRef bbName(labelInst->getLabel()->getName());
                // if (!bbName.empty())
                //    OP<<"[--]------------Block Name:   "<<bbName.str()<<"\n";
                if (/*(bbName.str().find("out") != llvm::StringRef::npos) || */
                    (bbName.str().find("clean") != llvm::StringRef::npos) || 
                    (bbName.str().find("err") != llvm::StringRef::npos) || 
                    (bbName.str().find("exit") != llvm::StringRef::npos) ||
                    (bbName.str().find("fail") != llvm::StringRef::npos) /* ||
                    (bbName.str().find("free") != llvm::StringRef::npos)*/) 
                    return true;
            }
        }
    }

    return false;
}
// isInstPassPrivilege() —— 判断该指令是否经过 capable(CAP_SYS_ADMIN) 函数   #define CAP_SYS_ADMIN        21
bool LeakerAnalyzerPass::isInstPassPrivilege(llvm::Function *F, llvm::Instruction *Inst)
{
    for (inst_iterator i = inst_begin(F), e = inst_end(F); i != e; i++)
    {
        Instruction* I = &*i;
        if (I == Inst) 
        {
            // OP<<"|||||||||||||||||||||| find in advance\n";                 // 检测 == 是否有用
            return false;
        }
        if (CallInst *callInst = dyn_cast<CallInst>(I))
        {
            const Function* callee = callInst->getCalledFunction();
            if (!callee)
                callee = dyn_cast<Function>(callInst->getCalledValue()->stripPointerCasts());
            if (callee) {
                std::string calleeName = callee->getName().str();
                if (calleeName.find("capable") != std::string::npos) 
                {
                    Value *v= callInst->getArgOperand(0);
                    if (ConstantInt *Ct = dyn_cast<ConstantInt>(v))
                    {
                        // OP<<"------------------- find a capable: argument = "<<Ct->getSExtValue()<<"\n";            // 检测是否找到 capable 语句
                        if ((Ct->getSExtValue() & 21) == 21)
                            return true;
                    }
                    // if (isa<ConstantInt>(BO->getOperand(1))) {
                    // Constant* Ct = dyn_cast<Constant>(V);      Value* V
                }
            }
        }
    }
    return false;
}

int LeakerAnalyzerPass::getline(llvm::CallInst* callInst)
{
    Instruction *Inst = dyn_cast<Instruction>(callInst);
    if (DILocation* Loc = Inst->getDebugLoc())
    {
        unsigned line = Loc->getLine();
        return line;
    }
    else 
        return 0;
    // string file = Loc->getFilename();
    // unsigned line = Loc->getLine();
}

void LeakerAnalyzerPass::outputSources(std::vector<llvm::Value *> &srcSet)
{
    OP<<"------------ output source ------------\n";
    for (std::vector<llvm::Value*>::iterator i = srcSet.begin(),
        e = srcSet.end(); i != e; i++)
    {
        Value *V = *i;
        if (Instruction *I = dyn_cast<Instruction>(V))
        {
            if (DILocation* Loc = I->getDebugLoc()) 
            {
                string file = Loc->getFilename();
                unsigned line = Loc->getLine();
                errs() << file << ":"  << line << "\n";
            }
            errs() << I->getModule()->getName().str();
            errs() << ":";
            errs() << I->getFunction()->getName().str();
            errs() << "\n" << *I << "\n";
        }
    }
}

void LeakerAnalyzerPass::forwardAnalysis(llvm::Value *V, 
                                        std::set<llvm::StoreInst *> &StoreInstSet,
                                        std::set<llvm::Value *> &TrackSet){


    for (auto *User : V->users()){

        if(TrackSet.find(User) != TrackSet.end())
            continue;

        TrackSet.insert(User);

        KA_LOGS(2, "Forward " << *User << "\n");

        // FIXME: should we check if V is SI's pointer?
        if(StoreInst *SI = dyn_cast<StoreInst>(User)){
            StoreInstSet.insert(SI);

            // forward memory alias
            Value *SV = SI->getValueOperand();
            Value *SP = SI->getPointerOperand();

            for(auto *StoreU : SP->users()){
                // alias pair
                if(dyn_cast<LoadInst>(StoreU)){
                    KA_LOGS(2, "Found Store and Load pair " << *StoreU << " " << *User << "\n");
                    forwardAnalysis(StoreU, StoreInstSet, TrackSet);
                }
            }

            // handle struct alias
            if(auto *GEP = dyn_cast<GetElementPtrInst>(SP)){
                Value *red_offset = getOffset(GEP);
                Value *red_obj = GEP->getOperand(0);
                
                KA_LOGS(2, "Marking " << *red_obj << " as red\n");

                for(auto *ObjU : red_obj->users()){
                    if(auto *ObjGEP = dyn_cast<GetElementPtrInst>(ObjU)){

                        if(ObjGEP != GEP && getOffset(ObjGEP) == red_offset){
                            // we found it
                            // and then check if its user is LOAD.
                            for(auto *OGEPUser : ObjGEP->users()){
                                if(dyn_cast<LoadInst>(OGEPUser)){
                                    KA_LOGS(2, "Solved Alias : " << *OGEPUser << " == " << *User << "\n");
                                    forwardAnalysis(OGEPUser, StoreInstSet, TrackSet);
                                }
                            }
                        }
                    }
                }
                // should we forward sturct ?

            }
        } else if(dyn_cast<GetElementPtrInst>(User) ||
                    dyn_cast<ICmpInst>(User) ||
                        dyn_cast<BranchInst>(User) ||
                    dyn_cast<BinaryOperator>(User)){

            forwardAnalysis(User, StoreInstSet, TrackSet);

        } else if(dyn_cast<CallInst>(User) ||
                    dyn_cast<CallBrInst>(User) ||
                    dyn_cast<SwitchInst>(User) ||
                        dyn_cast<ReturnInst>(User)){

                continue;

        // } else if(dyn_cast<UnaryInstruction>(User)){
        } else if(dyn_cast<SExtInst>(User) || dyn_cast<ZExtInst>(User)
                    || dyn_cast<TruncInst>(User)){

            forwardAnalysis(User, StoreInstSet, TrackSet);

        } else if(dyn_cast<PHINode>(User) || 
                    dyn_cast<SelectInst>(User) ||
                        dyn_cast<LoadInst>(User) ||
                    dyn_cast<UnaryInstruction>(User)){
                            
            // TODO: forward PHI node
            forwardAnalysis(User, StoreInstSet, TrackSet);

        } else {
            errs() << "\nForwardAnalysis Fatal errors , please handle " << *User << "\n";
            // exit(0);
        }
    }
}

// analyzeAlloc —— 根据分配点找到分配出来的 StructType,再将 struct name 和对应的分配指令保存到 Ctx->leakStructMap->StructInfo->allocaInst。
// customize flexible part here
// every time adding a new struct to allocInstMap, 
// update allocSyscallMap
void LeakerAnalyzerPass::analyzeAlloc(llvm::CallInst* callInst) {

    StructType* stType;
    Function *F;
    Module *M;

    M = callInst->getModule();
    F = callInst->getCalledFunction();  // F——被调用函数
// (1) 找到分配函数分配出来的 struct类型 —— stType
    if (!F) {
        if (Function *FF = dyn_cast<Function>(callInst->getCalledValue()->stripPointerCasts())) {
            F = FF;
        }
    }

    if (F) {
        Type *baseType = F->getReturnType();
        stType = dyn_cast<StructType>(baseType);                // stType —— 返回值的结构类型
    }

    if (!stType) {
        for (auto *callUser : callInst->users()) {
            if (auto *BCI = dyn_cast<BitCastInst>(callUser)) {  // 返回值 被用于 BitCastInst 指令，目标指针可能指向 StructType 类型
                KA_LOGS(1, "Found BitCast: "<< *BCI << "\n");
                PointerType* ptrType = dyn_cast<PointerType>(BCI->getDestTy());
                Type* baseType = ptrType->getElementType();
                stType = dyn_cast<StructType>(baseType);
                if (stType == nullptr)
                    continue;
                break;
            } else if (auto *SI = dyn_cast<StoreInst>(callUser)) {

            } else if (auto *LI = dyn_cast<LoadInst>(callUser)) {

            }
        }
    }

    if (!stType)
        return;
// (2) 将 struct name 和对应的分配指令保存起来，存到  Ctx->leakStructMap[1]->allocaInst
    // compose allocInst map
    string structName = getScopeName(stType, M);

    
    KA_LOGS(1, "We found " << structName << "\n");
    if (structName.find("struct") == string::npos)
        return;

    Function *body = callInst->getFunction();
    if (isPriviledged(body)) {      // isPriviledged —— 检查函数F是否被特权设备调用，递归遍历F的调用者
        outs() << body->getName() << " is priviledged function for allocating\n";
        return;
    }

    LeakStructMap::iterator it = Ctx->leakStructMap.find(structName);
    if (it != Ctx->leakStructMap.end()) {                                   // 若存在，将 struct 对应到分配点 —— Ctx->leakStructMap->StructInfo->allocaInst

        it->second->allocaInst.insert(callInst);

    } else {
        StructInfo *stInfo = Ctx->structAnalyzer.getStructInfo(stType, M);  // getStructInfo —— 根据StructType获取对应的 StructInfo。若不存在，则新建 StructInfo
        if (!stInfo) return;
        stInfo->allocaInst.insert(callInst);
        Ctx->leakStructMap.insert(std::make_pair(structName, stInfo));
    }
// (3) 将 struct name 和对应的分配指令保存起来，存到  Ctx->freeStructMap[1]->allocaInst
    OP<<"++++++++ Find an alloc struct: "<<structName<<"\n";

    LeakStructMap::iterator it2 = Ctx->freeStructMap.find(structName);
    if (it2 != Ctx->freeStructMap.end()) {                                   // 若存在，将 struct 对应到分配点 —— Ctx->leakStructMap->StructInfo->allocaInst

        it2->second->allocaInst.insert(callInst);

    } else {
        StructInfo *stInfo = Ctx->structAnalyzer.getStructInfo(stType, M);  // getStructInfo —— 根据StructType获取对应的 StructInfo。若不存在，则新建 StructInfo
        if (!stInfo) return;
        stInfo->allocaInst.insert(callInst);
        Ctx->freeStructMap.insert(std::make_pair(structName, stInfo));
    }
}
// argContainType —— 判断F的参数是否包含 指向 typeName类型的指针。
static bool argContainType(Function *F, string typeName) {
    for (auto arg = F->arg_begin(); arg != F->arg_end(); ++arg) {
        PointerType* ptrType = dyn_cast<PointerType>(arg->getType());
        if (ptrType == nullptr)
            continue;

        Type* baseType = ptrType->getElementType();
        StructType* stType = dyn_cast<StructType>(baseType);
        if (stType == nullptr)
            continue;

        if (stType->getName() == typeName)
            return true;
    }
    return false;
}
// argContainType —— 判断F的参数是否包含 指向 "struct.mbuf" 类型的指针。
static bool argContainMbuf(Function *F) {
    return argContainType(F, "struct.mbuf");
}
// addToFuncSet —— F加入到markedFuncSet。
static bool addToFuncSet(Function *F, FuncSet &markedFuncSet) {
    if (F && markedFuncSet.find(F) == markedFuncSet.end()) {
        markedFuncSet.insert(F);
        return true;
    }
    return false;
}

static bool addToCallInstSet(CallInst *CI, CallInstSet &CISet) {
    if (CI && CISet.find(CI) == CISet.end()) {
        CISet.insert(CI);
        return true;
    }
    return false;
}
// isSndbuf —— 检查该参数是否来自 snd_buf, 从GEP取过来
static bool isSndbuf(Value *V) {
    if (auto *GEP = dyn_cast<GetElementPtrInst>(V)) {
        PointerType* ptrType = dyn_cast<PointerType>(GEP->getPointerOperandType());
        if(!ptrType)
            return false;

        Type* baseType = ptrType->getElementType();
        StructType* stType = dyn_cast<StructType>(baseType);

        if (stType->getName() != "struct.socket")       // 指针指向的类型为socket类型, struct.socket[0][19] 为 snd_buf
            return false;

        if (GEP->getNumIndices() != 2)
            return false;

        if (auto *offset1 = dyn_cast<ConstantInt>(GEP->getOperand(1))) {
            if (auto *offset2 = dyn_cast<ConstantInt>(GEP->getOperand(2))) {
                if (offset1->getZExtValue() == 0 && offset2->getZExtValue() == 19) {
                    return true;
                }
            }
        }
    }
    return false;
}

bool LeakerAnalyzerPass::isMbufData(Value *buf) {
    std::vector<Value *> srcBufSet;
    std::set<Value *> trackedBufSet;
    findSources(buf, srcBufSet, trackedBufSet);

    for (std::vector<llvm::Value*>::iterator i = srcBufSet.begin(),
         e = srcBufSet.end(); i != e; i++) {
        Value *V = *i;
        if (auto *callInst = dyn_cast<CallInst>(V)) {

        } else if (auto *GEP = dyn_cast<GetElementPtrInst>(V)) {
            if (GEP->getNumIndices() == 1)
                continue;

            PointerType* ptrType = dyn_cast<PointerType>(GEP->getPointerOperandType());
            if (ptrType == nullptr)
                continue;
            Type* baseType = ptrType->getElementType();
            StructType* stType = dyn_cast<StructType>(baseType);
            if (stType == nullptr)
                continue;
            ConstantInt *CI = dyn_cast<ConstantInt>(GEP->getOperand(2));
            if (CI->getZExtValue() != 2)
                continue;

            if (stType->getName() == "struct.mbuf") {
                return true;
            }
        }
    }
    return false;

}
// composeMbufLeakAPI —— 若某函数中存在call指令调用了包含mbuf形参的函数，则将其加入到Ctx->LeakAPIs（表示可利用mbuf泄露内核数据的调用点），能到达该泄露点的路径上的函数也加入到 Ctx->LeakAPIs
void LeakerAnalyzerPass::composeMbufLeakAPI() {

    CallInstSet LeakInst;
    FuncSet trackedFuncSet;
// (1) 遍历函数，被调用过的函数存入 trackedFuncSet, 如果其参数（形参）含 "struct.mbuf" 且其调用指令传参 snd_buf（实参），则保存该call指令——LeakInst（可泄露内核数据）。
    for (auto M : Ctx->Callers) {
        Function *F = M.first;

        if(!addToFuncSet(F, trackedFuncSet))        // F 加入到 trackedFuncSet
            continue;

        if(!argContainMbuf(F))                      // argContainType —— 判断F的形参是否包含 指向 "struct.mbuf" 类型的指针。不包含则跳过不分析。
            continue;

        if(argContainType(F, "struct.sockbuf")){    // 若形参是 sockbuf 指针，实参是 snd_buf，则将该call指令存入 LeakInst
            // if the sockbuf is coming from sock's snd_buf
            CallerMap::iterator it = Ctx->Callers.find(F);
            if (it == Ctx->Callers.end()) {
                continue;
            }
            CallInstSet &CIS = it->second;

            for(CallInst *CI : CIS){
                // check if sockbuf is snd_buf
                for(unsigned i=0; i<CI->getNumArgOperands(); i++){
                    if(isSndbuf(CI->getArgOperand(i))){
                        addToCallInstSet(CI, LeakInst);     // 若传入参数（实参）来自 snd_buf 则该调用可以泄露内核数据。将该call指令存入 LeakInst。
                        KA_LOGS(1, "LEAK API: " <<  CI->getFunction()->getName() << " --------\n");
                        KA_LOGS(1, "CallInst : ");
                        DEBUG_Inst(1, CI);
                        KA_LOGS(1, "\n");
                    }
                }
            }
        }
    }

    SmallVector<Function*, 4> workList;

    workList.clear();
// (2) 将能到达泄漏点 LeakInst （mbuf泄露点）的路径上的函数都存入Ctx->LeakAPIs（workList递归向上遍历）
    for( auto *CI : LeakInst){
        Function *F = CI->getFunction();
        if(!F)
            continue;
        workList.push_back(F);
    }

    trackedFuncSet.clear();

    while(!workList.empty()){
        Function* FF = workList.pop_back_val();

        // already checked FF
        if(!addToFuncSet(FF, trackedFuncSet))
            continue;

        // add before checking mbuf in argument
        // so as to include top APIs that don't
        // have mbuf in arguments.
        addToFuncSet(FF, Ctx->LeakAPIs);       // 将 mbuf 泄露函数存入 Ctx->LeakAPIs，加入前需检查形参是否含mbuf    —— 反向路径

        if(!argContainMbuf(FF))
            continue;

        CallerMap::iterator it = Ctx->Callers.find(FF);
        if (it == Ctx->Callers.end()) {
            continue;
        }
        CallInstSet &CIS = it->second;

        for (CallInst *CI : CIS) {              // 递归找 FF 的 caller 所在的函数
            Function *CallerF = CI->getParent()->getParent();
            workList.push_back(CallerF);
        }
    }
// (3) 补充：若 Ctx->LeakAPIs 路径上的函数中的指令，只要有call指令调用了包含mbuf形参的函数，则把该函数也加入到Ctx->LeakAPIs —— 反向路径上的分支
    FuncSet tmpFuncSet;
    for(auto *FF : Ctx->LeakAPIs){
        for (inst_iterator i = inst_begin(FF), e = inst_end(FF); i != e; i++) {
            Instruction* I = &*i;
            if(auto *CI = dyn_cast<CallInst>(I)){
                Function *F = CI->getCalledFunction();
                if(F && argContainMbuf(F)){
                    KA_LOGS(1, "adding " << F->getName() << " to LeakAPIs\n");
                    addToFuncSet(F, tmpFuncSet);
                }
            }
        }
    }

    for(auto *FF : tmpFuncSet){
        addToFuncSet(FF, Ctx->LeakAPIs);
    }

    for(auto *FF : Ctx->LeakAPIs){
        KA_LOGS(0, "Function : " << FF->getName() << "\n");
    }
}
// analyzeLeak —— 追踪泄露信道的buffer和length参数，若都来自弹性结构则可泄露。对不同的泄露函数，分开分析。   先根据call泄露点确定len和buf参数 (确保call泄露点不需要特权)，然后进行反向数据流分析，找到len和buf的source struct信息，存到 Ctx->leakStructMap->StructInfo->SiteInfo 。
// determine leakable: track buffer and length argument in the leaking channel
// leakable if both arguments come from flexible structure's field
void LeakerAnalyzerPass::analyzeLeak(llvm::CallInst* callInst, std::string calleeName) {

    llvm::Function* F = callInst->getParent()->getParent();     // F —— call指令所在的函数
    KA_LOGS(1, "\n<<<<<<<<< Analyzing calling to " + calleeName + 
                "() in " + F->getName().str() + "()\n");

    Value* len = nullptr;
    Value* buf = nullptr;
// (1) 根据不同的泄露函数，获取 len 和 buf 参数。
    if (calleeName == "put_user") { 
        // FIXME, this is a macro
        // deal with this later if necessary

    } else if (calleeName == "copy_to_user") {
        if (callInst->getNumArgOperands() != 3) { 
            KA_LOGS(1, "[-] Weird copy_to_user(): ");
            KA_LOGV(1, callInst);
            return;
        }

        len = callInst->getArgOperand(2);
        buf = callInst->getArgOperand(1);

    } else if (calleeName == "_copy_to_user") {
        if (callInst->getFunction()->getName() == "copy_to_user") {
            return;
        }
        if (callInst->getNumArgOperands() != 3) { 
            KA_LOGS(1, "[-] Weird copy_to_user(): ");
            KA_LOGV(1, callInst);
            return;
        }

        len = callInst->getArgOperand(2);
        buf = callInst->getArgOperand(1);

    } else if (calleeName == "nla_put") {
        if (callInst->getNumArgOperands() != 4) {
            KA_LOGS(1, "[-] Weird nla_put(): ");
            KA_LOGV(1, callInst);
            return;
        }

        // Heuristic 2, duplicate with Heuristic 1 but save time and space
        if (F->getName().str() == "nla_put_string")         // nla_put_string() 调用 nla_put(), 退出, 避免重复分析
            return;

        len = callInst->getArgOperand(2);
        buf = callInst->getArgOperand(3);

    } else if (calleeName == "skb_put_data") {
        if (callInst->getNumArgOperands() != 3) {
            KA_LOGS(1, "[-] Weird skb_put_data(): ");
            KA_LOGV(1, callInst);
            return;
        }
        len = callInst->getArgOperand(2);
        buf = callInst->getArgOperand(1);
    } else if (calleeName == "nlmsg_data" ||
               calleeName == "nla_data" ||
               calleeName == "skb_put") {

        // Heuristic 2, avoid duplication of leak site
        if (calleeName == "skb_put" &&                      // skb_put_data() 调用 nla_put(), 退出, 避免重复分析
            F->getName().str() == "skb_put_data")
            return;

        Value* V = callInst;
        // if return value is used as des in memcpy 
        checkChannelUsageinFunc(V, len, buf);               // checkChannelUsageinFunc —— 若返回值V用于memcpy的dst地址, 则buf、len为memcpy的src; 若返回值V用于memcpy的src地址，则buf、len都为null。(V是调用泄露函数的参数buf???)

        
        /*
        for (Value::use_iterator ui = V->use_begin(), ue = V->use_end();
            ui != ue; ui++) {
            if (auto *I = dyn_cast<Instruction>(ui->getUser())) {
                if (auto* callInst = dyn_cast<CallInst>(I)) {
                    const Function* callee = callInst->getCalledFunction();
                    if (callee ==  nullptr)
                        continue;
                    std::string calleeName = callee->getName().str();
                    if (calleeName == "__memcpy" ||
                        calleeName == "memcpy" ||
                        calleeName == "llvm.memcpy.p0i8.p0i8.i64") { 
                        len = callInst->getArgOperand(2);
                        buf = callInst->getArgOperand(1);
                        break;
                    }
                }
            }
        }
        */
        

        if (len == nullptr || buf == nullptr)
            return ;

    }
// #define XNU
// #define FREEBSD
#ifdef XNU
    else if (calleeName == "copyout") {
        if (callInst->getNumArgOperands() != 3) { 
            KA_LOGS(1, "[-] Weird copyout(): ");
            KA_LOGV(1, callInst);
            return;
        }

#ifdef FREEBSD
        // discard this copyout if it is called
        // by uiomove since we have marked uiomove
        // as a leaking channel
        Function *F = callInst->getFunction();
        if (F->getName() == "uiomove_faultflag") {
            return;
        }
#endif

        len = callInst->getArgOperand(2);
        buf = callInst->getArgOperand(0);
    } else if (Ctx->LeakAPIs.find(F) != Ctx->LeakAPIs.end()){       // 若属于 通过mbuf泄露的函数
        if (calleeName == "m_copyback"){
            buf = callInst->getArgOperand(3);
            len = callInst->getArgOperand(2);
        } else if (calleeName == "m_append"){
            buf = callInst->getArgOperand(2);
            len = callInst->getArgOperand(1);
        } else if (calleeName.find("memcpy") != std::string::npos){
            Value *mbuf = callInst->getArgOperand(0);
            if (!isMbufData(mbuf))
                return;
            buf = callInst->getArgOperand(1);
            len = callInst->getArgOperand(2);
        }
    } else if (true){
        return;
    }
#endif

#ifdef FREEBSD
    else if (calleeName == "uiomove") {
        buf = callInst->getArgOperand(0);
        len = callInst->getArgOperand(1);
    }
#endif
    else {
        RES_REPORT(calleeName << "\n");
        assert(false && "callee is not a leak channel");
    }

    assert(len != nullptr && buf != nullptr && 
          "both len & buf are not nullptr");

    // KA_LOGS(1, "----- Tracing Buffer --------\n");
    
    // std::vector<Value *> srcBufSet;
    // std::set<Value *> trackedBufSet;
    // findSources(buf, srcBufSet, trackedBufSet);
// (2) 检查 调用泄露函数是否需要特权。
    // check permission
    Function *body = callInst->getFunction();
    if (isPriviledged(body)) {
        outs() << body->getName() << " is priviledged function for leaking\n";
        return;
    }
// (3) 反向数据流分析，收集len的source
    KA_LOGS(1, "----- Tracing Length --------\n");
    std::vector<Value *> srcLenSet;
    std::set<Value *> trackedLenSet;
    findSources(len, srcLenSet, trackedLenSet); // findSources —— 反向数据流分析，追踪 len—V 的source，若V来自 CallInst返回值/BitCastInst/AllocaInst/null指针/常量/LoadInst/GetElementPtrInst 则加入到 srcSet。

    Module* M = F->getParent();
    StructTypeSet &stSet = Ctx->moduleStructMap[M];
    
// (4) 反向数据流分析，收集buf的source struct, 将len和buf的source信息存于 Ctx->leakStructMap -> StructInfo -> SiteInfo
    KA_LOGS(1, "----- Setup SiteInfo Length -------\n");
    setupLeakInfo(srcLenSet, callInst, buf);    // setupLeakInfo —— 检查和设置len的source struct信息，检查和设置buf的source struct信息，存于 Ctx->leakStructMap -> StructInfo -> SiteInfo
}

void LeakerAnalyzerPass::analyzeFree(llvm::CallInst* callInst, std::string calleeName) {
    llvm::Function* F = callInst->getParent()->getParent(); // F —— call指令所在的函数
    KA_LOGS(1, "\n<<<<<<<<< Analyzing calling to " + calleeName + 
                "() in " + F->getName().str() + "()\n");
    // flag_debug = 0;
// (1) 根据不同的释放函数，获取 buf 参数
    Value* buf = nullptr;
    if (calleeName == "kfree"){
 /*       if (!F->getName().str().find("security_msg_msg_free"))
        {
            flag_debug = 1;
            OP<<"[+][+][+] Find security_msg_msg_free's call kfree\n";
        } */
        if (callInst->getNumArgOperands() != 1) { 
            KA_LOGS(1, "[-] Weird kfree(): ");
            KA_LOGV(1, callInst);
            return;
        }
        buf = callInst->getArgOperand(0);
    } else if (calleeName == "kmem_cache_free") {
        if (callInst->getNumArgOperands() != 2) { 
            KA_LOGS(1, "[-] Weird kmem_cache_free(): ");
            KA_LOGV(1, callInst);
            return;
        }
        buf = callInst->getArgOperand(1);
    } /* else if(calleeName.find("free") != std::string::npos
             && calleeName.find("security") != std::string::npos){
        // if (!F->getName().str().find("free_msg"))
        // {
        //    flag_debug = 2;
        //    OP<<"[+][+][+] Find free_msg's call security_msg_msg_free\n";
        // }
        if (callInst->getNumArgOperands() != 1) { 
            KA_LOGS(1, "[-] Weird kfree(): ");
            KA_LOGV(1, callInst);
            return;
        }
        buf = callInst->getArgOperand(0);
    } */
    if (buf == nullptr) return;

// (2) 检查 调用释放函数是否需要特权
    Function *body = callInst->getFunction();
    if (isPriviledged(body)) {
        outs() << body->getName() << " is priviledged function for leaking\n";
        return;
    }
// (3) 反向数据流分析, 收集 buf 的source
    KA_LOGS(1, "----- Tracing buf ------\n");
    std::vector<Value *> srcBufSet;
    std::set<Value *> trackedBufSet;
    findSources(buf, srcBufSet, trackedBufSet);
    /*if (getline(callInst) == 176)                           // 输出所有source, 验证找到的source是否正确
    {
        outputSources(srcBufSet);
    } */
// (4) 找到buf所属的 struct 
    setupFreeInfo(srcBufSet, callInst, buf);
}
// checkChannelUsageinFunc —— 若返回值V用于memcpy的dst地址, 则buf、len为memcpy的src; 若返回值V用于memcpy的src地址，则buf、len都为null。(V是调用泄露函数的参数buf???)
void LeakerAnalyzerPass::checkChannelUsageinFunc(Value* V, Value*& len, Value*& buf) {

    for (Value::use_iterator ui = V->use_begin(), ue = V->use_end();       // V 被用于call memcpy指令的参数
        ui != ue; ui++) {
        if (auto* callInst = dyn_cast<CallInst>(ui->getUser())) {
            const Function* callee = callInst->getCalledFunction();
            if (callee == nullptr)
                continue;
            string calleeName = callee->getName().str();
            if (calleeName == "__memcpy" ||
                calleeName == "memcpy" ||
                calleeName == "llvm.memcpy.p0i8.p0i8.i64") {
                    len = callInst->getArgOperand(2);
                    buf = callInst->getArgOperand(1);

                    // make sure src != nla_data()
                    if(buf == V){
                        buf = nullptr;
                        len = nullptr;
                    }
                    return ;
            }

        } else if (auto* BCI = dyn_cast<BitCastInst>(ui->getUser())) {  // BitCastInst & GetElementPtrInst  V被传给其他变量，则递归。
            checkChannelUsageinFunc(BCI, len, buf);
        } else if (auto* GEP = dyn_cast<GetElementPtrInst>(ui->getUser())) {
            checkChannelUsageinFunc(GEP, len, buf);
        }
        
        if (len != nullptr && buf != nullptr)
            return;
    }
}

SmallPtrSet<Value *, 16> LeakerAnalyzerPass::getAliasSet(Value *V, Function *F){

    SmallPtrSet<Value *, 16> null;
    null.clear();

    auto aliasMap = Ctx->FuncPAResults.find(F);
    if(aliasMap == Ctx->FuncPAResults.end())
        return null;

    auto alias = aliasMap->second.find(V);
    if(alias == aliasMap->second.end()){
        return null;
    }

    return alias->second;
}
// findSources —— 前向数据流分析，追踪 len—V 的source，若V来自 CallInst返回值/BitCastInst/AllocaInst/null指针/常量/LoadInst/GetElementPtrInst 则加入到 srcSet。
void LeakerAnalyzerPass::findSources(Value* V, std::vector<llvm::Value *> &srcSet, std::set<llvm::Value* > &trackedSet) {

    // Lewis: hard coded boundary to save time 
    // and avoid stack overflow, I mean that "overflow", hahaha
    // TODO: solve alias in current function
    if (trackedSet.count(V) != 0
        //  || trackedSet.size() >= 8000
        )
        return;

    trackedSet.insert(V);                           // trackedSet —— 避免重复
    KA_LOGS(2, "FindSource: Adding ");KA_LOGV(2, V);
    // OP<<"----------------------------\n";
    // OP<<V->getName()<<"\n";
 // (1) V 来自 CallInst 的返回值。定为source，存入 srcSet。strlen/vmalloc/alloc/free 即为源，直接返回，其他函数则递归找返回值的source。
    // FIXME: Not examining called function inside can introduce FP
    // Lewis: this guess hits, add one chicken leg tonight!
    if (auto* CI = dyn_cast<CallInst>(V)) {     // CallInst
        // Storing callInst helps to check from value type
        srcSet.push_back(V);
        // Heuristic 1: calling to strlen()/vmalloc() isn't what we want
        const Function* callee = CI->getCalledFunction();
        if (callee != nullptr) {
            std::string calleeName = callee->getName().str();
            if (calleeName == "strlen"||                        // 若 len 来自strlen/vmalloc的返回值，找到了源，直接返回。
                calleeName == "vmalloc")
                return;
        }

        if(!callee) return;
        // interprocedural analysis
        StringRef tmpName = callee->getName();                  // 若 len 来自alloc/free的返回值，找到了源，直接返回。
        if(tmpName.lower().find("alloc") != string::npos
            || tmpName.lower().find("ALLOC") != string::npos
            || tmpName.lower().find("free") != string::npos
            || tmpName.lower().find("FREE") != string::npos
        ){
            return;
        }
        KA_LOGS(1, "Starting interprocedural analysis for "<<callee->getName().str()<<"\n");
        for(const BasicBlock &BB : *callee){                    // 其他函数，继续递归分析返回值的source。
            for(const Instruction &I : BB){
                if(const ReturnInst *RI = dyn_cast<ReturnInst>(&I)){
                    if(Value *rValue = RI->getReturnValue()){
                        findSources(rValue, srcSet, trackedSet);
                    }
                }        
            }
        }
        // comment this because interprocedural analysis will taint the interesting arguments
        // for (auto AI = CI->arg_begin(), E = CI->arg_end(); AI != E; AI++) {
        //     Value* Param = dyn_cast<Value>(&*AI);
        //     findSources(Param, srcSet, trackedSet);
        // }
        return;
    }
// （2）V 来自 BitCastInst，定为source，存入 srcSet。递归分析源操作数。
    if(BitCastInst *BCI = dyn_cast<BitCastInst>(V)){
        srcSet.push_back(V);
        findSources(BCI->getOperand(0), srcSet, trackedSet);
        return;
    }
// （3）V 来自 AllocaInst。定为source，存入 srcSet。
    if (dyn_cast<AllocaInst>(V)){
        srcSet.push_back(V);
        return;
    }
// （4）V 为指向null的指针。定为source，存入 srcSet。
    if (dyn_cast<ConstantPointerNull>(V)){
        srcSet.push_back(V);
        return;
    }
// （5）V 为常量。定为source，存入 srcSet。
    if (dyn_cast<Constant>(V)) {
        srcSet.push_back(V);
        return;
    }
// （6）V为全局变量，且为常量。定为source，存入 srcSet。   不可能
    // Lewis: it is impossible but leave this in case
    // zipline: we need to handle this
    if (dyn_cast<GlobalVariable>(V)) {
        Constant* Ct = dyn_cast<Constant>(V);
        if (!Ct)
            return;
        srcSet.push_back(V);
        return;
    }
// （7）V为常量表达式。递归分析第1个操作数。   不可能
    // Lewis: it is impossible but leave this in case
    if (ConstantExpr* CE = dyn_cast<ConstantExpr>(V)) {
        findSources(CE->getOperand(0), srcSet, trackedSet);
        return;
    }
// （8）V为形参。定为source，存入 srcSet。
    if (Argument* A = dyn_cast<Argument>(V)) {
        srcSet.push_back(V);
        // return; // intra-procedural

        // inter-procedural analysis begins following
        Function* callee = A->getParent();
        if (callee == nullptr)
            return;

        for (CallInst* caller : Ctx->Callers[callee]) {         // 找到是哪个caller传过来的参数，递归分析该实参。
            if (caller) {
                // Lewis: this should never happen
                if (A->getArgNo() >= caller->getNumArgOperands())
                    continue;
                Value* arg = caller->getArgOperand(A->getArgNo());
                if (arg == nullptr)
                    continue;

                Function* F = caller->getParent()->getParent();
                KA_LOGS(1, "<<<<<<<<< Cross Analyzing " << F->getName().str() <<  "()\n");
                KA_LOGV(1, caller);
                findSources(arg, srcSet, trackedSet);
            }
        }
    }
// （9）V来自load加载。定为source，存入 srcSet。查找load指针之前，哪个Store往该指针存入了值，递归分析。
    if (LoadInst* LI = dyn_cast<LoadInst>(V)) {

        srcSet.push_back(V);

        // alias handling
        Function *F = LI->getFunction();

        if(!F) return;

        SmallPtrSet<Value *, 16> aliasSet;
        bool foundStore = false;

        aliasSet = getAliasSet(LI->getPointerOperand(), F);         // 获取load指针的别名 —— aliasSet

        // add Load's pointer operand to the set
        // it may have a store successor
        aliasSet.insert(LI->getPointerOperand());

        for(auto *alias : aliasSet){
            for(auto *aliasUser : alias->users()){
                if(auto *SI = dyn_cast<StoreInst>(aliasUser)){      // 遍历aliasSet，看是哪个Store指令存入的，递归分析该值。
                    foundStore |= true;
                    KA_LOGS(1, "FindSource: resolved an alias : " << *LI << " == " << *SI << "\n");
                    findSources(SI->getValueOperand(), srcSet, trackedSet);
                }
            }
        }

        // return because it maybe loading from a stack value
        // since we can found a corresponding store
        if(foundStore)
            return;


        findSources(LI->getPointerOperand(), srcSet, trackedSet);
        return;
    }
// （10）StoreInst，跳过
    if (StoreInst* SI = dyn_cast<StoreInst>(V)) {
        // findSources(SI->getValueOperand(), srcSet, trackedSet);
    }
// （11）V 来自 SelectInst，递归分析入边值。
    if (SelectInst* SI = dyn_cast<SelectInst>(V)) {
        findSources(SI->getTrueValue(), srcSet, trackedSet);
        findSources(SI->getFalseValue(), srcSet, trackedSet);
        return ;
    }
// （12）V来自GEP指令，递归。
    if (GetElementPtrInst* GEP = dyn_cast<GetElementPtrInst>(V)) {
        // TODO f**k aliases
        KA_LOGS(1, "Here may contain an alias, please check this\n");
        DEBUG_Inst(2, GEP);
        srcSet.push_back(V);
        // Heuristic 2: first GEP is enough?
        // Lewis: Wrong
        // findSources(GEP->getPointerOperand(), srcSet, trackedSet);               改进4: 避免成员为结构指针这种情况 struct -> pointer -> struct
        return;
    }
// （13）V来自 PHINode，定为source，存入 srcSet。递归分析入边值。
    if (PHINode* PN = dyn_cast<PHINode>(V)) {
        for (unsigned i = 0, e = PN->getNumIncomingValues(); i != e; i++) {
            Value* IV = PN->getIncomingValue(i);
            findSources(IV, srcSet, trackedSet);
        }
        return;
    } 
// （14）V来自 ICmpInst，递归分析操作数。
    if (ICmpInst* ICmp = dyn_cast<ICmpInst>(V)) {
        for (unsigned i = 0, e = ICmp->getNumOperands(); i != e; i++) {
            Value* Opd = ICmp->getOperand(i);
            findSources(Opd, srcSet, trackedSet);
        }
        return;
    }
// （15）V来自二元指令，递归分析操作数。
    if (BinaryOperator* BO = dyn_cast<BinaryOperator>(V)) {
        for (unsigned i = 0, e = BO->getNumOperands(); i != e; i++) {
            Value* Opd = BO->getOperand(i);
            if (dyn_cast<Constant>(Opd))
                continue;
            findSources(Opd, srcSet, trackedSet);
        }
        return;
    }
// （16）V来自一元指令，递归分析操作数。
    if (UnaryInstruction* UI = dyn_cast<UnaryInstruction>(V)) {
        findSources(UI->getOperand(0), srcSet, trackedSet);
        return;
    }

    return;
}
// setupFreeInfo —— 检查和记录buf的source信息
void LeakerAnalyzerPass::setupFreeInfo(std::vector<Value*> &srcSet, CallInst *callInst, Value *from){
    for (std::vector<llvm::Value*>::iterator i = srcSet.begin(),
        e = srcSet.end(); i != e; i++)
    {
        Value *V = *i;
// 检查buf的source是否来自 StructType （通过GEP指令获取struct成员）
        if (auto *LI = dyn_cast<LoadInst>(V))                                   // (1) GetElementPtrInst -> LoadInst
        {
            KA_LOGS(1, "[load] "); KA_LOGV(1, LI);
            Instruction *I = nullptr;

            // check if ot's loading a pointer                      检查load取的成员是否为指针
            //Type *type = LI->getPointerOperandType();
            //if(!type->getPointerElementType()->isPointerTy())
            //    continue;
            
            Value *lValue = LI->getPointerOperand();
            //while (auto *GEP = dyn_cast<GetElementPtrInst>(lValue))                         // 改进4：避免成员为结构指针这种情况 struct -> pointer -> struct
            if (auto *GEP = dyn_cast<GetElementPtrInst>(lValue))
            {
                KA_LOGS(1, "[GEP] "); KA_LOGV(1, GEP);

                if (!GEP->getPointerOperand()) break;
                I = GEP;
                if (auto *BCI = dyn_cast<BitCastInst>(GEP->getPointerOperand())) 
                    I = BCI;
                lValue = I->getOperand(0);                                                  // next loop 递归找指令的source

                if (GEP->getNumOperands() <= 2)
                    continue;
                
                PointerType* ptrType = dyn_cast<PointerType>(GEP->getPointerOperandType());
                assert(ptrType != nullptr);
                Type* baseType = ptrType->getElementType();
                StructType* stType = dyn_cast<StructType>(baseType);
                
                if (!stType) continue;
                if(stType->getName().find("union.anon") != string::npos ||  
                    stType->getName().find("struct.anon") != string::npos)
                    continue;

                Module* M = GEP->getModule();
                StructInfo* stInfo = Ctx->structAnalyzer.getStructInfo(stType, M);

                ConstantInt *CI = dyn_cast<ConstantInt>(GEP->getOperand(2));                // 2 or 1?
                assert(CI != nullptr && "GEP's index is not constant");
                uint64_t offset = CI->getZExtValue();

                if (isGEPIndexNegative(GEP))                                                           // 改进8：GEP第2个下标不为负数
                    continue;
                if (!isGEPGetPtr(GEP, stType))                                                         // 改进1：如果取值不是指针，则忽略（释放堆指针才有意义）
                    continue;
                if (isInstFromErrBlock(GEP))                                                           // 改进5：忽略错误处理块中的指令
                    continue;

                // we found buf info
                if (stInfo)
                    addFreeInst(stInfo, callInst, offset, GEP, stType);
/*                if (flag_debug==1)
    {
        OP<<"[-][-][-]1 find a source - analyze special!!!\n";
    }*/
            }
            else if (auto *BCI = dyn_cast<BitCastInst>(lValue))                         // 改进2-1: GEP -> BitCastInst -> LoadInst 参见问题2.  针对双链表 list_head 情况。
            {
                PointerType* srcPtrType = dyn_cast<PointerType>(BCI->getSrcTy());
                Type* baseType1 = srcPtrType->getElementType();
                StructType* srcType = dyn_cast<StructType>(baseType1);
                if (srcType == nullptr)
                    continue;
                PointerType* dstPtrType = dyn_cast<PointerType>(BCI->getDestTy());
                Type* baseType2 = dstPtrType->getElementType();
                StructType* dstType = dyn_cast<StructType>(baseType2);
                // if (dstType == nullptr)
                //    continue;

                if (srcType->getName().find("list_head") != string::npos)                   
                {
                    Value *lValue2 = BCI->getOperand(0);
                    if (auto *GEP = dyn_cast<GetElementPtrInst>(lValue2))
                    {
                        KA_LOGS(1, "[GEP] "); KA_LOGV(1, GEP);

                        if (!GEP->getPointerOperand()) break;

                        if (GEP->getNumOperands() <= 2)
                            continue;
                
                        PointerType* ptrType = dyn_cast<PointerType>(GEP->getPointerOperandType());
                        assert(ptrType != nullptr);
                        Type* baseType = ptrType->getElementType();
                        StructType* stType = dyn_cast<StructType>(baseType);
                
                        if (!stType) continue;
                        if(stType->getName().find("union.anon") != string::npos ||  
                            stType->getName().find("struct.anon") != string::npos)
                            continue;

                        Module* M = GEP->getModule();
                        StructInfo* stInfo = Ctx->structAnalyzer.getStructInfo(stType, M);

                        ConstantInt *CI = dyn_cast<ConstantInt>(GEP->getOperand(2));                // 2 or 1?
                        assert(CI != nullptr && "GEP's index is not constant");
                        uint64_t offset = CI->getZExtValue();

                        if (isGEPIndexNegative(GEP))                                                           // 改进8：GEP第2个下标不为负数
                            continue;
                        if (!isGEPGetPtr(GEP, stType))                                                         // 改进1：如果取值不是指针，则忽略（释放堆指针才有意义）
                            continue;
                        if (isInstFromErrBlock(GEP))                                                           // 改进5：忽略错误处理块中的指令
                            continue;

                        // we found buf info
                        if (stInfo)
                            addFreeInst(stInfo, callInst, offset, GEP, stType);
                    }
                    Module* M2 = BCI->getModule();
                    StructInfo* stInfo2 = Ctx->structAnalyzer.getStructInfo(srcType, M2);     // 改进2-3: 只要 bitcast -> load      bitcast 的源指针类型为 list_head, 则将该释放点记录到 list_head 的释放点

                    if (isInstFromErrBlock(BCI))                                                           // 改进5：忽略错误处理块中的指令
                        continue;
                    
                    if (stInfo2)
                        addFreeInst(stInfo2, callInst, 0, BCI, srcType);
                }

            }
        } else if (auto *GEP2 = dyn_cast<GetElementPtrInst>(V))
        {
            Value *lValue = V;
            Instruction *I = nullptr;

            // while (auto *GEP = dyn_cast<GetElementPtrInst>(lValue))                      // 改进4：避免成员为结构指针这种情况 struct -> pointer -> struct
            if (auto *GEP = dyn_cast<GetElementPtrInst>(lValue))
            {
                KA_LOGS(1, "[GEP] "); KA_LOGV(1, GEP);

                if (!GEP->getPointerOperand()) break;
                I = GEP;
                if (auto *BCI = dyn_cast<BitCastInst>(GEP->getPointerOperand())) 
                    I = BCI;
                lValue = I->getOperand(0);                                                  // next loop 递归找指令的source

                if (GEP->getNumOperands() <= 2)
                    continue;
                
                PointerType* ptrType = dyn_cast<PointerType>(GEP->getPointerOperandType());
                assert(ptrType != nullptr);
                Type* baseType = ptrType->getElementType();
                StructType* stType = dyn_cast<StructType>(baseType);
                
                if (!stType) continue;
                if(stType->getName().find("union.anon") != string::npos ||  
                    stType->getName().find("struct.anon") != string::npos)
                    continue;

                Module* M = GEP->getModule();
                StructInfo* stInfo = Ctx->structAnalyzer.getStructInfo(stType, M);

                ConstantInt *CI = dyn_cast<ConstantInt>(GEP->getOperand(2));                // 2 or 1?
                assert(CI != nullptr && "GEP's index is not constant");
                uint64_t offset = CI->getZExtValue();

                if (isGEPIndexNegative(GEP))                                                           // 改进8：GEP第2个下标不为负数
                    continue;
                if (!isGEPGetPtr(GEP, stType))                                                         // 改进1：如果取值不是指针，则忽略（释放堆指针才有意义）
                    continue;
                if (isInstFromErrBlock(GEP))                                                           // 改进5：忽略错误处理块中的指令
                    continue;

                // we found buf info
                if (stInfo)
                    addFreeInst(stInfo, callInst, offset, GEP, stType);
            }
        }/*
         else if (dyn_cast<LoadInst>(V) || dyn_cast<GetElementPtrInst>(V))     // (1) LoadInst & GetElementPtrInst
        {
            Value *lValue = V;
            // GetElementPtrInst *GEP = nullptr;
            Instruction *I = nullptr;
            if (auto *LI = dyn_cast<LoadInst>(V))
            {
                if (flag_debug==1)
    {
        OP<<"[-][-][-]1 find a source - analyze special!!!\n";
    }
                lValue = LI->getPointerOperand();

                PointerType* ptrType = dyn_cast<PointerType>(LI->getPointerOperandType());
                Type* baseType = ptrType->getElementType();             
                StructType* stType = dyn_cast<StructType>(baseType);

                if (!stType) continue;
                if(stType->getName().find("union.anon") != string::npos ||  
                    stType->getName().find("struct.anon") != string::npos)
                    continue;
                
                Module* M = LI->getModule();
                StructInfo* stInfo = Ctx->structAnalyzer.getStructInfo(stType, M);

                if (stInfo)
                    addFreeInst(stInfo, callInst, 0xffffffff, 0, stType);
            }
            while (auto *GEP = dyn_cast<GetElementPtrInst>(lValue))
            {

                KA_LOGS(2, "[GEP] in setupFreeInfo " << *GEP <<"\n");
                
                if (!GEP->getPointerOperand()) break;
                I = GEP;
                if (auto *BCI = dyn_cast<BitCastInst>(GEP->getPointerOperand())) 
                    I = BCI;
                lValue = I->getOperand(0);                                                  // 递归找指令的source

                if (GEP->getNumOperands() <= 2)
                    continue;
                
                PointerType* ptrType = dyn_cast<PointerType>(GEP->getPointerOperandType());
                assert(ptrType != nullptr);
                Type* baseType = ptrType->getElementType();
                StructType* stType = dyn_cast<StructType>(baseType);

                if (!stType) continue;
                if(stType->getName().find("union.anon") != string::npos ||  
                    stType->getName().find("struct.anon") != string::npos)
                    continue;
                
                Module* M = GEP->getModule();
                StructInfo* stInfo = Ctx->structAnalyzer.getStructInfo(stType, M);

                ConstantInt *CI = dyn_cast<ConstantInt>(GEP->getOperand(2));                // 2 or 1 ???????????????????   也就是第2个下标
                assert(CI != nullptr && "GEP's index is not constant");
                uint64_t offset = CI->getZExtValue();

                // if (!stType->getElementType(offset)->isPointerTy())                         // 如果取值不是指针，则忽略（释放堆指针才有意义）
                //    continue;
                if (!isGEPGetPtr(GEP, stType))                                                         // 如果取值不是指针，则忽略（释放堆指针才有意义）
                    continue;

                if (stInfo)
                    addFreeInst(stInfo, callInst, offset, GEP, stType);
            }
            // for (GEP)
        }*/ /*else if (auto *CPointerNull = dyn_cast<ConstantPointerNull>(V))       // ConstantPointerNull
        {
            PointerType *ptrType = CPointerNull->getType();
            Type* baseType = ptrType->getElementType();
            StructType* stType = dyn_cast<StructType>(baseType);

            if (!stType) continue;
            if(stType->getName().find("union.anon") != string::npos ||  
                stType->getName().find("struct.anon") != string::npos)
                continue;

            // Module* M = CPointerNull->getModule()
        } */ else if (auto *allocInst = dyn_cast<AllocaInst>(V))                   // (2) AllocaInst
        {
            Type *type = allocInst->getAllocatedType();
            StructType *stType = dyn_cast<StructType>(type);

            if (!stType) continue;
            if(stType->getName().find("union.anon") != string::npos ||  
                stType->getName().find("struct.anon") != string::npos)
                continue;

            Module* M = allocInst->getModule();
            StructInfo* stInfo = Ctx->structAnalyzer.getStructInfo(stType, M);

            if (stInfo)
                addFreeInst(stInfo, callInst, 0xffffffff, 0, stType);
        } else if (auto *BCI = dyn_cast<BitCastInst>(V))                        // (3) BitCastInst
        {
            KA_LOGS(1, "[BitCast] in setupFromInfo"); KA_LOGV(1, V);
            PointerType* srcPtrType = dyn_cast<PointerType>(BCI->getSrcTy());
            Type* baseType1 = srcPtrType->getElementType();
            StructType* srcType = dyn_cast<StructType>(baseType1);
            // if (srcType == nullptr)
            //    continue;
            PointerType* dstPtrType = dyn_cast<PointerType>(BCI->getDestTy());
            Type* baseType2 = dstPtrType->getElementType();
            StructType* dstType = dyn_cast<StructType>(baseType2);

            if (dstType)                                                                // 改进2-2: bitcast->load->bitcast   参见问题2.  针对双链表 list_head 情况。
            {
                Value *lValue2 = BCI->getOperand(0);
                if (auto *LI = dyn_cast<LoadInst>(lValue2))
                {
                    Value *lValue3 = LI->getPointerOperand();
                    if (auto *BCI2 = dyn_cast<BitCastInst>(lValue3))
                    {
                        PointerType* ptrType = dyn_cast<PointerType>(BCI2->getSrcTy());
                        Type* baseType = ptrType->getElementType();
                        StructType* srcType2 = dyn_cast<StructType>(baseType);
                        if (srcType2)
                        {
                            Module* M = BCI2->getModule();
                            StructInfo* stInfo = Ctx->structAnalyzer.getStructInfo(srcType2, M);

                            if (isInstFromErrBlock(BCI2))                                                           // 改进5：忽略错误处理块中的指令
                                continue;
                            
                            if (stInfo)
                                addFreeInst(stInfo, callInst, 0, BCI2, srcType2);
                        }
                    }
                }
            }

            if (srcType == nullptr)
                continue;

            if(srcType->getName().find("union.anon") != string::npos ||  
                srcType->getName().find("struct.anon") != string::npos)
                continue;

            Module* M = BCI->getModule();
            StructInfo* stInfo2 = Ctx->structAnalyzer.getStructInfo(srcType, M);

            if (stInfo2)
                addFreeInst(stInfo2, callInst, 0xffffffff, 0, srcType);   
        }/* else if (auto *callInst = dyn_cast<CallInst>(V))                      // (4) CallInst
        {
            KA_LOGS(1, "[CallInst] in setupFromInfo " << *callInst <<"\n");
            Function* callee = callInst->getCalledFunction();
            if (!callee)
                callee = dyn_cast<Function>(callInst->getCalledValue()->stripPointerCasts());
            if (!callee) continue;
            
            Type *type = callee->getReturnType();
            StructType *stType = dyn_cast<StructType>(type);
            
            if (!stType) continue;
            if(stType->getName().find("union.anon") != string::npos ||  
                stType->getName().find("struct.anon") != string::npos)
                continue;
            
            Module* M = callInst->getModule();
            StructInfo* stInfo = Ctx->structAnalyzer.getStructInfo(stType, M);

            if (stInfo)
                addFreeInst(stInfo, callInst, 0xffffffff, 0, stType);
        }*/
    }

}
// addFreeInst —— 保存释放信息 stInfo->freeInfo  [buf 所在的struct下标, [call释放指令, SiteInfo(GEP指令 + source struct)]]
void LeakerAnalyzerPass::addFreeInst(StructInfo *stInfo, llvm::CallInst *callInst,  
                        unsigned offset, llvm::Instruction *I, llvm::StructType *st)
{
    // OP<< "*********** Find an free struct: " << st->getStructName() << "\n";
    // OP<< "callInst: "<<callInst<<"\n";
    if (!stInfo) return;
    //if (stInfo->freeInst.find(callInst) != stInfo->freeInst.end())        // 由于有多种指令能够暴露结构类型, 可能先遍历到其他指令(除GEP外), 但GEP指令的信息更丰富, 为了避免错过GEP, 所以注释这句话
    //    return;
// (1) stInfo->freeInst —— 保存能释放 stInfo 的 callInst 指令
    stInfo->freeInst.insert(callInst);
// (2) Ctx->freeStructMap —— 配对能释放的 (struct name -> StructInfo)
    LeakStructMap::iterator it = Ctx->freeStructMap.find(stInfo->name);
    if (it == Ctx->freeStructMap.end())
        Ctx->freeStructMap.insert(std::make_pair(stInfo->name, stInfo));

    KA_LOGS(1, "Add "<<stInfo->name<<" successful\n");
    
    if (offset == -1) return;
    if (offset == 0xffffffff) return;                                       // 不是从GEP指令找到的 StructType 类型, 所以没有偏移 offset
// (3) stInfo->freeInfo —— 保存释放信息 [buf 所在的struct下标, [call释放指令, SiteInfo(GEP指令 + source struct)]]
    std::set<llvm::Value *> bufValueSet2;                       // 改进12
    bufValueSet2.insert(I);                                     // 改进12
    StructInfo::SiteInfo sInfo;
    sInfo.bufValueSet = bufValueSet2;                              // 改进12
    // sInfo.bufValue = I;     // I —— buf 的source 指令-GEP
    sInfo.bufSt = st;       // st —— buf 的source struct
    stInfo->addFreeSourceInfo(offset, dyn_cast<Value>(callInst), sInfo, I);
}

// addLeakInst —— 保存泄露信息(leakInst-call泄露指令, [len 所在的struct下标, [call泄露指令, SiteInfo(GEP指令+source struct)])。绑定 struct name 和对应的StructInfo (Ctx->leakStructMap)
void LeakerAnalyzerPass::addLeakInst(StructInfo *stInfo, llvm::CallInst *callInst, 
                        unsigned offset, llvm::Instruction *I, llvm::StructType *st){   // stInfo——StructType对应的StructInfo; callInst——调用泄露函数; offset——GEP中获取len的下标; I——GEP指令; stType——StructType。

    if(!stInfo)
        return;

    if(stInfo->leakInst.find(callInst) != stInfo->leakInst.end())
        return;
// (1) stInfo->leakInst —— 保存能泄露 stInfo 的 callInst 指令    
    stInfo->leakInst.insert(callInst);
// (2) Ctx->leakStructMap —— 配对(strcut name -> StructInfo)    StructInfo 包含能分配该struct的call指令-allocaInst 和 泄露该struct的call指令-leakInst
    LeakStructMap::iterator it = Ctx->leakStructMap.find(stInfo->name);
    if(it == Ctx->leakStructMap.end()){
        Ctx->leakStructMap.insert(std::make_pair(stInfo->name, stInfo));
    }

    KA_LOGS(1, "Add "<<stInfo->name<<" successful\n");

    if(offset == -1)
        return;
// (3) stInfo->leakInfo —— 保存泄露信息 [len 所在的struct下标, [call泄露指令, SiteInfo(GEP指令+source struct)]
    // add other SiteInfo in the future
    StructInfo::SiteInfo sInfo;
    sInfo.lenValue = I;     // I——len的source指令-GEP
    sInfo.lenSt = st;       // st——len的source-struct
    stInfo->addLeakSourceInfo(offset, dyn_cast<Value>(callInst), sInfo);        // addLeakSourceInfo —— 将泄露信息 [len 所在的struct下标, [call泄露指令, SiteInfo(GEP指令+source struct)] 存入 StructInfo-> leakInfo

}
// setupLeakInfo —— 检查和设置len的source struct信息，检查和设置buf的source struct信息，存于 Ctx->leakStructMap -> StructInfo -> SiteInfo
void LeakerAnalyzerPass::setupLeakInfo(std::vector<Value*> &srcSet, CallInst *callInst, Value *from){


    for (std::vector<llvm::Value*>::iterator i = srcSet.begin(),        // 遍历srcSet —— len的source
         e = srcSet.end(); i != e; i++) { 
        
        Value *V = *i;
// (1) 检查len的source是否来自 StructType （通过GEP指令获取struct成员）
        if(auto *LI = dyn_cast<LoadInst>(V)) {              // 检查len的source是否是通过load指令从struct中取出来的。

            KA_LOGS(1, "[Load] "); KA_LOGV(1, LI);

            // check if it's loading a pointer
            Type *type = LI->getPointerOperandType();
            if(type->getPointerElementType()->isPointerTy()){           // 检查, load指针指向的还是指针，则跳过
                continue;
            }

            Value *lValue = LI->getPointerOperand();                    // 该load指针 lValue 是用GEP指令从struct中获取
            while(auto *GEP = dyn_cast<GetElementPtrInst>(lValue)){
                KA_LOGS(1, "[GEP] "); KA_LOGV(1, GEP);

                // only pointer value GEP只有1个参数则跳过
                if (GEP->getNumIndices() == 1)
                    break;

                PointerType* ptrType = dyn_cast<PointerType>(GEP->getPointerOperandType());
                assert(ptrType != nullptr);
                Type* baseType = ptrType->getElementType();
                StructType* stType = dyn_cast<StructType>(baseType);    // 若GEP 指令的基指针指向 StructType —— stType
                if (stType == nullptr)
                    break;
                
                ConstantInt *CI = dyn_cast<ConstantInt>(GEP->getOperand(2));
                assert(CI != nullptr && "GEP's index is not constant"); // 获取GEP 的下标 offset
                uint64_t offset = CI->getZExtValue();

                Module* M = GEP->getModule();
                StructInfo* stInfo = Ctx->structAnalyzer.getStructInfo(stType, M);// getStructInfo —— 根据StructType获取对应的 StructInfo - stInfo。

                if(!stInfo) break;
// (2) 将len泄露信息保存到stType。   stInfo——StructType对应的StructInfo; callInst——调用泄露函数; offset——GEP中获取len的下标; stType——StructType。
                // we found length info
                addLeakInst(stInfo, callInst, offset, GEP, stType);     // addLeakInst —— 保存泄露信息(leakInst-call泄露指令, [len 所在的struct下标, [call泄露指令, SiteInfo(GEP指令+source struct)])。绑定 struct name 和对应的StructInfo (Ctx->leakStructMap)
 // (3) 前向数据流分析，追踪 buf—from 的source, 存入 srcFromSet; 检查buf是否来自struct（栈or堆），记录buf的source信息 (source指令/struct)。
                std::vector<Value *> srcFromSet;
                std::set<Value *> trackedFromSet;
                findSources(from, srcFromSet, trackedFromSet);
                setupFromInfo(srcFromSet, stInfo, callInst, offset);    // setupFromInfo —— 检查和记录buf的source信息到 StructInfo (fromValue-source指令 / fromSt-source struct / TYPE-来自堆还是栈 / TYPE-和len的source相同还是不同)
                
                // next loop
                lValue = dyn_cast<Value>(GEP->getPointerOperand());
            }
        }
    }
}
// setupFromInfo —— 检查和记录buf的source信息到 StructInfo (fromValue-source指令 / fromSt-source struct / TYPE-来自堆还是栈 / TYPE-和len的source相同还是不同)
void LeakerAnalyzerPass::setupFromInfo(std::vector<llvm::Value*> &srcSet, 
                            StructInfo *stInfo, CallInst *callInst, unsigned offset){           // srcSet - buf 的source, stInfo - len 的source
    // FIXME: plz keep tracking whether the value is from stack or heap
    // after finding its type.
    StructInfo::SiteInfo *siteInfo = stInfo->getSiteInfo(offset, dyn_cast<Value>(callInst));    // siteInfo —— len 和 buf 的source信息
    
    if(siteInfo == nullptr)
        return;


    for (std::vector<llvm::Value*>::iterator i = srcSet.begin(),        // 遍历buf的source, 只要找到1个就停止, 直接返回
         e = srcSet.end(); i != e; i++) {

        Value *V = *i;

        KA_LOGS(2, "setupFromInfo : " << *V << "\n");
 // (1) V 来自null指针——堆, 设置buf的source信息，检查是否和len来自同一source struct
        if(auto *CPointerNull = dyn_cast<ConstantPointerNull>(V)){

            siteInfo->fromValue = V;

            PointerType *ptrType = CPointerNull->getType();
            Type* baseType = ptrType->getElementType();
            StructType* stType = dyn_cast<StructType>(baseType);        // 指针指向struct类型

            if(!stType){
                return;                                                 // ?????????????????????????????????????????? 怎么总是return? 应该 continue
            }
            if(stType->getName().find("union.anon") != string::npos ||  // 排除此类型的struct
                stType->getName().find("struct.anon") != string::npos){
                return;
            }

            if(stType->getName() == stInfo->name){                      // 是否和len的source位于同一struct 。 stType-buf的source, stInfo-len的source 。
                siteInfo->TYPE = HEAP_SAME_OBJ;
            }else{
                siteInfo->TYPE = HEAP_DIFF_OBJ;
            }
            siteInfo->fromSt = stType;                                  // 设置 buf 的 source struct
            return;
        } else if(auto *allocInst = dyn_cast<AllocaInst>(V)){
// (2) V 来自 AllocaInst——栈，一样
            Type *type = allocInst->getAllocatedType();

            if(!type->isPointerTy()){                                   // 非指针则位于栈，指针则位于堆
                siteInfo->TYPE=STACK;
                siteInfo->fromValue = V;
            }else{
                siteInfo->TYPE=HEAP_DIFF_OBJ;
                siteInfo->fromValue = V;
            }
            StructType* stType = dyn_cast<StructType>(type);
            if(stType){
                siteInfo->fromSt = stType;
            }
            return;
// (3) V 来自 LoadInst
        } else if(dyn_cast<LoadInst>(V) || dyn_cast<GetElementPtrInst>(V)) {

            auto *LI = dyn_cast<LoadInst>(V);
            Value *lValue = V;
            GetElementPtrInst *GEP = nullptr;
            Instruction *I = nullptr;

            if(LI){
                // return on load anyway.
                lValue = LI->getPointerOperand();
                PointerType* ptrType = dyn_cast<PointerType>(LI->getPointerOperandType());
                Type* baseType = ptrType->getElementType();
                StructType* stType = dyn_cast<StructType>(baseType);    // stType - load 源指针指向的 struct
                if (stType == nullptr)
                    continue;

                Module* M = LI->getModule();
                StructInfo* stInfoFrom = Ctx->structAnalyzer.getStructInfo(stType, M);  // stInfoFrom —— buf的source; stInfo —— len 的source struct

                if(!stInfoFrom 
                    || stType->getName().find("union.anon") == 0
                    || stType->getName().find("struct.anon") == 0)
                    continue;

                if(stInfo->name == stInfoFrom->name){                   // 是否和len的source位于同一struct
                    // we found it
                    siteInfo->TYPE = HEAP_SAME_OBJ;
                }else{
                    siteInfo->TYPE = HEAP_DIFF_OBJ;
                }

                siteInfo->fromSt = stType;
                siteInfo->fromValue = LI;
                return;
            }
// (4) V 来自 GetElementPtrInst
            for(GEP=dyn_cast<GetElementPtrInst>(lValue); GEP;
                    GEP=dyn_cast<GetElementPtrInst>(I->getOperand(0))){

                KA_LOGS(2, "[GEP] in setupFromInfo " << *GEP <<"\n");

                if (!GEP->getPointerOperand())
                    break;
                
                I = GEP;

                if(auto *BCI = dyn_cast<BitCastInst>(GEP->getPointerOperand())){
                    I = BCI;
                }

                // only pointer value
                if (GEP->getNumIndices() == 1)
                    continue;

                PointerType* ptrType = dyn_cast<PointerType>(GEP->getPointerOperandType());
                assert(ptrType != nullptr);
                Type* baseType = ptrType->getElementType();
                StructType* stType = dyn_cast<StructType>(baseType);      // stType - GEP源指针, buf的source
                if (stType == nullptr)
                    continue;

                Module* M = GEP->getModule();
                StructInfo* stInfoFrom = Ctx->structAnalyzer.getStructInfo(stType, M); // stInfoFrom —— buf的source; stInfo —— len 的source struct

                if(!stInfoFrom 
                    || stType->getName().find("union.anon") == 0
                    || stType->getName().find("struct.anon") == 0)
                    continue;

                if(stInfo->name == stInfoFrom->name){
                    // we found it
                    siteInfo->TYPE = HEAP_SAME_OBJ;
                }

                siteInfo->fromSt = stType;
                siteInfo->fromValue = GEP;
                // return;
            }
        } else if(auto *BCI = dyn_cast<BitCastInst>(V)){
            KA_LOGS(1, "[BitCast] in setupFromInfo"); KA_LOGV(1, V);
// (5) V 来自 BitCastInst
            PointerType* ptrType = dyn_cast<PointerType>(BCI->getSrcTy());
            assert(ptrType != nullptr);
            Type* baseType = ptrType->getElementType();

            StructType* stType = dyn_cast<StructType>(baseType);        // stType
            if (stType == nullptr)
                continue;

            Module* M = BCI->getParent()->getParent()->getParent();
            StructInfo* stInfoFrom = Ctx->structAnalyzer.getStructInfo(stType, M);  // StructInfo

            if(!stInfoFrom 
                || stType->getName().find("union.anon") == 0
                || stType->getName().find("struct.anon") == 0)
                continue;

            // FIXME: what if siteInfo has already been set?

            if(stInfoFrom->name == stInfo->name){
                siteInfo->TYPE = HEAP_SAME_OBJ;
            }

            siteInfo->fromSt = stType;
            siteInfo->fromValue = BCI;
 // (6) V 来自 CallInst 返回值           // return;
        } else if(auto *callInst = dyn_cast<CallInst>(V)){
            KA_LOGS(1, "[CallInst] in setupFromInfo " << *callInst <<"\n");
            Function* callee = callInst->getCalledFunction();
            if (!callee)
                callee = dyn_cast<Function>(callInst->getCalledValue()->stripPointerCasts());
            if (callee) {

                // we assume all functions return memory coming from heap
                std::string calleeName = callee->getName().str();
                siteInfo->fromValue = callInst;
                siteInfo->TYPE = HEAP_DIFF_OBJ;                         // 若buf源自函数返回值，则默认和len位于不同的堆块
    // (6-1) buf 来自 mbuf 结构
                if(calleeName == "m_mtod"){
                    if(stInfo->name == "mbuf")
                        siteInfo->TYPE = HEAP_SAME_OBJ;
                    // find mbuf
		    // use this for compatibility issue
		    // Value *arg = callee->getArg(0);
                    Value *arg = callee->arg_begin();
                    Type *t = arg->getType()->getPointerElementType();
                    if(auto *st = dyn_cast<StructType>(t)){
                        siteInfo->fromSt = st;
                    }
                    return;
    // (6-2) buf来自一般的结构   
                } else {
                    if(siteInfo->fromSt){                               // 已存在 fromSt ??? 不可能
                        if(siteInfo->fromSt->getName() == stInfo->name){
                            siteInfo->TYPE = HEAP_SAME_OBJ;
                        }
                        return;
                    }
                    // get return type if no bitcast after calling a function
                    Type *type = callee->getReturnType();
                    if(auto *st = dyn_cast<StructType>(type)){
                        if(st->getName() == stInfo->name){
                            siteInfo->TYPE = HEAP_SAME_OBJ;
                        }
                        siteInfo->fromSt = st;
                    }
                    return;

                }
            }
// (7) V 来自 Argument 形参, 由于只在函数内有效, 所以忽略 (之前进行反向数据流分析时，已经分析了调用者)   
        } else if(dyn_cast<Argument>(V)){
            return;
        }
    
    }
}

llvm::StructType* LeakerAnalyzerPass::checkSource(std::vector<llvm::Value*>& srcSet, StructTypeSet& stSet , CallInst *callInst, bool isLen) {

    // Heuristic 2, check source from close to remote
    for (std::vector<llvm::Value*>::iterator i = srcSet.begin(), 
         e = srcSet.end(); i != e; i++) {

        llvm::Value* V = *i;

        if (GetElementPtrInst* GEP = dyn_cast<GetElementPtrInst>(V)) {
            
            KA_LOGS(1, "[GEP] "); KA_LOGV(1, V);
            
            // only pointer value
            if (GEP->getNumIndices() == 1)
                continue;

            PointerType* ptrType = dyn_cast<PointerType>(GEP->getPointerOperandType());
            assert(ptrType != nullptr);
            Type* baseType = ptrType->getElementType();
            StructType* stType = dyn_cast<StructType>(baseType);
            if (stType == nullptr)
                continue;
            
            ConstantInt *CI = dyn_cast<ConstantInt>(GEP->getOperand(2));
            assert(CI != nullptr && "GEP's index is not constant");
            uint64_t idx = CI->getZExtValue();

            Module* M = GEP->getParent()->getParent()->getParent();
            StructInfo* stInfo = Ctx->structAnalyzer.getStructInfo(stType, M);

            if(!stInfo) continue;

            addLeakInst(stInfo, callInst, idx, GEP, stType);

            // situation 1: return value refers to buffer in the flexible structure
            // if (stSet.find(stType) != stSet.end()) {
            // if (stInfo->flexibleStructFlag) {
            //     if (isLen) {
            //         stInfo->lenOffsetByLeakable.push_back(idx);
            //         KA_LOGS(1, "[+] update length field offset: " << idx << "\n");
            //         return stType;
            //     } else if (idx == (stType->element_end() - stType->element_begin() - 1)) {
            //         return stType;
            //     }
            // } else {
            //     // situation 2: return value refers to flexible structure 
            //     Type* idxType = stType->getElementType(idx);
            //     PointerType* ptrType = dyn_cast<PointerType>(idxType);
            //     if (ptrType == nullptr)
            //         continue;
            //     Type* subType = ptrType->getElementType();
            //     StructType* subSTType = dyn_cast<StructType>(subType);
            //     if (subSTType == nullptr)
            //         continue;

            //     stInfo = Ctx->structAnalyzer.getStructInfo(subSTType, M);

            //     if(!stInfo) continue;

            //     // if (stSet.find(subSTType) != stSet.end()) {
            //     if (stInfo->flexibleStructFlag) {
            //         if (isLen)
            //             KA_LOGS(1, "[-] no length field update, FIXME 1\n");
            //         return subSTType;
            //     }
            // }

        } else if (LoadInst* LI = dyn_cast<LoadInst>(V)){

            KA_LOGS(1, "[Load] "); KA_LOGV(1, V);

            PointerType* ptrType = dyn_cast<PointerType>(LI->getPointerOperandType());
            assert(ptrType != nullptr);
            Type* baseType = ptrType->getElementType();

            // situation 1: pointer itself refers flexible structure
            if (StructType* stType = dyn_cast<StructType>(baseType)) {

                Module* M = LI->getParent()->getParent()->getParent();
                StructInfo* stInfo = Ctx->structAnalyzer.getStructInfo(stType, M);

                if(!stInfo) continue;

                // if (stSet.find(stType) != stSet.end()) {
                if (stInfo->flexibleStructFlag) {
                    if (isLen)
                        KA_LOGS(1, "[-] no length field update, FIXME 2\n");
                    return stType;
                }
            } else if (PointerType* ptrType = dyn_cast<PointerType>(baseType)) {
                KA_LOGS(1, "[-] load from a pointer\n");
            }

        } else if (BitCastInst *BCI = dyn_cast<BitCastInst>(V)) {
            
            KA_LOGS(1, "[BitCast] "); KA_LOGV(1, V);

            PointerType* ptrType = dyn_cast<PointerType>(BCI->getSrcTy());
            assert(ptrType != nullptr);
            Type* baseType = ptrType->getElementType();

            StructType* stType = dyn_cast<StructType>(baseType);
            if (stType == nullptr)
                continue;

            Module* M = BCI->getParent()->getParent()->getParent();
            StructInfo* stInfo = Ctx->structAnalyzer.getStructInfo(stType, M);

            if(!stInfo) continue;
            
            // if (stSet.find(stType) != stSet.end()) {
            if (stInfo->flexibleStructFlag) {
                if (isLen)
                    KA_LOGS(1, "[-] no length field update, FIXME 3\n");
                return stType;
            }

        } else if (Argument* A = dyn_cast<Argument>(V)) {

            KA_LOGS(1, "[Arg] "); KA_LOGV(1, V);
            
            PointerType* ptrType = dyn_cast<PointerType>(A->getType());
            if (ptrType == nullptr)
                continue;

            Type* baseType = ptrType->getElementType();
            StructType* stType = dyn_cast<StructType>(baseType);
            if (stType == nullptr)
                continue;
            
            Module* M = A->getParent()->getParent();
            StructInfo* stInfo = Ctx->structAnalyzer.getStructInfo(stType, M);

            if(!stInfo) continue;


            // if (stSet.find(stType) != stSet.end()) {
            if (stInfo->flexibleStructFlag) {
                if (isLen)
                    KA_LOGS(1, "[-] no length field update, FIXME 4\n");
                return stType;
            }
           
        } else {
            KA_LOGS(1, "[-] add support for: ");
            KA_LOGV(1, V);
        }
    }
    return nullptr;
}
// doFinalization —— 去除 moduleStructMap 没有泄露点的struct，生成 structModuleMap，leakInstMap 转化为 leakSyscallMap 和 leakerList
// join allocInstMap and leakInstMap to compute moduleStructMap
// reverse moduleStructMap to obtain structModuleMap
// reachable analysis to compute allocSyscallMap and leakSyscallMap
// join allocSyscallMap and leakSyscallMap to compute leakerList
bool LeakerAnalyzerPass::doFinalization(Module* M) {

    KA_LOGS(1, "[Finalize] " << M->getModuleIdentifier() << "\n");
    ModuleStructMap::iterator it = Ctx->moduleStructMap.find(M);
    assert(it != Ctx->moduleStructMap.end() &&
        "M is not analyzed in doInitialization");

    if (it->second.size() == 0) {
        KA_LOGS(1, "No flexible structure in this module\n");
        return false;
    }
// (1) 遍历 moduleStructMap, 去除不可泄露的struct
    KA_LOGS(1, "Building moduleStructMap ...\n");
    // moduleStructMap: map module to flexible struct "st"
    StructTypeSet tmpStructTypeSet = Ctx->moduleStructMap[M];
    for (StructTypeSet::iterator itr = tmpStructTypeSet.begin(), 
            ite = tmpStructTypeSet.end(); itr != ite; itr++) {              // 遍历 struct，若不可泄露则去除（在Ctx->leakInstMap 中有对应的泄露指令）

        StructType* st = *itr;
        std::string structName = getScopeName(st, M);
        
        LeakInstMap::iterator liit = Ctx->leakInstMap.find(structName);
        // XXX 
        // AllocInstMap::iterator aiit = Ctx->allocInstMap.find(structName);

        // either leak or alloc or both
        if (liit == Ctx->leakInstMap.end() )
            // XXX    
            //  || aiit == Ctx->allocInstMap.end() )
            Ctx->moduleStructMap[M].erase(st);
    }

    if (Ctx->moduleStructMap[M].size() == 0) {
        KA_LOGS(1, "Actually no flexible structure in this module\n");
        return false;
    }

// (2) moduleStructMap->structModuleMap —— struct对应到所属的module
    KA_LOGS(1, "Building structModuleMap ...\n");
    // structModuleMap: map flexible struct "st" to module
    for (StructTypeSet::iterator itr = Ctx->moduleStructMap[M].begin(), 
            ite = Ctx->moduleStructMap[M].end(); itr != ite; itr++) {

        StructType* st = *itr;
        std::string structName = getScopeName(st, M);

        StructModuleMap::iterator sit = Ctx->structModuleMap.find(structName);
        if (sit == Ctx->structModuleMap.end()) {
            ModuleSet moduleSet;
            moduleSet.insert(M);
            Ctx->structModuleMap.insert(std::make_pair(structName, moduleSet)) ;
        } else {
            sit->second.insert(M);
        }
    }
// (3) leakInstMap -> leakSyscallMap     struct对应leak指令 -> struct对应leak syscall
    KA_LOGS(1, "Building leakSyscallMap & allocSyscallMap ...\n");
    // leakSyscallMap: map structName to syscall reaching leak sites
    // allocSyscallMap: map structName to syscall reaching allocation sites
    for (StructTypeSet::iterator itr = Ctx->moduleStructMap[M].begin(),
            ite = Ctx->moduleStructMap[M].end(); itr != ite; itr++) {

        StructType* st = *itr;
        std::string structName = getScopeName(st, M);

        // leakSyscallMap
        // XXX
        KA_LOGS(1, "Dealing with leaking: " << structName << "\n");
        LeakInstMap::iterator liit = Ctx->leakInstMap.find(structName);
        LeakSyscallMap::iterator lsit = Ctx->leakSyscallMap.find(structName);
        if (liit != Ctx->leakInstMap.end() &&
            lsit == Ctx->leakSyscallMap.end() // to avoid redundant computation
            ) {
            for (auto I : liit->second) {                       // 1个 struct 有多个泄露指令

                Function* F = I->getParent()->getParent();
                FuncSet syscallSet = reachableSyscall(F);
                if (syscallSet.size() == 0)
                    continue;

                LeakSyscallMap::iterator lsit = Ctx->leakSyscallMap.find(structName);
                if (lsit == Ctx->leakSyscallMap.end())
                    Ctx->leakSyscallMap.insert(std::make_pair(structName, syscallSet));
                else
                    for (auto F : syscallSet)
                        lsit->second.insert(F);
            }
        }

        // allocSyscallMap
        // XXX
        /*
        KA_LOGS(1, "Dealing with allocating: " << structName << "\n");
        AllocInstMap::iterator aiit = Ctx->allocInstMap.find(structName);
        AllocSyscallMap::iterator asit = Ctx->allocSyscallMap.find(structName);
        if (aiit != Ctx->allocInstMap.end() &&
            asit == Ctx->allocSyscallMap.end()
            ) {
            for (auto I : aiit->second) {

                Function* F = I->getParent()->getParent();
                FuncSet syscallSet = reachableSyscall(F);
                if (syscallSet.size() == 0)
                    continue;

                AllocSyscallMap::iterator asit = Ctx->allocSyscallMap.find(structName);
                if (asit == Ctx->allocSyscallMap.end())
                    Ctx->allocSyscallMap.insert(std::make_pair(structName, syscallSet));
                else
                    for (auto F : syscallSet)
                        asit->second.insert(F);
            }
        }
        */
        
    }
// (4) leakInstMap -> leakerList    struct对应leak指令-> 从syscall可达的struct对应leak指令
    KA_LOGS(1, "Building leakerList ...\n");
    for (StructTypeSet::iterator itr = Ctx->moduleStructMap[M].begin(), 
            ite = Ctx->moduleStructMap[M].end(); itr != ite; itr++) {

        StructType* st = *itr;
        std::string structName = getScopeName(st, M);

        LeakSyscallMap::iterator lsit = Ctx->leakSyscallMap.find(structName);
        // XXX 
        // AllocSyscallMap::iterator asit = Ctx->allocSyscallMap.find(structName);
        
        if (lsit == Ctx->leakSyscallMap.end())
            //XXX    
            // || asit == Ctx->allocSyscallMap.end())
            continue;

        LeakerList::iterator tit = Ctx->leakerList.find(structName);
        if (tit == Ctx->leakerList.end()) {
            InstSet instSet;
            for (auto I : Ctx->leakInstMap[structName])
                instSet.insert(I);
            Ctx->leakerList.insert(std::make_pair(structName, instSet));

        } else {
            for (auto I : Ctx->leakInstMap[structName])
                tit->second.insert(I);
        }
    }
    return false;
}

FuncSet LeakerAnalyzerPass::getSyscalls(Function *F){
    ReachableSyscallCache::iterator it = reachableSyscallCache.find(F);
    if (it != reachableSyscallCache.end())
        return it->second;
    FuncSet null;
    return null;
}
// reachableSyscall —— 找到能够到达F函数的syscall集合，存入 reachableSyscallCache。
FuncSet LeakerAnalyzerPass::reachableSyscall(llvm::Function* F) {

    ReachableSyscallCache::iterator it = reachableSyscallCache.find(F);
    if (it != reachableSyscallCache.end())
        return it->second;

    FuncSet reachableFuncs;     // reachableFuncs —— 可达F的函数集（含F自身）
    reachableFuncs.clear();

    FuncSet reachableSyscalls;  // reachableSyscalls —— 可达F的syscall集合
    reachableSyscalls.clear();
// (1) 先找到能到达F的函数集合 —— reachableFuncs
    SmallVector<Function*, 4> workList;
    workList.clear();
    workList.push_back(F);

    while (!workList.empty()) {
        Function* F = workList.pop_back_val();
        if (!reachableFuncs.insert(F).second)
            continue;

        if(reachableSyscallCache.find(F) != reachableSyscallCache.end()){
            FuncSet RS = getSyscalls(F);
            for(auto *RF : RS){
                reachableFuncs.insert(RF);
            }
            continue;
        }

        CallerMap::iterator it = Ctx->Callers.find(F);      // 调用过F的函数 都加入到 reachableFuncs
        if (it != Ctx->Callers.end()) {
            for (auto calleeInst: it->second) {
                Function* F = calleeInst->getParent()->getParent();
                if (!isInstPassPrivilege(F, calleeInst))     // 判断该指令是否经过 capable(CAP_SYS_ADMIN) 函数
                    workList.push_back(F);
            }
        }
    }
// (2) 从 reachableFuncs 中挑出 syscall，存入 reachableSyscalls                     ************** 待改进：只要是外部可调用，则为syscall   F.hasExternalLinkage()
    for (auto F : reachableFuncs) {                         // 遍历 reachableFuncs，将syscall的函数名都转化为 sys_ 开头
        StringRef funcNameRef = F->getName();
        std::string funcName = "";
        //if (flag_debug == 3)
        //    OP<<"[-] x509_cert_parse: "<<F->getName()<<"\n";
        if (funcNameRef.startswith("__sys_")) {
            funcName = "sys_" + funcNameRef.str().substr(6);
        } else if (funcNameRef.startswith("__x64_sys_")) {
	        funcName = "sys_" + funcNameRef.str().substr(9);
	    } else if (funcNameRef.startswith("__ia32_sys")) {
            continue;                                       // 忽略  __ia32_sys
	        funcName = "sys_" + funcNameRef.str().substr(10);
	    } else if (funcNameRef.startswith("__se_sys")) {
            continue;                                       // 忽略  __se_sys
	        funcName = "sys_" + funcNameRef.str().substr(8);
	    }

	if(funcName != "") {                                    // 若不属于已定义的 rootSyscall 集合，则加入到reachableSyscalls （所以rootSyscall是不可达的？？）
            if (std::find(rootSyscall.begin(), rootSyscall.end(), funcName) ==
                rootSyscall.end()) {
                reachableSyscalls.insert(F);
            }
	}
    }

    reachableSyscallCache.insert(std::make_pair(F, reachableSyscalls));
    return  reachableSyscalls;
}

void LeakerAnalyzerPass::dumpSimplifiedLeakers(){
    for(LeakStructMap::iterator it = Ctx->leakStructMap.begin(),
            e = Ctx->leakStructMap.end(); it != e; it++ ){

        StructInfo *st = it->second;
        if(st->leakInfo.size() == 0)
            continue;
        st->dumpSimplified();
    }
    return;
}

// dump final moduleStructMap and structModuleMap for debugging
void LeakerAnalyzerPass::dumpLeakers() {

    RES_REPORT("\n=========  printing LeakStructMap ==========\n");

    for(LeakStructMap::iterator it = Ctx->leakStructMap.begin(),
            e = Ctx->leakStructMap.end(); it != e; it++ ){
            
        // RES_REPORT("[+] " << it->first << "\n");

        StructInfo *st = it->second;

        if(st->leakInfo.size() == 0)
            continue;

        if(VerboseLevel > 0){
            st->dumpLeakInfo(false);
        }else{
            st->dumpLeakInfo(true);
            // skip print syscall map if no allocaInst or no leakInst
            if(!st->allocaInst.size() || !st->leakInst.size())
                continue;
        }
        
        // dump syscall info

        FuncSet SYSs;
        SYSs.clear();

        RES_REPORT("[+] syscalls:\n");
        for(auto *I : st->allocaInst){
            Function *F = I->getFunction();
            if(!F) continue;
            FuncSet syscalls = getSyscalls(F);
            for(auto *SF : syscalls){
                SYSs.insert(SF);
            }
        }
        for(auto *I : st->leakInst){
            Function *F = I->getFunction();
            if(!F) continue;
            FuncSet syscalls = getSyscalls(F);
            for(auto *SF : syscalls){
                SYSs.insert(SF);
            }
        }
        for(auto *SF : SYSs){
            RES_REPORT(SF->getName() << "\n");
        }
        RES_REPORT("\n");
    }


    RES_REPORT("======= end printting LeakStructMap =========\n");

    if(VerboseLevel >= 3){
        // dump alias
        for (auto const &alias : Ctx->FuncPAResults){
            KA_LOGS(2, "Function: " << getScopeName(alias.first) << "\n");
            for( auto const &aliasMap : alias.second){
                KA_LOGS(2, "Start dumping alias of Pointer : " << *aliasMap.first << "\n");
                for( auto *pointer : aliasMap.second){
                    KA_LOGS(2, *pointer << "\n");
                }
                KA_LOGS(2, "End dumping\n");
            }
            KA_LOGS(2, "\nEnding Function\n\n");
        }
    }

    unsigned cnt = 0;
    RES_REPORT("\n=========  printing moduleStructMap ==========\n");
    for (ModuleStructMap::iterator i = Ctx->moduleStructMap.begin(),
            e = Ctx->moduleStructMap.end(); i != e; i++) {

        Module* M = i->first;
        StructTypeSet &stSet = i->second;

        RES_REPORT("[+] " << M->getModuleIdentifier() << "\n");

        for (StructType* st : stSet) {
            RES_REPORT(getScopeName(st, M) << "\n");
            const StructInfo* stInfo = Ctx->structAnalyzer.getStructInfo(st, M);
            RES_REPORT("Offset by Flexible: ");
            for (auto offset : stInfo->lenOffsetByFlexible)
                RES_REPORT(offset << ", ");
            RES_REPORT("\n");

            RES_REPORT("Offset by Leakable: ");
            for (auto offset : stInfo->lenOffsetByLeakable)
                RES_REPORT(offset << ", ");
            RES_REPORT("\n");
        }
    } 
    RES_REPORT("======= end printting moduleStructMap =========\n");

    RES_REPORT("\n=========  printing structModuleMap ==========\n");
    cnt = 0;
    for (StructModuleMap::iterator i = Ctx->structModuleMap.begin(), 
            e = Ctx->structModuleMap.end(); i != e; i++, cnt++) {

        std::string structName = i->first;
        ModuleSet& moduleSet = i->second;
        
        RES_REPORT("[" << cnt << "] " << structName << "\n");
        for (Module* M : moduleSet)
            RES_REPORT("-- " << M->getModuleIdentifier() << "\n");
    }
    RES_REPORT("====== end printing structModuleMap ==========\n");

    RES_REPORT("\n=========  printing leakInstMap ==========\n");
    cnt = 0;
    for (AllocInstMap::iterator i = Ctx->leakInstMap.begin(), 
            e = Ctx->leakInstMap.end(); i != e; i++, cnt++) {

        std::string structName = i->first;
        InstSet& instSet = i->second;

        RES_REPORT("[" << cnt << "] " << structName << "\n");

         for (Instruction* I : instSet) {
            Function* F = I->getParent()->getParent();

            RES_REPORT("-- " << F->getName().str() << "(), " << 
                       F->getParent()->getModuleIdentifier() << "\n");
            RES_REPORT("   ");
            I->print(errs());
            RES_REPORT("\n");
         }
                    
    }
    RES_REPORT("====== end printing leakInstMap ==========\n");
    
    RES_REPORT("\n=========  printing allocInstMap ==========\n");
    cnt = 0;
    for (AllocInstMap::iterator i = Ctx->allocInstMap.begin(), 
            e = Ctx->allocInstMap.end(); i != e; i++, cnt++) {

        std::string structName = i->first;
        InstSet& instSet = i->second;

        RES_REPORT("[" << cnt << "] " << structName << "\n");

         for (Instruction* I : instSet) {
            Function* F = I->getParent()->getParent();

            RES_REPORT("-- " << F->getName().str() << "(), " << 
                       F->getParent()->getModuleIdentifier() << "\n");
            RES_REPORT("   ");
            I->print(errs());
            RES_REPORT("\n");
         }
                    
    }
    RES_REPORT("====== end printing allocInstMap ==========\n");

    RES_REPORT("\n=========  printing leakerList ==========\n");
    cnt = 0;
    for (LeakerList::iterator i = Ctx->leakerList.begin(), 
            e = Ctx->leakerList.end(); i != e; i++, cnt++) {

        std::string structName = i->first;
        InstSet& instSet = i->second;

        RES_REPORT("[" << cnt << "] " << structName << "\n");

         for (Instruction* I : instSet) {
            Function* F = I->getParent()->getParent();

            RES_REPORT("-- " << F->getName().str() << "(), " << 
                       F->getParent()->getModuleIdentifier() << "\n");
            RES_REPORT("   ");
            I->print(errs());
            RES_REPORT("\n");
         }
                    
    }
    RES_REPORT("====== end printing leakerList ==========\n");
    
    RES_REPORT("\n========= printing allocSyscallMap & leakSyscallMap ==========\n");
    cnt = 0;
    for (LeakerList::iterator i = Ctx->leakerList.begin(), 
            e = Ctx->leakerList.end(); i != e; i++, cnt++) {

        std::string structName = i->first;
        RES_REPORT("[" << cnt << "] " << structName << "\n");

        // XXX 
        // AllocSyscallMap::iterator asit = Ctx->allocSyscallMap.find(structName);
        LeakSyscallMap::iterator lsit = Ctx->leakSyscallMap.find(structName);

        assert(
        // XXX 
        //      asit != Ctx->allocSyscallMap.end() &&
               lsit != Ctx->leakSyscallMap.end() &&
               "leakerList is allocSyscallMap AND leakSyscallMap");
        
        // XXX
        /*
        RES_REPORT("<<<<<<<<<<<<<< Allocation <<<<<<<<<<<\n");
        
        for (auto F : asit->second)
            RES_REPORT(F->getName() << "\n");
        */

        RES_REPORT("<<<<<<<<<<<<<< Leaking <<<<<<<<<<<\n");

        for (auto F : lsit->second)
            RES_REPORT(F->getName() << "\n");

        RES_REPORT("\n");

    }
    RES_REPORT("======== end printing allocSyscallMap & leakSyscallMap =======\n");
}

void LeakerAnalyzerPass::dumpThanos()
{
    int count = 0, ji1=0, ji2 = 0;
    OP<<"\n=========== printing Thanos object =============\n";
    for (LeakStructMap::iterator it = Ctx->freeStructMap.begin(),
        e = Ctx->freeStructMap.end(); it != e; it++)
    {
        StructInfo *stInfo = it->second;

        if (stInfo->freeInfo.size() == 0)
            continue;
// (1) 打印 分配点
        if (stInfo->allocaInst.size() == 0)
            continue;
        count++;
        OP<<"\n";
        OP<<"[+][+][+] "<<count<<" "<<stInfo->name<<"\n";
        OP<<"AllocInst:\n";
        for (auto *I : stInfo->allocaInst)
            DEBUG_Inst(0, I);
// (2) 打印释放点
        OP<<"\nFreeInst:";
        ji1=0;
        for (auto const &freeInfo : stInfo->freeInfo)
        {  
            unsigned offset = freeInfo.first;
            OP<<"\n";
            ji1++;
            OP<<"("<<ji1<<") Struct offset: "<<offset<<"\n";
            ji2 = 0;
            for (auto const source : freeInfo.second)
            {   ji2++;
                OP<<"("<<ji1<<"-"<<ji2<<")\n";
                DEBUG_Inst(0, dyn_cast<Instruction>(source.first));
                stInfo->dumpSiteInfo(source.second, 1);
            }
        }
// (3) 打印syscall信息
        FuncSet SYSs;
        SYSs.clear();
        OP<<"\n[+] syscalls:\n";
        OP<<"    Alloc syscall:\n";
        for (auto *I : stInfo->allocaInst)
        {
            Function *F = I->getFunction();
            if (!F) continue;
            FuncSet syscalls = getSyscalls(F);
            for (auto *SF : syscalls)
            {
                // OP<<"        "<<SF->getName()<<"\n";
                if (SYSs.find(SF) == SYSs.end()) 
                    SYSs.insert(SF);
            }
        }
        for (auto *SF : SYSs)
            OP<<"        "<<SF->getName()<<"\n";
        SYSs.clear();
        // OP<<SYSs.size()<<"\n";
        OP<<"    Free syscall:\n";
        for (auto *I : stInfo->freeInst)
        {
            Function *F = I->getFunction();
            if (!F) continue;
            FuncSet syscalls = getSyscalls(F);
            for (auto *SF : syscalls)
            {
                // OP<<"        "<<SF->getName()<<"\n";
                SYSs.insert(SF);
            }
        }
        for (auto *SF : SYSs)
            OP<<"        "<<SF->getName()<<"\n";
    }
    OP<<"======= end printting Thanos object =========\n";
}

