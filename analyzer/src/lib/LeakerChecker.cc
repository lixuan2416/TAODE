;/*
 * Copyright (C) 2019 Yueqi (Lewis) Chen
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

#include "LeakerChecker.h"
#include "Annotation.h"

using namespace llvm;
using namespace std;

const string test_funcs[] = {
    "verify_replay",
    "user_preparse",
    "unix_bind",
	"necp_client_copy_internal"
};

bool LeakerCheckerPass::doInitialization(Module* M) {
    return false;
}

bool LeakerCheckerPass::doFinalization(Module* M) {
    return false;
}
// doModulePass —— 遍历能到达泄漏点的struct, 对泄露点参数len的source - 进行后向数据流分析，找到其到达泄露点之前的所有use点-LoadInst 和 check点-ICmpInst, 并存入 siteInfo.leakCheckMap
bool LeakerCheckerPass::doModulePass(Module* M) {

    TypeFinder usedStructTypes;
    usedStructTypes.run(*M, false);
    for (auto &st : usedStructTypes) {
        if (st->isOpaque())
            continue;
        // only analyze modules using structures we interested in
        std::string structName = getScopeName(st, M);
        LeakStructMap::iterator it = Ctx->leakStructMap.find(structName);       // 遍历所有 struct, 只分析有泄露点的struct
        if (it == Ctx->leakStructMap.end())
            continue;
        StructInfo* structInfo = it->second;
        for (auto &leak : structInfo->leakInfo) {                               // leakInfo —— [len 所在的struct下标, [call泄露指令, SiteInfo(GEP指令+source struct)]
            for (auto &srcInfo : leak.second) {
                Instruction* leakSite = dyn_cast<Instruction>(srcInfo.first);   // leakSite —— call泄露指令, siteInfo —— len 和 buf 的source信息
                StructInfo::SiteInfo& siteInfo = srcInfo.second;
                // leak site is an instruction
                if (leakSite == nullptr)
                    continue;

                Value* lenValue = siteInfo.lenValue;                            // lenValue —— len的source指令-GEP
                Instruction* retrieveLenInst = dyn_cast<Instruction>(lenValue);
                // retrieve site is an instruction
                if (retrieveLenInst == nullptr)
                    continue;

                Module* RetrieveLenM = retrieveLenInst->getModule();
                // only analyze this Module             只分析本module内的指令
                if (RetrieveLenM != M)
                    continue;

                GetElementPtrInst* GEP = dyn_cast<GetElementPtrInst>(retrieveLenInst);
                // retrieve site is a GEP
                if (GEP == nullptr) {
                    KA_LOGS(0, "[WARNING] Retrieve Length Inst is not GEP: \n");
                    DEBUG_Inst(0, retrieveLenInst); KA_LOGS(0, "\n");
                    continue;
                }
                Value* base = GEP->getOperand(0);                               // base —— len 的 source指针
                // FIXME: deal with alias
                for (Value::use_iterator ui = base->use_begin(), ue = base->use_end();
                    ui != ue; ui++) {
                    Instruction* I = dyn_cast<Instruction>(ui->getUser());      // I —— 使用了len的source指针的 指令
                    SrcSlice tracedV;
                    collectChecks(siteInfo, I, leakSite, base, "", 0, tracedV); // collectChecks —— 后向数据流分析，检查 V 值到达泄漏点之前的use点 。LoadInst-use点, ICmpInst-check点, 将<struct偏移, <load指令/cmp指令, checkSrc>> (另一操作数的source / 是否可达泄露点) 存入 siteInfo.leakCheckMap 
                }
// 遍历所有可泄露的struct, 对每个 len 的 source及其别名, 进行后向数据流分析, 收集其路径约束
                SmallPtrSet<Value*, 16> aliasPtrSet = 
                    getAliasSet(base, GEP->getParent()->getParent());           // 获取 base-len 的 source指针 的别名 aliasPtrSet, 对其别名也进行后向数据流分析，找到use点和check点
                for (auto V : aliasPtrSet) {
                    for(Value::use_iterator ui = V->use_begin(), ue = base->use_end(); 
                        ui != ue; ui++) {
                        Instruction* I = dyn_cast<Instruction>(ui->getUser());
                        SrcSlice tracedV;
                        collectChecks(siteInfo, I, leakSite, V, "", 0, tracedV);
                    }
                }
            }
        }
    }
    return false;
}
// collectChecks —— 后向数据流分析，检查 V 值到达泄漏点之前的use点 。LoadInst-use点, ICmpInst-check点, 将<struct偏移, <load指令/cmp指令, checkSrc>> (另一操作数的source / 是否可达泄露点) 存入 siteInfo.leakCheckMap 
void LeakerCheckerPass::collectChecks(
    StructInfo::SiteInfo& siteInfo,     // siteInfo —— len 和 buf 的source信息
    Instruction* I,                     // I —— 使用了len的source指针的 指令
    Instruction* leakSite,              // leakSite —— call 泄露指令
    Value* V,                           // V —— len的source指针
    string offset, 
    unsigned loadDep,
    SrcSlice& tracedV) {                // tracedV —— 记录已遍历过的 I 指令

    // recursion temination condition
    if (I == nullptr ||
        tracedV.size() > 256 ||
        std::find(tracedV.begin(), tracedV.end(), I) != tracedV.end())
        return;
    tracedV.push_back(I);
// (1) I - GetElementPtrInst, 后向数据流分析，递归检查GEP取出来的值被用于哪里
    if (GetElementPtrInst* GEP = dyn_cast<GetElementPtrInst>(I)) {
        if (GEP->getNumIndices() == 1)
            return;

        PointerType* ptrType = dyn_cast<PointerType>(GEP->getPointerOperandType());
        assert(ptrType != nullptr);
        Type* baseType = ptrType->getElementType();
        StructType* stType = dyn_cast<StructType>(baseType);
        if (stType == nullptr)                                          // 确保 GEP 源操作数指向 struct
            return;        

        // obtain offset                                                // offset —— 获取GEP指令的第3个操作数，也即struct的偏移
        ConstantInt *CI = dyn_cast<ConstantInt>(GEP->getOperand(2));
        uint64_t curOffset = CI->getZExtValue();
        offset = (offset == "") ? to_string(curOffset) : offset + "+" + to_string(curOffset);
        
        // collect forward                                              // 后向搜索GEP取出来的值流向哪里 —— 递归
        for (Value::use_iterator ui = GEP->use_begin(), ue = GEP->use_end();
            ui != ue; ui++) {
            Instruction* I = dyn_cast<Instruction>(ui->getUser());
            collectChecks(siteInfo, I, leakSite, GEP, offset, loadDep, tracedV);
        }
        return;
    }
// (2) I - LoadInst, 作为对source struct的use点存入 siteInfo.leakCheckMap <struct偏移, <use指令, 空CheckSrc>>
    if (LoadInst* LI = dyn_cast<LoadInst>(I)) { 
        if (offset == "") { // first GEP then Load
            KA_LOGS(0, "[WARNING] weird Load: ");
            DEBUG_Inst(0, LI);
        }
        if (loadDep == 1) // one load to access structure field         // 表示已经有一个load访问过该struct
            return;
        unsigned reachableRet = isReachable(I->getParent(), leakSite->getParent());
        if (reachableRet == 0) { // skip not reachable Inst             // isReachable —— load指令能否到达泄露点
            return;
        }

        // add this LI usage to siteInfo
        StructInfo::CheckSrc checkSrc; // Note LI has no check          // LI-LoadInst 没有check，就当做use点存入 siteInfo.leakCheckMap <struct偏移, <use指令, 空CheckSrc>>
        StructInfo::CheckMap::iterator it = siteInfo.leakCheckMap.find(offset);
        if (it == siteInfo.leakCheckMap.end()) {
            StructInfo::CheckInfo checkInfo;
            checkInfo.insert(std::make_pair(I, checkSrc));
            siteInfo.leakCheckMap.insert(std::make_pair(offset, checkInfo));
        } else {
            it->second.insert(std::make_pair(I, checkSrc));
        }

        // collect forward                                              // 递归搜集 load 取出的值，接下来被谁use和check
        for (Value::use_iterator ui = LI->use_begin(), ue = LI->use_end();
            ui != ue; ui++) {
            Instruction* I = dyn_cast<Instruction>(ui->getUser());
            collectChecks(siteInfo, I, leakSite, LI, offset, 1, tracedV);
        }
        return;
    }
// (3) I - ICmpInst, 其中一个操作数是V-len的source，将 <struct偏移, <cmp指令I, checkSrc>> (另一操作数的source / 是否可达泄露点) 存入 siteInfo.leakCheckMap
    if (ICmpInst *ICmp = dyn_cast<ICmpInst>(I)) {
        BasicBlock* BB = ICmp->getParent();
        BranchInst* BI = dyn_cast<BranchInst>(&*(BB->rbegin()));    // ICmp所在基本块中的分支指令
        if (BI == nullptr)
            return;
        unsigned reachableTrueRet, reachableFalseRet;
        if (BI->isUnconditional()) {                                // 无条件跳转，检查分支是否能到达泄露点
            reachableTrueRet = isReachable(BI->getSuccessor(0), leakSite->getParent());
            reachableFalseRet = reachableTrueRet;
        } else if (BI->isConditional()) {                           // 有条件跳转，有一个分支可达泄漏点即可
            assert(BI->getNumSuccessors() == 2);
            reachableTrueRet = isReachable(BI->getSuccessor(0), leakSite->getParent());
            reachableFalseRet = isReachable(BI->getSuccessor(1), leakSite->getParent());
        }

        if (reachableTrueRet == 0 && reachableFalseRet == 0) { // not reachable
            return;
        }

        // collect source of another op                             // 收集另一分支操作数的source，并记录哪条分支能到达泄露点
        Value* op1 = ICmp->getOperand(0);
        Value* op2 = ICmp->getOperand(1);
        Value* unknownSrcOp = (op1 == V)? op2 : op1;                // unknownSrcOp —— len的source 另一个操作数
        StructInfo::CheckSrc checkSrc;
        SrcSlice tracedV;
        if (unknownSrcOp == op1)
            collectCmpSrc(unknownSrcOp, checkSrc.src1, tracedV, 0); // collectCmpSrc —— 前向遍历，查找 unknownSrcOp 的源，若来自 CallInst(若调用的是外部函数)/GEP(且GEP指针指向struct)/常量/本函数的参数，则加入到 checkSrc.src1
        else
            collectCmpSrc(unknownSrcOp, checkSrc.src2, tracedV, 0);
        
        if (reachableTrueRet == 1 && reachableFalseRet == 0)
            checkSrc.branchTaken = 0;
        else if (reachableTrueRet == 0 && reachableFalseRet == 1)
            checkSrc.branchTaken = 1;
        else if (reachableTrueRet == 1 && reachableFalseRet == 1)
            checkSrc.branchTaken = 2;                               // 两分支都可达泄露点

        // add this ICmp comparison to siteInfo                     // 将 <struct偏移, <cmp指令I, checkSrc>> 存入 siteInfo.leakCheckMap
        StructInfo::CheckMap::iterator it = siteInfo.leakCheckMap.find(offset);
        if (it == siteInfo.leakCheckMap.end()) {
            StructInfo::CheckInfo checkInfo;
            checkInfo.insert(std::make_pair(I, checkSrc));
            siteInfo.leakCheckMap.insert(std::make_pair(offset, checkInfo));
        } else {
            it->second.insert(std::make_pair(I, checkSrc));
        }
        return;
    }
// (4) I - CallInst, 后向数据流分析，递归检查被调用函数中 V 值被用于哪里
    if (CallInst* CI = dyn_cast<CallInst>(I)) {
        if (IntrinsicInst* II = dyn_cast<IntrinsicInst>(I))
            return;
        unsigned i = 0;
        for (i = 0; i < CI->getNumArgOperands(); i++) {                         // V (len的source) 对应第 i 个实参
            if (CI->getArgOperand(i) == V)
                break;
        }

        if (i == CI->getNumArgOperands()) {
            KA_LOGS(0, "[WARNING] weird call ");
            DEBUG_Inst(0, CI);
            KA_LOGV(0, V);
            return;
        }

        for (Function* F : Ctx->Callees[CI]) {                                  // 遍历被调用函数，分析 V 流向哪里
            if (F->isDeclaration())
                continue;
            if (F->arg_size() != CI->getNumArgOperands())
                continue;
            Argument* A = F->getArg(i);
            for (Value::use_iterator ui = A->use_begin(), ue = A->use_end();    // 递归检查被调用函数中 形参 A(实参V) 被谁使用
                ui != ue; ui++) {
                Instruction* I = dyn_cast<Instruction>(ui->getUser());
                collectChecks(siteInfo, I, leakSite, A, offset, loadDep, tracedV);
            }
        }
        return;
    }
// (5) I - BinaryOperator, 后向数据流分析，递归检查目的操作数被用于哪里
    if (BinaryOperator* BO = dyn_cast<BinaryOperator>(I)) {
        // collect forward
        for (Value::use_iterator ui = BO->use_begin(), ue = BO->use_end();
            ui != ue; ui++) {
            Instruction* I = dyn_cast<Instruction>(ui->getUser());
            collectChecks(siteInfo, I, leakSite, BO, offset, loadDep, tracedV);
        }
        return;
    }
// (6) I - UnaryInstruction, 后向数据流分析，递归检查目的操作数被用于哪里
    if (UnaryInstruction* UI = dyn_cast<UnaryInstruction>(I)) {
        // collect forward
        for (Value::use_iterator ui = UI->use_begin(), ue = UI->use_end();
            ui != ue; ui++) {
            Instruction* I = dyn_cast<Instruction>(ui->getUser());
            collectChecks(siteInfo, I, leakSite, UI, offset, loadDep, tracedV);
        }
        return;
    }
// (7) I - SelectInst后向数据流分析，递归检查目的操作数被用于哪里
    if (SelectInst* SI = dyn_cast<SelectInst>(I)) {
        for (Value::use_iterator ui = SI->use_begin(), ue = SI->use_end();
            ui != ue; ui++) {
            Instruction* I = dyn_cast<Instruction>(ui->getUser());
            collectChecks(siteInfo, I, leakSite, SI, offset, loadDep, tracedV);
        }
        return;
    }
// (8) I - PHINode, 后向数据流分析，递归检查目的操作数被用于哪里
    if (PHINode* PN = dyn_cast<PHINode>(I)) {
        for (Value::use_iterator ui = PN->use_begin(), ue = PN->use_end();
            ui != ue; ui++) {
            Instruction* I = dyn_cast<Instruction>(ui->getUser());
            collectChecks(siteInfo, I, leakSite, PN, offset, loadDep, tracedV);
        }
        return;
    }
}
// isReachable —— 判断两基本块能否到达
unsigned LeakerCheckerPass::isReachable(BasicBlock* from, BasicBlock* to) {

    std::vector<BasicBlock*> workList;
    std::vector<BasicBlock*> tracedBB;
    workList.clear();
    workList.push_back(from);

    while (!workList.empty() & (tracedBB.size() < 512)) {
        BasicBlock* BB = workList.back();
        workList.pop_back();
        if (BB == to) // reached                                // 可以到达
            return 1;

        // BB has been traced                                   // tracedBB —— 防止重复
        if (std::find(tracedBB.begin(), tracedBB.end(), BB) != tracedBB.end())
            continue;
        tracedBB.push_back(BB);

        // add Terminator-associated successors to worklist     // (1) 子块加入worklist
        Instruction* TI = BB->getTerminator();
        for(unsigned i = 0; i < TI->getNumSuccessors(); i++) {
            BasicBlock* SuccBB = TI->getSuccessor(i);
            workList.push_back(SuccBB);
        }

        // inside function
        if (from->getParent() == to->getParent())
            continue;
        // add CallInst-associated successors to worklist       // (2) call 调用的函数的入口块也加入worklist
        for(auto &I : *BB) {
            if (CallInst* CI = dyn_cast<CallInst>(&I)) {
                if (IntrinsicInst* II = dyn_cast<IntrinsicInst>(&I))
                    continue;
                for (Function* F : Ctx->Callees[CI]) {
                    if (F->isDeclaration())
                        continue;
                    BasicBlock* EntryBB = &(F->getEntryBlock());
                    workList.push_back(EntryBB);
                }
            }
        }
    }
    return 0;
}
// collectCmpSrc —— 前向遍历，查找 V 的源，若来自 CallInst(若调用的是外部函数)/GEP(且GEP指针指向struct)/常量/本函数的参数，则加入到 cmpSrc
void LeakerCheckerPass::collectCmpSrc(
    Value* V,                       // V —— len的source 另一个操作数
    StructInfo::CmpSrc& cmpSrc,     // cmpSrc —— CheckSrc.srcX
    SrcSlice& tracedV,              // tracedV —— 防止重复
    unsigned loadDep) {

    if (V == nullptr ||
        tracedV.size() > 128 || 
        std::find(tracedV.begin(), tracedV.end(), V) != tracedV.end())
        return;

    tracedV.push_back(V);
// (1) V 来自 CallInst 的返回值
    if (CallInst* CI = dyn_cast<CallInst>(V)) {
        if (IntrinsicInst* II = dyn_cast<IntrinsicInst>(V)) {
            cmpSrc.push_back(V);
            return;
        }
        for (Function* F : Ctx->Callees[CI]) { 
            if (F->isDeclaration()) {                               // (1-1) 若调用的是外部函数，则把V加入到 cmpSrc —— source集合
                cmpSrc.push_back(V);
                return;
            }
            // collect backward        
            for (inst_iterator i = inst_begin(F), e = inst_end(F);  // (1-2) 若调用内部函数，递归追踪被调用函数中的返回值来自哪
                i != e; i++) {
                if (ReturnInst* RI = dyn_cast<ReturnInst>(&*i)) {
                    Value *RV = RI->getReturnValue();
                    collectCmpSrc(RV, cmpSrc, tracedV, loadDep);
                }
            }
        }
        return;
    }
// (2) V 来自 UnaryInstruction, 递归
    if (UnaryInstruction* UI = dyn_cast<UnaryInstruction>(V)) {
        Value* V = UI->getOperand(0);
        // collect backward        
        collectCmpSrc(V, cmpSrc, tracedV, loadDep);
        return;
    }
// (3) V 来自 BinaryOperator, 递归
    if (BinaryOperator* BO = dyn_cast<BinaryOperator>(V)) {
        // collect backward        
        for (unsigned i = 0, e = BO->getNumOperands(); i != e; i++) {
            Value* Opd = BO->getOperand(i);
            collectCmpSrc(Opd, cmpSrc, tracedV, loadDep);
        }
        return;
    }
// (4) V 来自 LoadInst, 递归
    if (LoadInst* LI = dyn_cast<LoadInst>(V)) {
        if(loadDep == 1) // only one load to find source
            return;
        Value* V = LI->getPointerOperand();
        collectCmpSrc(V, cmpSrc, tracedV, loadDep);
        return;
    }
// (5) V 来自 PHINode, 递归
    if (PHINode* PN = dyn_cast<PHINode>(V)) {
        // collect backward        
        for (unsigned i = 0, e = PN->getNumIncomingValues(); 
                i != e; i++) {
            Value* IV = PN->getIncomingValue(i);
            collectCmpSrc(IV, cmpSrc, tracedV, loadDep);
        }
        return;
    }
// (6) V 来自 GetElementPtrInst （且GEP指针指向struct）, 加入到 cmpSrc —— source集合
    if (GetElementPtrInst* GEP = dyn_cast<GetElementPtrInst>(V)) {
        if (GEP->getNumIndices() == 1)
            return;
        PointerType* ptrType = dyn_cast<PointerType>(GEP->getPointerOperandType());
        assert(ptrType != nullptr);
        Type* baseType = ptrType->getElementType();

        if (StructType* stType = dyn_cast<StructType>(baseType)) {
            ConstantInt *CI = dyn_cast<ConstantInt>(GEP->getOperand(2));
            assert(CI != nullptr && "GEP's index is not constant");
            cmpSrc.push_back(V);
        }
        return;
    }
// (7) V 来自 Constant, 加入到 cmpSrc —— source集合
    if (Constant *C = dyn_cast<Constant>(V)) {
        cmpSrc.push_back(V);
        return;
    }
// (8) V 来自 SelectInst, 递归
    if (SelectInst* SI = dyn_cast<SelectInst>(V)) {
        collectCmpSrc(SI->getTrueValue(), cmpSrc, tracedV, loadDep);
        collectCmpSrc(SI->getFalseValue(), cmpSrc, tracedV, loadDep);
        return;
    }
// (9) V 来自 Argument 形参, 加入到 cmpSrc —— source集合
    if (Argument* A = dyn_cast<Argument>(V)) {
       cmpSrc.push_back(V);
        return;
    }

    KA_LOGS(0, "[Unknown Value] "); KA_LOGV(0, V);

}


SmallPtrSet<Value*, 16> LeakerCheckerPass::getAliasSet(Value* V, Function* F) {
    
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

void LeakerCheckerPass::dumpChecks() {
    RES_REPORT("\n=========  printing leaker constraints===========\n");
    for (auto leaker : Ctx->leakStructMap) {
        StructInfo *st = leaker.second;
        if(st->leakInfo.size() == 0)
            continue;
        st->dumpLeakChecks();
    }
    RES_REPORT("\n======= end printing leaker constraints ==========\n");
}
