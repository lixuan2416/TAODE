#ifndef _CALL_GRAPH_H
#define _CALL_GRAPH_H

#include "GlobalCtx.h"
// 收集全局变量和指令中的函数地址——Ctx->FuncPtrs，收集被调用过的函数——Ctx->AddressTakenFuncs，更新 Ctx->Callees 和 Ctx->Callers
class CallGraphPass : public IterativeModulePass {
private:
    llvm::Function *getFuncDef(llvm::Function *F);
    bool runOnFunction(llvm::Function*);
    void processInitializers(llvm::Module*, llvm::Constant*, llvm::GlobalValue*, std::string);
    bool findCallees(llvm::CallInst*, FuncSet&);
    bool isCompatibleType(llvm::Type *T1, llvm::Type *T2);
    bool findCalleesByType(llvm::CallInst*, FuncSet&);
    bool mergeFuncSet(FuncSet &S, const std::string &Id, bool InsertEmpty);
    bool mergeFuncSet(std::string &Id, const FuncSet &S, bool InsertEmpty);
    bool mergeFuncSet(FuncSet &Dst, const FuncSet &Src);
    bool findFunctions(llvm::Value*, FuncSet&);
    bool findFunctions(llvm::Value*, FuncSet&, 
                       llvm::SmallPtrSet<llvm::Value*,4>);

public:
    CallGraphPass(GlobalContext *Ctx_)
        : IterativeModulePass(Ctx_, "CallGraph") { }
    virtual bool doInitialization(llvm::Module *);  // doInitialization —— 收集全局变量中的函数地址——Ctx->FuncPtrs，收集被调用过的函数——Ctx->AddressTakenFuncs
    virtual bool doFinalization(llvm::Module *);    // doFinalization —— 根据 Ctx->Callees 来更新 Ctx->Callers
    virtual bool doModulePass(llvm::Module *);      // doModulePass —— 遍历函数，调用runOnFunction —— 识别指令中的函数指针，存入 Ctx->FuncPtrs。分3类指令，CallInst/StoreInst/ReturnInst，对于 CallInst 指令需更新 Ctx->Callees

    // debug
    void dumpFuncPtrs();
    void dumpCallees();
    void dumpCallers();
};

#endif
