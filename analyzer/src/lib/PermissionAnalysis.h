#ifndef PERMISSION_ANALYZER_H
#define PERMISSION_ANALYZER_H

#include "GlobalCtx.h"
#include "Common.h"

using namespace llvm;

class PermissionAnalysisPass : public IterativeModulePass {

private:
    bool checkDevicePermission(User *Ini);
    bool checkPermission(CallInst *CI, int offset);
public:

    PermissionAnalysisPass(GlobalContext *Ctx_)
        : IterativeModulePass(Ctx_, "PermissionAnalysisPass") {}
    virtual bool doInitialization(Module*);     // doInitialization —— 有些设备是通过全局结构来调用的（如"struct.cdevsw"），检查调用时是否需要特权参数
    virtual bool doFinalization(Module*);       // 空
    virtual bool doModulePass(Module*);         // 空
};

#endif
