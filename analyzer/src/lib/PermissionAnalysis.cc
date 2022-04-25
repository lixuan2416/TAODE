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

#include "PermissionAnalysis.h"
// doInitialization —— 有些设备是通过全局结构来调用的（如"struct.cdevsw"），检查调用时是否需要特权参数
bool PermissionAnalysisPass::doInitialization(Module *M) {

    for (Module::global_iterator gi = M->global_begin();    // 遍历全局变量，被初始化的值
			gi != M->global_end(); ++gi) {
		GlobalVariable* GV = &*gi;
		if (!GV->hasInitializer())
			continue;
		Constant *Ini = GV->getInitializer();
		if (!isa<ConstantAggregate>(Ini))
			continue;

		checkDevicePermission(Ini);
	}

    return false;
}

// checkPermission —— 如果需要特权则返回true。调用时第4个参数 后3位不为0，则需要特权    return true if the operation is priviledged.
bool PermissionAnalysisPass::checkPermission(CallInst *CI, int offset) {
    Value *v = CI->getOperand(offset);
    if (auto *m = dyn_cast<ConstantInt>(v)) {
        int mode = m->getZExtValue();
        if (mode % 8 == 0 && mode % 64 == 0) {
            return true;
        }
    }
    return false;
}
// checkDevicePermission —— 检查 调用"struct.cdevsw"时的参数是否需要特权，需要特权的函数加入 Ctx->devDenyList
bool PermissionAnalysisPass::checkDevicePermission(User *Ini) {

	list<User *>LU;
	LU.push_back(Ini);

	while (!LU.empty()) {
		User *U = LU.front();
		LU.pop_front();

		bool deny = false;
        bool dev = false;
        if (auto *ST = dyn_cast<StructType>(U->getType())) {                        // 若被初始化为一个结构，且name中含 struct.cdevsw
            if (ST->getName().find("struct.cdevsw") == 0) {
                for (auto *user : U->users()) {
                    for (auto *uu : user->users()) {
                        if (CallInst *CI = dyn_cast<CallInst>(uu)) {                // 被用于call指令中
                            Function *F = CI->getCalledFunction();
                            if (F && F->getName() == "make_dev") {                  // 被调用的函数名包含 make_dev
                                dev = true;
                                deny |= checkPermission(CI, 4);
                            } else if (F && F->getName().find("make_dev") == 0) {   // 被调用的函数名不含 make_dev
                                // log out others
                                outs() << "Please handle this function: " << F->getName() << "\n";
                            }
                        }
                    }
                }
            }
		}

        if (!dev) {
            continue;
        }

		for (auto oi = U->op_begin(), oe = U->op_end(); 
				    oi != oe; ++oi) {
            Value *O = *oi;
            Type *OTy = O->getType();
            
            if (Function *F = dyn_cast<Function>(O)) {
                if (!deny) {
                    // add to allow list
                    outs() << "adding "<<F->getName()<<" to allow list\n";
                    Ctx->devAllowList.insert(F);
                } else {
                    // add to deny list
                    outs() << "adding "<<F->getName()<<" to deny list\n";           // 特权函数 加入 Ctx->devDenyList
                    Ctx->devDenyList.insert(F);
                }

            }
        }
    }

	return true;
}



bool PermissionAnalysisPass::doFinalization(Module *M) {
    return false;
}

bool PermissionAnalysisPass::doModulePass(Module *M) {
    return false;
}