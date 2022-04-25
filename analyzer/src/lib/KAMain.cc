/*
 * main function
 *
 * Copyright (C) 2012 Xi Wang, Haogang Chen, Nickolai Zeldovich
 * Copyright (C) 2015 Byoungyoung Lee
 * Copyright (C) 2015 - 2019 Chengyu Song 
 * Copyright (C) 2016 Kangjie Lu
 * Copyright (C) 2019 Yueqi Chen
 *
 * For licensing details see LICENSE
 */

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/ToolOutputFile.h>
#include <llvm/Support/SystemUtils.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/Path.h>

#include <memory>
#include <vector>
#include <sstream>
#include <sys/resource.h>

#include <stdio.h>          // #####
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>

#include "GlobalCtx.h"
#include "CallGraph.h"
#include "PointerAnalysis.h"
#include "LeakerAnalyzer.h"
#include "LeakerChecker.h"
#include "PermissionAnalysis.h"

using namespace llvm;

char files[20000][256];     // #####
int count_files = -1;       // #####

cl::list<std::string> InputFilenames(
    cl::Positional, cl::OneOrMore, cl::desc("<input bitcode files>"));

cl::opt<unsigned> VerboseLevel(
    "debug-verbose", cl::desc("Print information about actions taken"),
    cl::init(0));

cl::opt<bool> DumpLeakers(
    "dump-leakers", cl::desc("Dump leakers"), cl::NotHidden, cl::init(false));

cl::opt<bool> DumpFlexibleStruts(
    "dump-flexible-st", cl::desc("Dump flexible st"), cl::NotHidden, cl::init(false));

cl::opt<bool> AnalyzeLeakers(
    "check-leakers", cl::desc("Analyze leakers"), cl::NotHidden, cl::init(false));

cl::opt<bool> DumpAlias(
    "dump-alias", cl::desc("Dump alias"), cl::NotHidden, cl::init(false));

cl::opt<bool> DumpSimplified(
    "dump-simple", cl::desc("Dump simplified leakers"), cl::NotHidden,
    cl::init(false));

cl::opt<bool> IgnoreReachable(
    "ignore-reachable", cl::desc("Ignore whether the function is reachable from syscall"),
    cl::NotHidden, cl::init(false));

GlobalContext GlobalCtx;

static void trave_dir(char* path) {     // #####
    DIR *d = NULL;
    struct dirent *dp = NULL; /* readdir函数的返回值就存放在这个结构体中 */
    struct stat st;   
    char p[256] = {0};
    
    if(stat(path, &st) < 0 || !S_ISDIR(st.st_mode)) {
        printf("invalid path: %s\n", path);
        return;
    }

    if(!(d = opendir(path))) {
        printf("opendir[%s] error: %m\n", path);
        return;
    }

    while((dp = readdir(d)) != NULL) {
        /* 把当前目录.，上一级目录..及隐藏文件都去掉，避免死循环遍历目录 */
        if((!strncmp(dp->d_name, ".", 1)) || (!strncmp(dp->d_name, "..", 2)))
            continue;

        snprintf(p, sizeof(p) - 1, "%s/%s", path, dp->d_name);
        stat(p, &st);
        if(!S_ISDIR(st.st_mode)) {
        	count_files++;
        	snprintf(files[count_files], sizeof(files[count_files]) - 1, "%s/%s", path, dp->d_name);
            // printf("%s\n", p);
        } else {
            printf("%s/\n", dp->d_name);
            trave_dir(p);
        }
    }
    closedir(d);

    return;
}

void IterativeModulePass::run(ModuleList &modules) {

    ModuleList::iterator i, e;

    KA_LOGS(0, "[" << ID << "] Initializing " << modules.size() << " modules.\n");
    bool again = true;
    while (again) {
        again = false;
        for (i = modules.begin(), e = modules.end(); i != e; ++i) {
            KA_LOGS(0, "[" << i->second << "]\n");
            again |= doInitialization(i->first);
        }
    }

    KA_LOGS(0, "[" << ID << "] Processing " << modules.size() << " modules.\n");
    unsigned iter = 0, changed = 1;
    while (changed) {
        ++iter;
        changed = 0;
        for (i = modules.begin(), e = modules.end(); i != e; ++i) {
            KA_LOGS(0, "[" << ID << " / " << iter << "] ");
            // FIXME: Seems the module name is incorrect, and perhaps it's a bug.
            KA_LOGS(0, "[" << i->second << "]\n");
            
            bool ret = doModulePass(i->first);
            if (ret) {
                ++changed;
                KA_LOGS(0, "\t [CHANGED]\n");
            } else {
                KA_LOGS(0, "\n");
            }
        }
        KA_LOGS(0, "[" << ID << "] Updated in " << changed << " modules.\n");
    }

    KA_LOGS(0, "[" << ID << "] Finalizing " << modules.size() << " modules.\n");
    again = true;
    while (again) {
        again = false;
        for (i = modules.begin(), e = modules.end(); i != e; ++i) {
            again |= doFinalization(i->first);
        }
    }

    KA_LOGS(0, "[" << ID << "] Done!\n\n");
    return;
}
// doBasicInitialization —— 收集struct（识别struct、扁平化struct、标记弹性对象）、全局对象、全局函数
void doBasicInitialization(Module *M) {
//（1）struct分析：识别struct、扁平化struct、含int成员的struct标记为弹性对象候选项。  struct analysis
    GlobalCtx.structAnalyzer.run(M, &(M->getDataLayout()));
    if (VerboseLevel >= 2)
        GlobalCtx.structAnalyzer.printStructInfo();

//（2）收集全局对象，存于GlobalCtx.Gobjs  collect global object definitions
    for (GlobalVariable &G : M->globals()) {
        if (G.hasExternalLinkage())                                                 // eg, init_ipc_ns
        {
            // OP<<"....... "<<G.getName()<<"\n";
            GlobalCtx.Gobjs[G.getName()] = &G;
        }
    }

//（3）收集全局函数 (用户可调用的函数)，<函数名, 对应函数> 存于GlobalCtx.Funcs  collect global function definitions
    for (Function &F : *M) {
        if (F.hasExternalLinkage() && !F.empty()) {
            // external linkage always ends up with the function name               // eg, ksys_msgget / ksys_msgsnd / ksys_msgrcv
            StringRef FNameRef = F.getName();
            std::string FName = "";
            if (FNameRef.startswith("__sys_"))
                FName = "sys_" + FNameRef.str().substr(6);
            else 
                FName = FNameRef.str();
            // fprintf(stderr, "------- FName: %s\n", FName.c_str());
            // assert(GlobalCtx.Funcs.count(FName) == 0); // force only one defintion
            GlobalCtx.Funcs[FName] = &F;
        }
    }

    return;
}

int main(int argc, char **argv) {

#ifdef SET_STACK_SIZE
    struct rlimit rl;
    if (getrlimit(RLIMIT_STACK, &rl) == 0) {
        rl.rlim_cur = SET_STACK_SIZE;
        setrlimit(RLIMIT_STACK, &rl);
    }
#endif

    // Print a stack trace if we signal out.
#if LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR < 9
    sys::PrintStackTraceOnErrorSignal();
#else
    sys::PrintStackTraceOnErrorSignal(StringRef());
#endif
    PrettyStackTraceProgram X(argc, argv);

    // Call llvm_shutdown() on exit.
    llvm_shutdown_obj Y;  
    
    cl::ParseCommandLineOptions(argc, argv, "global analysis\n");
    SMDiagnostic Err;
/*
    // Load modules
    KA_LOGS(0, "Total " << InputFilenames.size() << " file(s)\n");
// 读取文件，解析文件IR为module，存入 GlobalCtx.Modules，调用 doBasicInitialization() 进行初始化
    for (unsigned i = 0; i < InputFilenames.size(); ++i) {
        // Use separate LLVMContext to avoid type renaming
        KA_LOGS(0, "[" << i << "] " << InputFilenames[i] << "\n");
        LLVMContext *LLVMCtx = new LLVMContext();
        std::unique_ptr<Module> M = parseIRFile(InputFilenames[i], Err, *LLVMCtx);

        if (M == NULL) {
            errs() << argv[0] << ": error loading file '" << InputFilenames[i] << "'\n";
            continue;
        }

        Module *Module = M.release();
        StringRef MName = StringRef(strdup(InputFilenames[i].data()));
        GlobalCtx.Modules.push_back(std::make_pair(Module, MName));
        GlobalCtx.ModuleMaps[Module] = InputFilenames[i];
        doBasicInitialization(Module);                  // doBasicInitialization —— 收集struct（识别struct、扁平化struct、标记弹性对象）、全局对象、全局函数。
    }
*/
    // Load modules
    // char *path = "/home/john/Desktop/test/linux-bitcode/linux-5.3.0";
    // trave_dir(path);
    //char path[256];
    //memcpy
    trave_dir(strdup(InputFilenames[0].data()));
    char security_dir[] = "/home/john/Desktop/test/linux-bitcode/linux-5.3.0/security";
    trave_dir(security_dir);                    // 很多模块都和security模块有交叉，所以一起分析
    KA_LOGS(0, "Total " << count_files << " file(s)\n");
    // 读取文件，解析文件IR为module，存入 GlobalCtx.Modules，调用 doBasicInitialization() 进行初始化
    for (unsigned i = 0; i <= count_files; ++i) {
        // Use separate LLVMContext to avoid type renaming
        KA_LOGS(0, "[" << i << "] " << files[i] << "\n");
        LLVMContext *LLVMCtx = new LLVMContext();
        std::unique_ptr<Module> M = parseIRFile(files[i], Err, *LLVMCtx);

        if (M == NULL) {
            errs() << argv[0] << ": error loading file '" << files[i] << "'\n";
            continue;
        }

        Module *Module = M.release();
        StringRef MName = StringRef(files[i]);  // strdup(files[i].data())
        GlobalCtx.Modules.push_back(std::make_pair(Module, MName));
        GlobalCtx.ModuleMaps[Module] = files[i];
        doBasicInitialization(Module);                  // doBasicInitialization —— 收集struct（识别struct、扁平化struct、标记弹性对象）、全局对象、全局函数。
    }

    CallGraphPass CGPass(&GlobalCtx);                   // 收集全局变量和指令中的函数地址——Ctx->FuncPtrs，收集被调用过的函数——Ctx->AddressTakenFuncs，更新 Ctx->Callees 和 Ctx->Callers
    CGPass.run(GlobalCtx.Modules);
    // CGPass.dumpCallers();

    PointerAnalysisPass PAPass(&GlobalCtx);             // 先调用LLVM自带的别名分析，再收集指令中的指针，判断两两指针是否别名，别名信息存入 Ctx->FuncAAResults
    PAPass.run(GlobalCtx.Modules);
    // PAPass.dumpAlias();

    PermissionAnalysisPass PermissionPass(&GlobalCtx);  // 有些设备是通过全局结构来调用的（如"struct.cdevsw"），检查调用时是否需要特权参数
    PermissionPass.run(GlobalCtx.Modules);

    if(DumpAlias){
        PAPass.dumpAlias();
    }
    
    if (DumpLeakers) {
        LeakerAnalyzerPass LAPass(&GlobalCtx);
        LAPass.run(GlobalCtx.Modules);
        // LAPass.dumpLeakers();
        LAPass.dumpThanos();
    }

    if (AnalyzeLeakers) {
        LeakerCheckerPass LCPass(&GlobalCtx);
        LCPass.run(GlobalCtx.Modules);
        LCPass.dumpChecks();
    }

    if (DumpSimplified) {
        LeakerAnalyzerPass LAPass(&GlobalCtx);
        LAPass.run(GlobalCtx.Modules);
        LAPass.dumpSimplifiedLeakers();
    }

    if (DumpFlexibleStruts) {
        GlobalCtx.structAnalyzer.printFlexibleSt();
    }
    
    return 0;
}
