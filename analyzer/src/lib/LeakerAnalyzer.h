/*
 * Copyright (C) 2019 Yueqi (Lewis) Chen
 *
 * For licensing details see LICENSE
 */

#ifndef LS_H_
#define LS_H_

#include "GlobalCtx.h"
#include <set>

class LeakerAnalyzerPass : public IterativeModulePass {

private:

    void runOnFunction(llvm::Function*);
    bool isCall2Alloc(std::string calleeName);
    bool isCall2Leak(std::string calleeName);
    bool isCall2Free(std::string calleeName);
    void backwardUseAnalysis(llvm::Value *V, std::set<llvm::Value *> &DefineSet);
    llvm::Instruction* forwardUseAnalysis(llvm::Value *V);
    void forwardAnalysis(llvm::Value *V, std::set<llvm::StoreInst *> &StoreInstSet, std::set<llvm::Value *> &TrackSet);
    llvm::Value* getOffset(llvm::GetElementPtrInst *GEP);
    llvm::Value* removeUnaryOp(llvm::Value *I);

    bool expandBinaryOp(llvm::Value *V, std::set<llvm::Value *> &OpendSet);
    void handleGetElement(llvm::Value *V, StoreMap &SM);
    void analyzeAlloc(llvm::CallInst* callInst);
    void analyzeLeak(llvm::CallInst* callInst, std::string calleeName);
    void analyzeFree(llvm::CallInst* callInst, std::string calleeName);
    bool isGEPGetPtr(llvm::GetElementPtrInst *GEP, llvm::StructType* stType);             // 判断是否用GEP从结构中取指针
    bool isGEPIndexNegative(llvm::GetElementPtrInst *GEP);                                // 判断GEP指令的下标是否为负数
    bool isInstFromErrBlock(llvm::Instruction *Inst);                                     // 判断释放点和GEP指令是否位于错误处理块
    bool isInstPassPrivilege(llvm::Function *F, llvm::Instruction *Inst);                 // 判断该指令是否经过 capable(CAP_SYS_ADMIN) 函数   #define CAP_SYS_ADMIN        21
    int  getline(llvm::CallInst* callInst);                                     // 获取指令所在行数
    void outputSources(std::vector<llvm::Value *> &srcSet);                     // 输出所有的源

    bool isPriviledged(llvm::Function *F);

    SmallPtrSet<Value *, 16> getAliasSet(llvm::Value *V, llvm::Function *F);
    void composeMbufLeakAPI(void);
    bool isMbufData(Value *buf);
    void findSources(llvm::Value* V, std::vector<llvm::Value *> &srcSet, std::set<llvm::Value* > &trackedSet);
    void checkChannelUsageinFunc(llvm::Value* V, llvm::Value*&, llvm::Value*&);
    void addLeakInst(StructInfo *stInfo, llvm::CallInst *callInst, unsigned offset, llvm::Instruction *I, llvm::StructType *st);
    void addFreeInst(StructInfo *stInfo, llvm::CallInst *callInst, unsigned offset, llvm::Instruction *I, llvm::StructType *st);
    void setupLeakInfo(std::vector<Value*> &srcSet, llvm::CallInst *callInst, llvm::Value *from);
    void setupFreeInfo(std::vector<Value*> &srcSet, llvm::CallInst *callInst, llvm::Value *from);
    void setupFromInfo(std::vector<llvm::Value*> &srcSet, StructInfo *stInfo, llvm::CallInst *callInst, unsigned offset);
    llvm::StructType* checkSource(std::vector<llvm::Value*>& srcSet, StructTypeSet& stSet , llvm::CallInst *CI, bool isLen);
    FuncSet getSyscalls(Function *F);
    FuncSet reachableSyscall(llvm::Function*);

    // allocAPIVec——内存分配的API   hard-coded SLAB/SLUB allocation API
    std::vector<std::string> allocAPIVec = {
    "__kmalloc", "__kmalloc_node", "kmalloc", "kvzalloc",
    "kmalloc_node", "kmalloc_array", "kzalloc", "kmalloc_array_node", "kzalloc_node",
    "kcalloc_node", "kcalloc", "kmem_cache_alloc", "kmem_cache_alloc_node", "kmem_cache_zalloc",
    "sock_kmalloc",
    };

    // leakAPIVec——泄露API    hard-coded leak API
    std::vector<std::string> leakAPIVec = {
    "put_user", "copy_to_user", "_copy_to_user",
    "nla_put", "skb_put_data", "nlmsg_data",
    "nla_data", "skb_put", "copyout", "m_copyback",
    "m_append",
    };

    std::vector<std::string> freeAPIVec = {
        "kfree","kmem_cache_free",
    };

    //  rootSyscall——特权调用 hard-coded privileged syscalls
    std::vector<std::string> rootSyscall = {
    // CAP_SYS_BOOT
    "sys_reboot", "sys_kexec_load",
    // CAP_SYS_ADMIN
    "sys_swapon", "sys_swapoff", "sys_umount", "sys_oldumount", "sys_quotactl", 
    "sys_mount", "sys_pivot_root", "sys_lookup_dcookie", "sys_bdflush",
    // CAP_SYS_MODULE
    "sys_finit_module", "sys_init_module", "sys_delete_module",
    // CAP_DAC_READ_SEARCH
    "sys_open_by_handle_at",
    // CAP_CHOWN
    "sys_fchown", "sys_fchown16", "sys_fchownat", "sys_lchown", "sys_lchown16",
    "sys_chown", "sys_chown16", "sys_fchmodat", "sys_chmod", "sys_fchmod",
    // CAP_SYS_PACCT
    "sys_acct",
    // CAP_SYS_TIME
    "sys_settimeofday", "sys_stime", "sys_adjtimex",
    // CAP_SYS_CHROOT
    "sys_chroot",
    // CAP_SYSLOG
    "sys_syslog"
    };

    typedef llvm::DenseMap<llvm::Function*, FuncSet> ReachableSyscallCache;
    ReachableSyscallCache reachableSyscallCache;            // 函数F -> 可达F的syscall集合

public:
    int flag_debug;     // 便于调试

    LeakerAnalyzerPass(GlobalContext *Ctx_)
        : IterativeModulePass(Ctx_, "LeakerAnalyzer") {}
    virtual bool doInitialization(llvm::Module* );  // doInitialization —— 识别模块中有body定义的StructType并存入 Ctx->moduleStructMap，识别能通过mbuf泄露内核数据的函数——Ctx->LeakAPIs。
    virtual bool doFinalization(llvm::Module* );    // doFinalization —— 清除moduleStructMap没有泄露点的struct，生成 structModuleMap，leakInstMap 转化为 leakSyscallMap 和 leakerList。
    virtual bool doModulePass(llvm::Module* );      // doModulePass —— 识别StructType的分配点 - allocInstMap，识别泄露点的len和buf的source struct - leakInstMap (确保分配点和泄露点都不需要特权)。

    // debug
    void dumpLeakers();
    void dumpSimplifiedLeakers();
    void dumpThanos();
};

#endif
