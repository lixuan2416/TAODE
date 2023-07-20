#ifndef STRUCT_ANALYZER_H
#define STRUCT_ANALYZER_H

#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/ADT/iterator_range.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/DebugLoc.h>
#include <llvm/IR/DebugInfoMetadata.h>

#include <vector>
#include <map>
#include <set>
#include <unordered_map>

#include "Common.h"
#include "Annotation.h"

using namespace llvm;
using namespace std;

// Every struct type T is mapped to the vectors fieldSize and offsetMap.
// If field [i] in the expanded struct T begins an embedded struct, fieldSize[i] is the # of fields in the largest such struct, else S[i] = 1.
// Also, if a field has index (j) in the original struct, it has index offsetMap[j] in the expanded struct.
class StructInfo
{
private:
	// FIXME: vector<bool> is considered to be BAD C++ practice. We have to switch to something else like deque<bool> some time in the future
	std::vector<bool> arrayFlags;			// 是否为 array
	std::vector<bool> pointerFlags;			// 是否为 pointer
	std::vector<bool> unionFlags;			// 是否为 union
	std::vector<unsigned> fieldSize;		// field 对应的展开前的大小
	std::vector<unsigned> offsetMap;		// 扩展之后，域对应的下标
	std::vector<unsigned> fieldOffset;		// field 对应的偏移
	std::vector<unsigned> fieldRealSize;	// field 对应的展开的大小


	// field => type(s) map					扩展之后，      对应下标处 -> 对应的 struct 类型
	std::map<unsigned, std::set<const llvm::Type*> > elementType;
	
	// the corresponding data layout for this struct
	const llvm::DataLayout* dataLayout;
	void setDataLayout(const llvm::DataLayout* layout) { dataLayout = layout; }

	// real type	对应的 StructType
	const llvm::StructType* stType;
	void setRealType(const llvm::StructType* st) { stType = st; }

	// defining module
	const llvm::Module* module;
	void setModule(const llvm::Module* M) { module = M; }

	// container type(s)
	std::set<std::pair<const llvm::StructType*, unsigned> > containers;
	void addContainer(const llvm::StructType* st, unsigned offset)
	{
		containers.insert(std::make_pair(st, offset));
	}

	static const llvm::StructType* maxStruct;
	static unsigned maxStructSize;
	uint64_t allocSize;

	bool finalized;

	void addOffsetMap(unsigned newOffsetMap) { offsetMap.push_back(newOffsetMap); }
	void addField(unsigned newFieldSize, bool isArray, bool isPointer, bool isUnion)
	{
		fieldSize.push_back(newFieldSize);
		arrayFlags.push_back(isArray);
		pointerFlags.push_back(isPointer);
		unionFlags.push_back(isUnion);
	}
	void addFieldOffset(unsigned newOffset) { fieldOffset.push_back(newOffset); }
	void addRealSize(unsigned size) { fieldRealSize.push_back(size); }
	void appendFields(const StructInfo& other)			// 拷贝子结构的 fieldSize / fieldRealSize
	{
		//if (!other.isEmpty()) {						// u64_stats_sync结构没有field, 导致报错, 注释这句话
			fieldSize.insert(fieldSize.end(), (other.fieldSize).begin(), (other.fieldSize).end());
		//}
		arrayFlags.insert(arrayFlags.end(), (other.arrayFlags).begin(), (other.arrayFlags).end());
		pointerFlags.insert(pointerFlags.end(), (other.pointerFlags).begin(), (other.pointerFlags).end());
		unionFlags.insert(unionFlags.end(), (other.unionFlags).begin(), (other.unionFlags).end());
		fieldRealSize.insert(fieldRealSize.end(), (other.fieldRealSize).begin(), (other.fieldRealSize).end());
	}
	void appendFieldOffset(const StructInfo& other)		// 拷贝子结构的 fieldOffset
	{
		unsigned base = fieldOffset.back();
		for (auto i : other.fieldOffset) {
			if (i == 0) continue;
			fieldOffset.push_back(i + base);
		}
	}
	void addElementType(unsigned field, const llvm::Type* type) { elementType[field].insert(type); }
	void appendElementType(const StructInfo& other)		// 拷贝子结构的 elementType
	{
		unsigned base = fieldSize.size();
		for (auto item : other.elementType)
			elementType[item.first + base].insert(item.second.begin(), item.second.end());
	}

	// Must be called after all fields have been analyzed
	void finalize()
	{

	}

	static void updateMaxStruct(const llvm::StructType* st, unsigned structSize)
	{
		if (structSize > maxStructSize) {
			maxStruct = st;
			maxStructSize = structSize;
		}
	}
public:
	bool isFinalized() {
		return finalized;
	}

    /****************** Flexible Structural Object Identification **************/
    bool flexibleStructFlag;										// 表示该结构包含整型成员，为可疑的elastic object
    std::vector<unsigned> lenOffsetByFlexible; // TODO fill this vector in flexible part
    std::vector<unsigned> lenOffsetByLeakable; // TODO fill this vector in leakable part
    /**************** End Flexible Structural Object Identification ************/

	// external information
	std::string name;
	llvm::SmallPtrSet<llvm::Instruction*, 32>   allocaInst;			// 分配该struct的call指令
	llvm::SmallPtrSet<llvm::Instruction*, 32>   leakInst;			// 能够泄露该struct的call指令
	llvm::SmallPtrSet<llvm::Instruction*, 32>   freeInst;			// free										//###################

    typedef std::vector<Value*> CmpSrc;
    struct CheckSrc{	// cmp check信息
        CmpSrc src1;						// 分支操作数的source集
        CmpSrc src2;
        unsigned branchTaken;				// 分支是否可达泄露点 (0-true分支可达, 1-false分支可达, 2-两个分支都可达)
    };

    typedef std::unordered_map<llvm::Instruction*, CheckSrc> CheckInfo;
    typedef std::unordered_map<string, CheckInfo> CheckMap; 		// <struct偏移, <use指令, CheckSrc>>
    CheckMap allocCheck, otherCheck;

	struct SiteInfo {	// len 和 buf 的source信息
		unsigned TYPE;						// 堆还是栈 / 和len的source相同还是不同
		// location info can be stored in Value
		// see the location by calling DEBUG_Inst()
		// value stores Load or GEP, which indicates load-GEP pair
		llvm::StructType *fromSt=nullptr;	// buf的source struct
		llvm::Value *fromValue=nullptr;		// buf的source指令			
		llvm::StructType *lenSt=nullptr;	// len的source struct
		llvm::Value *lenValue=nullptr;		// len的source指令-GEP
		llvm::StructType *bufSt=nullptr;	// buf的source struct												//###################
		// llvm::Value *bufValue=nullptr;		// buf的source指令													//###################
		std::set<llvm::Value *> bufValueSet; // buf的source指令集												//###################     改进12: 需要存多条GEP指令, 因为有的GEP来自错误处理块
        CheckMap leakCheckMap; 				// 泄露前的use点 <struct偏移, <use指令, CheckSrc>>  usage of all fields before leaking
	};
	// differents values represent different leaking sites
	// value here equals call copyout(from, to, len);
	typedef std::unordered_map<llvm::Value *, SiteInfo> LeakSourceInfo;		// call泄露指令 -> SiteInfo
	// len offset and leakInfo
	typedef std::unordered_map<unsigned, LeakSourceInfo> LeakInfo;			// len的source在GEP中的下标 -> LeakSourceInfo

	typedef std::set<SiteInfo*> SiteInfoSet;																			//###################  为泄露点设计的数据结构  需存多条GEP指令
	typedef std::unordered_map<llvm::Value *, SiteInfoSet> FreeSourceInfo;		// call泄露指令 -> SiteInfoSet				 //###################  改进12: 需要存多条GEP指令, 因为有的GEP来自错误处理块
	typedef std::unordered_map<unsigned, FreeSourceInfo> FreeInfo;			// len的source在GEP中的下标 -> FreeSourceInfo//###################

	LeakInfo leakInfo;						// [len 所在的struct下标, [call泄露指令, SiteInfo(GEP指令+source struct)]
	LeakInfo freeInfo;						// [buf 所在的struct下标, [call释放指令, SiteInfo(GEP指令 + source struct)]]
// addLeakSourceInfo —— 将泄露信息 [len 所在的struct下标, [call泄露指令, SiteInfo(GEP指令+source struct)] 存入 StructInfo-> leakInfo
	void addLeakSourceInfo(unsigned offset, llvm::Value *V, SiteInfo siteInfo){	// offset——len 所在的struct下标; V——call泄露指令; siteInfo——len的source指令和source struct

		if(leakInfo.find(offset) == leakInfo.end()){		// (1) 不存在 struct 下标 - offset
			LeakSourceInfo LSI;
			LSI.insert(std::make_pair(V, siteInfo));
			leakInfo.insert(std::make_pair(offset, LSI));
			return;
		}

		LeakInfo::iterator it = leakInfo.find(offset);

		if(it->second.find(V) == it->second.end()){			// (2) 存在偏移 struct 下标 - offset, 不存在V这条泄漏指令
			it->second.insert(std::make_pair(V, siteInfo));
			return;
		}

		WARNING("Are we trying to update siteInfo?");
		assert(false && "BUG?");

		LeakSourceInfo::iterator sit = it->second.find(V);	// (3) 存在偏移 struct 下标 - offset, 存在V这条泄漏指令, 加入 SiteInfo
		sit->second = siteInfo;
	}
// addFreeSourceInfo —— 将释放信息 [buf 所在的struct下标, [call释放指令, SiteInfo(GEP指令 + source struct)]] 存入 StructInfo->freeInfo
	void addFreeSourceInfo(unsigned offset, llvm::Value *V, SiteInfo siteInfo, llvm::Instruction *I)
	{
		if(freeInfo.find(offset) == freeInfo.end())			// (1) 不存在 struct 下标 - offset
		{
			LeakSourceInfo LSI;
			LSI.insert(std::make_pair(V, siteInfo));
			freeInfo.insert(std::make_pair(offset, LSI));
			return;
		}

		LeakInfo::iterator it = freeInfo.find(offset);

		if (it->second.find(V) == it->second.end()){		// (2) 存在偏移 struct 下标 - offset, 不存在V这条泄漏指令
			it->second.insert(std::make_pair(V, siteInfo));
			return;
		}

		WARNING("Are we tring to update siteInfo?");
		// assert(false && "BUG?");

		LeakSourceInfo::iterator sit = it->second.find(V);	// (3) 存在偏移 struct 下标 - offset, 存在V这条泄漏指令, 加入 SiteInfo
		// sit->second.bufV = siteInfo;
		sit->second.bufValueSet.insert(I);					// 改进 12
	}
// getSiteInfo —— 根据struct 偏移和 call泄露指令, 从 StructInfo->leakInfo 中找到对应的 SiteInfo
	SiteInfo *getSiteInfo(unsigned offset, llvm::Value *V){

		if(leakInfo.find(offset) == leakInfo.end()){
			return nullptr;
		}

		LeakInfo::iterator it = leakInfo.find(offset);

		if(it->second.find(V) == it->second.end()){
			return nullptr;
		}

		LeakSourceInfo::iterator sit = it->second.find(V);
		return &sit->second;
	}

	void dumpSiteInfo(SiteInfo siteInfo, int func){
		/*if (func == 1)					// 打印 Thanos对象的释放点信息
		{
			if(siteInfo.bufValue && siteInfo.bufSt)
			{
				OP<<"buf Value: \n";
				DEBUG_Inst(0, dyn_cast<Instruction>(siteInfo.bufValue));
			}
			return;
		}*/

		if (func == 1)					// 打印 Thanos对象的释放点信息					改进12
		{
			if(siteInfo.bufValueSet.size() && siteInfo.bufSt)
			{
				OP<<"buf Value: \n";
				int ji=0;
				for (std::set<llvm::Value*>::iterator i = siteInfo.bufValueSet.begin(),
					e = siteInfo.bufValueSet.end(); i != e; i++)
				{
					ji++;
					OP<<"    ["<<ji<<"]\n";
					OP<<"    ";
					Value *V = *i;
					Instruction *Inst = dyn_cast<Instruction>(V);
					DEBUG_Inst(0, dyn_cast<Instruction>(Inst));
				}
			}
			return;
		}
		
		if(siteInfo.lenValue && siteInfo.lenSt){
			KA_LOGS(0, "len Value ");
			DEBUG_Inst(0, dyn_cast<Instruction>(siteInfo.lenValue));
			KA_LOGS(0, "StructType : "<< siteInfo.lenSt->getName() << "\n");
		}
		if(siteInfo.fromValue){
			KA_LOGS(0, "from Value ");
			if(dyn_cast<Instruction>(siteInfo.fromValue)){
				DEBUG_Inst(0, dyn_cast<Instruction>(siteInfo.fromValue));
			}else{
				KA_LOGS(0, *siteInfo.fromValue);
				for(auto *user : siteInfo.fromValue->users()){
					if(auto *I = dyn_cast<Instruction>(user)){
						KA_LOGS(0, " in " << I->getModule()->getName());
						break;
					}
				}
			}

		}
		if(siteInfo.fromSt){
			KA_LOGS(0, "StructType : "<< siteInfo.fromSt->getName() << "\n");
		}
		KA_LOGS(0,"\n");
	}

	void dumpAllocInst(){
		for( auto *I : allocaInst ){
			// KA_LOGS(0, *I << "\n");
			DEBUG_Inst(0, I);
			// KA_LOGS(0, "\n");
		}
	}

	void dumpLeakInst(){
		for( auto *I : leakInst){
			KA_LOGS(0, *I << "\n");
		}
	}

	void dumpLeakInfo(bool dumpAllocable){

		if(dumpAllocable && allocaInst.size() == 0)
			return;

		RES_REPORT("[+] "<<name<<"\n");
		
		KA_LOGS(0,"AllocInst:\n");
		dumpAllocInst();
		KA_LOGS(0,"LeakInst:\n");
		for( auto const &leak : leakInfo){
			
			unsigned offset = leak.first;
			
			for ( auto const &source : leak.second){

				switch (source.second.TYPE)
				{
				case STACK:
					DEBUG_Inst(0, dyn_cast<Instruction>(source.first));
					KA_LOGS(0, " Leaking from STACK at offset : " << offset << "\n");
					break;

				case HEAP_SAME_OBJ:
					DEBUG_Inst(0, dyn_cast<Instruction>(source.first));
					KA_LOGS(0, " Leaking from the same object in the HEAP at offset : " << offset << "\n");
					break;

				case HEAP_DIFF_OBJ:
					DEBUG_Inst(0, dyn_cast<Instruction>(source.first));
					KA_LOGS(0, " Leaking from the different object in the HEAP at offset : " << offset << "\n");
					break;
				
				default:
					DEBUG_Inst(0, dyn_cast<Instruction>(source.first));
					KA_LOGS(0, " Unknown object at offset: " << offset << "\n");
					break;
				}

				dumpSiteInfo(source.second, 0);
			}
		}
	}


	void dump(){
		if(leakInfo.size() == 0)
			return;
		dumpLeakInfo(true);
		KA_LOGS(0, "\n\n");
	}

	void dumpAll(){
		dumpLeakInfo(false);
	}
// dumpLeakChecks —— 打印 StructInfo
    void dumpLeakChecks() {
        if (allocaInst.size() == 0)
            return;
        RES_REPORT("[+] "<<name<<"\n");

        for (auto const &leak : leakInfo) {												// leakInfo - [len 所在的struct下标, [call泄露指令, SiteInfo(GEP指令+source struct)]
            unsigned offset = leak.first;
            LeakSourceInfo leakSrcInfo = leak.second;
            RES_REPORT("<<<<<<<<<<<<<<<<< Length offset: " << offset << " >>>>>>>>>>>>>>>>\n");
            for ( auto const &srcInfo : leakSrcInfo){
                Instruction* leakSite = dyn_cast<Instruction>(srcInfo.first);			// leakSite - call 泄露指令
                SiteInfo siteInfo = srcInfo.second;
                Value* lenValue = siteInfo.lenValue;
                Instruction* retrieveLenInst = dyn_cast<Instruction>(lenValue);			// retrieveLenInst - GEP指令

                if (leakSite == nullptr || retrieveLenInst == nullptr)
                    continue;

                RES_REPORT("=================== Retrieve Site =================\n"); 
                DEBUG_Inst(0, retrieveLenInst);

                RES_REPORT("=================== Leak Site =================\n"); 
                // e.g., copyout
                DEBUG_Inst(0, leakSite);

                RES_REPORT("=================== Checks ===================\n");
                for (auto checkMap : siteInfo.leakCheckMap) {							// checkMap - <struct偏移, <use指令, CheckSrc>>
                    string offset = checkMap.first;
                    CheckInfo checkInfo = checkMap.second;

                    RES_REPORT("--------------- field offset: " << offset << "-------------\n");
                    for (auto checks : checkInfo) {
                        Instruction* I = checks.first;
                        CheckSrc checkSrc = checks.second;								// checkSrc - cmp check信息
                        DEBUG_Inst(0, I);
                        
                        if (ICmpInst* ICMP = dyn_cast<ICmpInst>(I)) {					// 打印 checkSrc 信息
                            // e.g., |xx| [>] true |xx|
                            for (auto V : checkSrc.src1)								// dumpCmpSrc —— 打印 len source 的信息, 所在的 struct 及其 偏移
                                dumpCmpSrc(V);
                            dumpPred(ICMP, checkSrc.branchTaken);						// dumpPred —— 打印路径约束
                            for (auto V : checkSrc.src2)
                                dumpCmpSrc(V);
                        }
                        RES_REPORT("\n------------------------------------------\n");
                    }
                }
            }
        }
    }
// dumpCmpSrc —— 打印 len source 的信息, 所在的 struct 及其 偏移
    void dumpCmpSrc(Value* V) {
        RES_REPORT("| ");
        if (GetElementPtrInst* GEP = dyn_cast<GetElementPtrInst>(V)) {					
            PointerType* ptrType = dyn_cast<PointerType>(GEP->getPointerOperandType());
            assert(ptrType != nullptr);
            Type* baseType = ptrType->getElementType();
            StructType* stType = dyn_cast<StructType>(baseType);
            assert(stType != nullptr);

            Module* M = GEP->getParent()->getParent()->getParent();
            string structName = getScopeName(stType, M);

            ConstantInt *CI = dyn_cast<ConstantInt>(GEP->getOperand(2));
            assert(CI != nullptr && "GEP's index is not constant");
            int64_t offset = CI->getSExtValue();

            RES_REPORT("<" << structName << ", " << offset << ">");

        } else if (ConstantInt *CI = dyn_cast<ConstantInt>(V)) {
            int64_t num = CI->getSExtValue();
            RES_REPORT("<C, " << num  << ">");
        } else if (ConstantPointerNull * CPN = dyn_cast<ConstantPointerNull>(V)) {
            RES_REPORT("<C, null>");
        } else if (IntrinsicInst* II = dyn_cast<IntrinsicInst>(V)) {
            string name = II->getCalledFunction()->getName().str();
            RES_REPORT("<Intrinsic, " << name << ">");
        } else if (CallInst* CI = dyn_cast<CallInst>(V)){
            RES_REPORT("<CallInst, ");
            Function* F = CI->getCalledFunction();
            if (F == nullptr || !F->hasName()) {
                CI->print(errs());
                RES_REPORT(">");
            } else {
                string name = F->getName().str();
                RES_REPORT(name << ">");
            }
        } else if (Argument* A = dyn_cast<Argument>(V)) {
            RES_REPORT("<Arg, ");
            A->print(errs());
            RES_REPORT(">");
        } else if (BitCastInst* BCI = dyn_cast<BitCastInst>(V)) {
            RES_REPORT("<BitCast, ");
            BCI->print(errs());
            RES_REPORT(">");
        } else {
            RES_REPORT("<Unknown, ");
            V->print(errs());
            RES_REPORT(">"); // it shouldn't happen but it does
        }
        RES_REPORT(" |");
    }
// dumpPred —— 打印路径约束
    void dumpPred(ICmpInst* ICMP, unsigned branchTaken) {
        ICmpInst::Predicate Pred = ICMP->getPredicate();
        switch (Pred) {
            case ICmpInst::ICMP_SLT:
            case ICmpInst::ICMP_ULT:
                if (branchTaken == 0) { // true
                    RES_REPORT(" [<] ");
                } else if (branchTaken == 1) { // false
                    RES_REPORT(" [>=] ");
                } else { // both
                    RES_REPORT(" [<]* ");
                }
                break;

            case ICmpInst::ICMP_SGT:
            case ICmpInst::ICMP_UGT:
                if (branchTaken == 0) { // true
                    RES_REPORT(" [>] ");
                } else if (branchTaken == 1) { // false
                    RES_REPORT(" [<=] ");
                } else { // both
                    RES_REPORT(" [>]* ");
                }
                break;
            
            case ICmpInst::ICMP_ULE:
            case ICmpInst::ICMP_SLE:
                if (branchTaken == 0) { // true
                    RES_REPORT(" [<=] ");
                } else if (branchTaken == 1) { // false
                    RES_REPORT(" [>] ");
                } else { // both
                    RES_REPORT(" [<=]* ");
                }
                break;

            case ICmpInst::ICMP_SGE:
            case ICmpInst::ICMP_UGE:
                if (branchTaken == 0) { // true
                    RES_REPORT(" [>=] ");
                } else if (branchTaken == 1) { // false
                    RES_REPORT(" [<] ");
                } else { // both
                    RES_REPORT(" [>=]* ");
                }
                break;

            case ICmpInst::ICMP_EQ:
                if (branchTaken == 0) { // true
                    RES_REPORT(" [==] ");
                } else if (branchTaken == 1) { // false
                    RES_REPORT(" [!=] ");
                } else { // both
                    RES_REPORT(" [==]* ");
                }
                break;

            case ICmpInst::ICMP_NE:
                if (branchTaken == 0) { // true
                    RES_REPORT(" [!=] ");
                } else if (branchTaken == 1) { // false
                    RES_REPORT(" [==] ");
                } else { // both
                    RES_REPORT(" [!=]* ");
                }
                break;

            default:
                break;
        }
    }

	void dumpSimplified(){
		if(allocaInst.size() == 0)
			return;

		// RES_REPORT("[+] "<<name<<"\n");
		for( auto const &leak : leakInfo){

			unsigned offset = leak.first;
			// RES_REPORT(name << " " << offset << "\n");
			outs() << name << " " << offset << "\n";
			
		}

	}


	// # fields == # arrayFlags == # pointer flags
	// size => # of fields????
	// getExpandedSize => # of unrolled fields???

	typedef std::vector<unsigned>::const_iterator const_iterator;
	unsigned getSize() const { return offsetMap.size(); }
	unsigned getExpandedSize() const { return arrayFlags.size(); }

	bool isEmpty() const { return (fieldSize[0] == 0);}
	bool isFieldArray(unsigned field) const { return arrayFlags.at(field); }
	bool isFieldPointer(unsigned field) const { return pointerFlags.at(field); }
	bool isFieldUnion(unsigned field) const { return unionFlags.at(field); }
	unsigned getOffset(unsigned off) const { return offsetMap.at(off); }
	const llvm::Module* getModule() const { return module; }
	const llvm::DataLayout* getDataLayout() const { return dataLayout; }
	const llvm::StructType* getRealType() const { return stType; }
	const uint64_t getAllocSize() const { return allocSize; }
	unsigned getFieldRealSize(unsigned field) const { return fieldRealSize.at(field); }
	unsigned getFieldOffset(unsigned field) const { return fieldOffset.at(field); }
	std::set<const llvm::Type*> getElementType(unsigned field) const
	{
		auto itr = elementType.find(field);
		if (itr != elementType.end())
			return itr->second;
		else
			return std::set<const llvm::Type*>();
	}
	const llvm::StructType* getContainer(const llvm::StructType* st, unsigned offset) const
	{
		assert(!st->isOpaque());
		if (containers.count(std::make_pair(st, offset)) == 1)
			return st;
		else
			return nullptr;
	}

	static unsigned getMaxStructSize() { return maxStructSize; }

	friend class StructAnalyzer;
};

// Construct the necessary StructInfo from LLVM IR
// This pass will make GEP instruction handling easier
class StructAnalyzer
{
private:
	// 映射StructType->相应的StructInfo    Map llvm type to corresponding StructInfo
	typedef std::map<const llvm::StructType*, StructInfo> StructInfoMap;
	StructInfoMap structInfoMap;

	// 映射struct名-> StructType   Map struct name to llvm type
	typedef std::map<const std::string, const llvm::StructType*> StructMap;
	StructMap structMap;

	// Expand (or flatten) the specified StructType and produce StructInfo
	StructInfo& addStructInfo(const llvm::StructType* st, const llvm::Module* M, const llvm::DataLayout* layout);
	// If st has been calculated before, return its StructInfo; otherwise, calculate StructInfo for st
	StructInfo& computeStructInfo(const llvm::StructType* st, const llvm::Module *M, const llvm::DataLayout* layout);
	// update container information
	void addContainer(const llvm::StructType* container, StructInfo& containee, unsigned offset, const llvm::Module* M);
public:
	StructAnalyzer() {}

	// Return NULL if info not found
	// const StructInfo* getStructInfo(const llvm::StructType* st, llvm::Module* M) const;
	StructInfo* getStructInfo(const llvm::StructType* st, llvm::Module* M);
	size_t getSize() const { return structMap.size(); }
	bool getContainer(std::string stid, const llvm::Module* M, std::set<std::string> &out) const;
	//bool getContainer(const llvm::StructType* st, std::set<std::string> &out) const;

	void run(llvm::Module* M, const llvm::DataLayout* layout);

	void printStructInfo() const;
	void printFlexibleSt() const;
};

#endif
