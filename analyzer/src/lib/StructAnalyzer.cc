/*
 * Data structure
 *
 * Copyright (C) 2015 Jia Chen
 * Copyright (C) 2015 - 2019 Chengyu Song
 *
 * For licensing details see LICENSE
 */

#include <llvm/IR/TypeFinder.h>
#include <llvm/Support/raw_ostream.h>
#include <string.h>
#include <stdio.h>

#include "StructAnalyzer.h"
#include "Annotation.h"

using namespace llvm;

// Initialize max struct info
const StructType* StructInfo::maxStruct = NULL;
unsigned StructInfo::maxStructSize = 0;
// addContainer —— 将 <所在的父struct, 对应的偏移> 保存到 containee.containers 集合对 （container-父结构, containee-子结构/孙子结构）
void StructAnalyzer::addContainer(const StructType* container, StructInfo& containee, unsigned offset, const Module* M)
{
	containee.addContainer(container, offset);								// containers —— 所属的父struct -> 对应的偏移
	// recursively add to all nested structs
	const StructType* ct = containee.stType;
	for (auto subType : ct->elements()) {									// 遍历子结构的成员 —— 孙子
		// strip away array
		while (const ArrayType* arrayType = dyn_cast<ArrayType>(subType))
			subType = arrayType->getElementType();
		if (const StructType* structType = dyn_cast<StructType>(subType)) {
			if (!structType->isLiteral()) {									// 如果在structMap中已存在，则根据struct name 取出来
				auto real = structMap.find(getScopeName(structType, M));
				if (real != structMap.end())
					structType = real->second;
			}
			auto itr = structInfoMap.find(structType);

            // XXX: Lewis's quick FIX in the case of itr == structInfoMap.end()
            if (itr == structInfoMap.end())
                return;

			assert(itr != structInfoMap.end());
			StructInfo& subInfo = itr->second;								// subInfo —— 孙子结构对应的 StructInfo
			for (auto item : subInfo.containers) {
				if (item.first == ct)										// item.second —— 孙子结构在子结构中的偏移 = 孙子在子结构中的偏移 + 子结构偏移  ********* 如果还未分析孙子结构subInfo与子结构ct的关系, 则找不到 孙子在子结构中的偏移, 怎么办?????
					addContainer(container, subInfo, item.second + offset, M);
			}
		}
	}
}
// computeStructInfo —— 返回 structInfoMap 中对应的 StructInfo
StructInfo& StructAnalyzer::computeStructInfo(const StructType* st, const Module* M, const DataLayout* layout)
{
	if (!st->isLiteral()) {
		auto real = structMap.find(getScopeName(st, M));		// (1) 结构声明?? 模块名加进去进行标识 
		if (real != structMap.end())
			st = real->second;
	}

	auto itr = structInfoMap.find(st);							// (2) 已存在 structInfoMap 中的结构
	if (itr != structInfoMap.end())
		return itr->second;
	else
		return addStructInfo(st, M, layout);					// (3) 结构定义?? 且未出现过，递归调用 addStructInfo
}
// addStructInfo —— 扁平化struct，含int成员的struct标记 flexibleStructFlag——弹性对象候选项，设置 StructInfo 对应的 stType（struct类型）、dataLayout（该struct的结构）、module
StructInfo& StructAnalyzer::addStructInfo(const StructType* st, const Module* M, const DataLayout* layout)
{
	unsigned numField = 0;					// numField		 —— 域成员的新下标
	unsigned fieldIndex = 0;				// fieldIndex 	 ——域成员原始下标
	unsigned currentOffset = 0;				// currentOffset —— 当前偏移
	StructInfo& stInfo = structInfoMap[st];

	if (stInfo.isFinalized())
		return stInfo;

	const StructLayout* stLayout = layout->getStructLayout(const_cast<StructType*>(st));

    /* XXX Lewis comments following for efficiency					struct扁平化处理
     * Aftert all, structInfo is too complicated to use, really sucks */

	stInfo.addElementType(0, const_cast<StructType*>(st));			// elementType —— 扩展后，第0个成员对应的st类型
// (1) union结构
	if (!st->isLiteral() && st->getName().startswith("union")) {
		// handle union
		stInfo.addFieldOffset(currentOffset);						// fieldOffset —— field 对应的偏移
		stInfo.addField(1, false, false, true);						// fieldSize —— 域大小为1;  unionFlags —— 标记为union
		stInfo.addOffsetMap(numField);								// offsetMap —— 扩展之后，域对应的下标
		//deal with the struct inside this union independently:
		for (auto subType : st->elements()) {						// (1-1) 遍历结构成员
			//deal with fixed size array of struct
			uint64_t arraySize = 1;
			while (const ArrayType* arrayType = dyn_cast<ArrayType>(subType)) {		// (1-1-1) 成员是array-数组, 递归直到不是array的成员
				arraySize *= arrayType->getNumElements();
				subType = arrayType->getElementType();
			}
			if (arraySize == 0) arraySize = 1;

			if (const StructType* structType = dyn_cast<StructType>(subType)) {		// (1-1-2) 成员是struct-结构
				StructInfo& subInfo = computeStructInfo(structType, M, layout);								// 返回 structInfoMap 中对应的 StructInfo
				// assert(subInfo.isFinalized());
				// to allow weird container_of()
				for (uint64_t i = 0; i < arraySize; ++i)
					addContainer(st, subInfo, currentOffset + i * layout->getTypeAllocSize(subType), M);	// addContainer —— 将子结构 <所在的父struct, 对应的偏移> 保存到 containee.containers 集合对 （container-父结构, containee-子结构/孙子结构）
			}
		}
	} else {
		int ji=0;
// (2) 正常struct (非union)            or 结构定义(body)
		for (auto subType : st->elements()) {						// (2-1) 遍历结构成员
			ji++;
			currentOffset = stLayout->getElementOffset(fieldIndex++);										// 更新当前偏移 —— currentOffset
			stInfo.addFieldOffset(currentOffset);															// fieldOffset —— field 对应的偏移

			bool isArray = false;
			// deal with array
			uint64_t arraySize = 1;
			if (const ArrayType* arrayType = dyn_cast<ArrayType>(subType)) {								// field成员是结构数组
				stInfo.addRealSize(layout->getTypeAllocSize(arrayType->getElementType()) * arrayType->getNumElements());
				isArray = true;																				// fieldRealSize —— field 对应展开的大小
			}

			// Treat an array field as a single element of its type
			while (const ArrayType* arrayType = dyn_cast<ArrayType>(subType)) {		// (2-1-1) 成员是array - 数组, 递归直到不是array的成员
				arraySize *= arrayType->getNumElements();
				subType = arrayType->getElementType();
			}
			if (arraySize == 0) arraySize = 1;

			// record type after stripping array
			stInfo.addElementType(numField, subType);														// elementType —— 扩展之后， 第 numField 个成员对应的 struct 类型

			// The offset is where this element will be placed in the expanded struct						// offsetMap —— 扩展之后，域对应的下标
			stInfo.addOffsetMap(numField);

			// Nested struct
			if (const StructType* structType = dyn_cast<StructType>(subType)) {		// (2-1-2) 成员是struct - 结构
				assert(!structType->isOpaque() && "Nested opaque struct");
/*
				if (!st->getStructName().str().compare(structType->getStructName().str()))
					OP<<"******* find one: "<<st->getStructName()<<"\n";
				if ((st->getStructName().str().find("list_head")!= string::npos))
				{ 
					OP<<"111111 find one: "<<st->getStructName()<<"\n";
					OP<<"222222 find one: "<<structType->getStructName()<<"\n";
				}
*/
				// OP<<".........."<<getScopeName(structType, M)<<"\n";
				StructInfo& subInfo = computeStructInfo(structType, M, layout);
				// assert(subInfo.isFinalized());

				// for rare container_of
				for (uint64_t i = 0; i < arraySize; ++i)
					addContainer(st, subInfo, currentOffset + i * layout->getTypeAllocSize(subType), M);	// addContainer —— 将子结构 <所在的父struct, 对应的偏移> 保存到 containee.containers 集合对 （st-父结构, subInfo-子结构/孙子结构）

				// Copy information from this substruct
				stInfo.appendFields(subInfo);																// 拷贝子结构的 fieldSize / fieldRealSize
				stInfo.appendFieldOffset(subInfo);															// 拷贝子结构的 fieldOffset
				stInfo.appendElementType(subInfo);															// 拷贝子结构的 elementType

				numField += subInfo.getExpandedSize();
			} else {																// (2-1-3) 成员不是 struct
				// if ((st->getStructName().str().find("list_head")!= string::npos))
				//	OP<<"333333 find one: "<<ji<<"   "<<st->getStructName()<<"\n";													
				stInfo.addField(1, isArray, subType->isPointerTy(), false);									// fieldSize —— 域大小为1;
				++numField;
				if (!isArray) {
					stInfo.addRealSize(layout->getTypeAllocSize(subType));									// fieldRealSize —— field 对应展开的大小
				}
			}
		}
	}


    // 只要结构中含有int类型，则标记 flexibleStructFlag——弹性对象候选项   check if the structure has integer field
	for (auto subType : st->elements()) {
		if (isa<IntegerType>(subType)) {
			stInfo.flexibleStructFlag = true;
		}
	}

	stInfo.setRealType(st);				// 对应的 StructType
	stInfo.setDataLayout(layout);
	stInfo.setModule(M);
	stInfo.finalize();
	stInfo.name = getScopeName(st, M);

	/* XXX Lewis comments this for efficiency
    StructInfo::updateMaxStruct(st, numField);
    */

	return stInfo;
}

// 扁平化struct，含int成员的struct标记 flexibleStructFlag——弹性对象候选项   We adopt the approach proposed by Pearce et al. in the paper "efficient field-sensitive pointer analysis of C"
void StructAnalyzer::run(Module* M, const DataLayout* layout)
{
	TypeFinder usedStructTypes;				// TypeFinder —— 识别module中用到的所有 StructType 
	usedStructTypes.run(*M, false);
	for (TypeFinder::iterator itr = usedStructTypes.begin(), ite = usedStructTypes.end(); itr != ite; ++itr) {
		const StructType* st = *itr;

		// handle non-literal first
		if (st->isLiteral()) {
			// OP<<"-------------"<<st->getName()<<"\n";	// st->getStructName().str() 	getScopeName(st, M)
			addStructInfo(st, M, layout);				// addStructInfo —— 扁平化struct，含int成员的struct标记 flexibleStructFlag——弹性对象候选项，设置 StructInfo 对应的 stType（struct类型）、dataLayout（该struct的结构）、module
			continue;
		}

		// only add non-opaque type
		if (!st->isOpaque()) {		// 如果是结构声明
			// process new struct only
			if (structMap.insert(std::make_pair(getScopeName(st, M), st)).second) {
				// OP<<"+++++++++++++"<<getScopeName(st, M)<<"\n";	//st->getStructName().str()
					addStructInfo(st, M, layout);
			}
		}
	}
}

// getStructInfo —— 根据StructType获取对应的 StructInfo。   const StructInfo* StructAnalyzer::getStructInfo(const StructType* st, Module* M) const
StructInfo* StructAnalyzer::getStructInfo(const StructType* st, Module* M)
{
	// try struct pointer first, then name
	auto itr = structInfoMap.find(st);
	if (itr != structInfoMap.end())
		return &(itr->second);

	if (!st->isLiteral()) {				// 根据 struct name 返回对应的 StructType
		auto real = structMap.find(getScopeName(st, M));
		//assert(real != structMap.end() && "Cannot resolve opaque struct");
		if (real != structMap.end()) {
			st = real->second;
		} else {
			errs() << "cannot find struct, scopeName:" << getScopeName(st, M) << "\n";
			st->print(errs());
			errs() << "\n";
		}
	}

	itr = structInfoMap.find(st);		// 再根据 StructType 返回对应的 StructInfo
	if (itr == structInfoMap.end())
		return nullptr;
	else
		return &(itr->second);
}

bool StructAnalyzer::getContainer(std::string stid, const Module* M, std::set<std::string> &out) const
{
	bool ret = false;

	auto real = structMap.find(stid);
	if (real == structMap.end())
		return ret;

	const StructType* st = real->second;
	auto itr = structInfoMap.find(st);
	assert(itr != structInfoMap.end() && "Cannot find target struct info");
	for (auto container_pair : itr->second.containers) {
		const StructType* container = container_pair.first;
		if (container->isLiteral())
			continue;
		std::string id = container->getStructName().str();
		if (id.find("struct.anon") == 0 || id.find("union.anon") == 0) {
			// anon struct, get its parent instead
			id = getScopeName(container, M);
			ret |= getContainer(id, M, out);
		} else {
			out.insert(id);
		}
		ret = true;
	}

	return ret;
}

void StructAnalyzer::printStructInfo() const
{
	errs() << "----------Print StructInfo------------\n";
	for (auto const& mapping: structInfoMap) {
		errs() << "Struct " << mapping.first << " ";
        if (!mapping.first->isLiteral())
            errs() << mapping.first->getStructName().str();
        errs() << ": sz <";
		const StructInfo& info = mapping.second;
		for (auto sz: info.fieldSize)
			errs() << sz << " ";
        errs() << ">, rsz < ";
        for (auto rsz : info.fieldRealSize)
            errs() << rsz << " ";
		errs() << ">, offset < ";
		for (auto off: info.offsetMap)
			errs() << off << " ";
		errs() << ">, fieldOffset <";
		for (auto off: info.fieldOffset)
			errs() << off << " ";
		errs() << ">, arrayFlag <";
		for (auto af: info.arrayFlags)
			errs() << af << " ";
		errs() <<">, unionFlag <";
		for (auto uf: info.unionFlags)
			errs() << uf << " ";
		errs() << ">";
		errs() <<">, pointerFlag <";
		for (auto uf: info.pointerFlags)
			errs() << uf << " ";
		errs() << ">";
        if (info.flexibleStructFlag)
            errs() << " flexible";
        errs() << "\n";
	}
	errs() << "----------End of print------------\n";
}

void StructAnalyzer::printFlexibleSt() const
{
	errs() << "----------Print Flexible Structure------------\n";
	for (auto const& mapping: structInfoMap) {
		const StructInfo& info = mapping.second;
		if (!info.flexibleStructFlag) {
			continue;
		}
		// errs() << "Struct " << mapping.first << " ";
        if (!mapping.first->isLiteral()) {
			string name = mapping.first->getStructName().str();

			if (name.find("struct") != 0) {
				continue;
			}

			if (name.find("struct.anon") == 0) {
				continue;
			}
            errs() << name << "\n";
		}
	}
	errs() << "----------Print Flexible Structure Done--------\n";
}