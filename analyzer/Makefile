CUR_DIR = $(shell pwd)
SRC_DIR := ${CURDIR}/src
BUILD_DIR := ${CURDIR}/build
LLVM_BUILD := /home/john/Desktop/tools/svf/SVF/llvm-10.0.0.obj

include Makefile.inc

NPROC := ${shell nproc}

build_ka_func = \
	(mkdir -p ${2} \
		&& cd ${2} \
		&& PATH=${LLVM_BUILD}/bin:${PATH} \
			LLVM_ROOT_DIR=${LLVM_BUILD}/bin \
			LLVM_LIBRARY_DIRS=${LLVM_BUILD}/lib \
			LLVM_INCLUDE_DIRS=${LLVM_BUILD}/include \
			CC=clang CXX=clang++ \
            cmake ${1} \
                -DCMAKE_BUILD_TYPE=Release \
                -DCMAKE_CXX_FLAGS_RELEASE="-std=c++14 -fno-rtti -fpic -g" \
		&& make -j${NPROC})

all: analyzer

analyzer: 
	$(call build_ka_func, ${SRC_DIR}, ${BUILD_DIR})
