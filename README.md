### Related paper

This repo is the code repo for TIFS 2022 paper “**From Release to Rebirth: Exploiting Thanos Objects in Linux Kernel**”

### Organization

analyzer - LLVM implementation of static analysis

LLVM_include.tar.gz - LLVM 10.0.0 library files that TAODE needs

results.zip - Thanos objects that TAODE found in FreeBSD, Linux, and XNU

### Build & Use

Please check `scripts/build_essential.sh` for the setup of the environment.

Please read `./analyzer/Makefile` to learn how to compile the analyzer.

General command —— `./build/lib/analyzer -dump-leakers ./IR_dir`.

### Technical details

First, TAODE employs the two-layer type analysis to construct control-flow graph and the LLVM built-in alias analysis pass to do alias analysis. Then, TAODE performs inter-procedural control-flow and data-flow analysis to explore the allocation path and the release path of Thanos objects, which is the main part of TAODE. In the mean time, TAODE can collect the constraints of their field members on release paths. Finally, TAODE can pair the vulnerabilities with suitable Thanos objects, with the given vulnerability capability.

