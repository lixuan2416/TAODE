#!/bin/bash

# Download and extract a tarball to specified destination
function download() {
    URL=$1
    DST=$2
    FILENAME=$(basename $URL)
    wget $URL
    mkdir -p $DST
    tar --strip 1 -xf $FILENAME -C $DST
    rm $FILENAME
}


#1 Set up make jobs 
if [[ -z $MAKE_JOBS ]]; then
    CNT_CPU=$(grep -c ^processor /proc/cpuinfo)
    if [ $CNT_CPU -gt 2 ]; then
        MAKE_JOBS=$((CNT_CPU / 2))
    else
        MAKE_JOBS=1
    fi
fi

#2 Install required packages
sudo apt install -y wget subversion cmake libboost-dev libboost-system-dev \
  git python subversion build-essential curl libcap-dev libncurses5-dev \
  python-minimal python-pip unzip libtcmalloc-minimal4 libgoogle-perftools-dev \
  libgmp-dev zlib1g-dev doxygen libconfig++-dev libsqlite3-dev debootstrap

#3 Download & build & install llvm 10.0 and clang 10.0 
if [ ! -d llvm ]; then
  llvm_version=$(llvm-config --version)
  if [ "$llvm_version" != "10.0.0" ]; then
    # URLs
    URL_LLVM=http://releases.llvm.org/10.0.0/llvm-10.0.0.src.tar.xz
    URL_CLANG=http://releases.llvm.org/10.0.0/cfe-10.0.0.src.tar.xz

    download $URL_LLVM llvm 
    download $URL_CLANG llvm/tools/clang

    mkdir -p llvm/build
    cd llvm/build
    cmake ..
    make -j$MAKE_JOBS
    cd ../..
  fi
fi

#4 Download linux-bitcode for v5.3.0
git clone https://github.com/umnsec/linux-bitcode.git
mv linux-bitcode/linux-5.3.0 .
rm -rf linux-bitcode


<<COMMENT
#4 Download & build Linux kernel v5.3.0, first using gcc, then using clang
URL_LINUX=https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.3.0.tar.xz
download $URL_LINUX linux-5.3.0
cd linux-5.3.0
make defconfig
# gcc
make -j$MAKE_JOBS
#clang
ln -s ../../scripts/bitcodedst.py ./
./bitcodedst.py
cd ../..
COMMENT