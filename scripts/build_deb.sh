#!/bin/bash -x
name=opof

FILE_DIR="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
ROOT_DIR="$(dirname "$FILE_DIR")"
cd $ROOT_DIR

set -e
# create dist tarball in current directory
VER=$(grep NV_OPOF_VERSION include/nv_opof.h | cut -d'"' -f2)
TARBALL="$name-$VER.tar.gz"
if [ -e $TARBALL ] ; then rm -f $TARBALL; fi
mkdir -p $name-$VER && rm -rf $name-$VER/*
rsync -av --no-links $ROOT_DIR/* $name-$VER \
	--exclude=".*" \
	--exclude="*.o" \
	--exclude=*tar* \
	--exclude=$name-$VER \
	--exclude=build/nv_opof \
	--exclude=build/deps/grpc \
	--exclude=build/deps/sessionOffload \
	--exclude=cscope*
tar -cvzf $name-$VER.tar.gz $name-$VER
rm -rf $name-$VER

rm -rf $HOME/debbuild && mkdir -p $HOME/debbuild
cp $name-$VER.tar.gz $HOME/debbuild
cd $HOME/debbuild && tar -xvf $name-$VER.tar.gz

echo "start deb build..."
cd $name-$VER && dpkg-buildpackage -b -us -uc
