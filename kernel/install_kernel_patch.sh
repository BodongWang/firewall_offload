#!/bin/bash

function error_exit() {
    text=$1
    echo "error in $text"
    echo "error in $text" >&2
    exit 1
}

driver_version=$(ofed_info | head -n 1 | cut -f 2 -d "(" | cut -f 2 -d "-" )

echo "Deleting /tmp/ofa_kernel-$driver_version..."
rm -rf /tmp/ofa_kernel-$driver_version/

echo "Copying driver to /tmp"
cp -rf /usr/src/ofa_kernel-$driver_version/ /tmp
if [ 0 -ne $? ] ; then error_exit "copy to tmp" ; fi

cp $1 /tmp/ofa_kernel-$driver_version

echo "Chaning directory to /tmp/ofa_kernel-$driver_version"
pushd /tmp/ofa_kernel-$driver_version/

echo "configuring mlnx_rdma..."
opt=$(/etc/infiniband/info |grep "\-\-.*" -o) && ./configure $opt -j
if [ 0 -ne $? ] ; then error_exit "configure mlnx_rdma" ; fi

echo "applying $1..."
patch -p1 < $1
if [ 0 -ne $? ] ; then error_exit "patch apply $1" ; fi

echo "Make and Make install"
make distclean && make -j $('nproc') > /dev/null && sudo make install > /dev/null
if [ 0 -ne $? ] ; then error_exit "make and install" ; fi

echo "Restart driver..."
sudo /etc/init.d/openibd force-restart

popd
