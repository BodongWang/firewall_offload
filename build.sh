#!/usr/bin/env bash

#set -xeo pipefail
NCPUS=$(nproc)
# default to 4 threads for a reasonable build speed (e.g in travis)
if (( NCPUS < 4 )); then
	NCPUS=4
fi
ROOT_DIR="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
SOURCE_ONLY="n"

# Useful constants
COLOR_RED="\033[0;31m"
COLOR_GREEN="\033[0;32m"
COLOR_OFF="\033[0m"

usage()
{
cat 1>&2 <<EOF
Usage ${0##*/} [-h|?]
    -p BUILD_DIR:     Build directiory, defautl build
    -i INSTALL_DIR:   Install dirctory for GRPC, default build/deps
    -s:               Download source files only without compiling
    -h|?             Show this help message
EOF
}

while getopts ":hp:i:s:" arg; do
	case $arg in
		p)
			BUILD_DIR="${OPTARG}"
			;;
		i)
			INSTALL_DIR="${OPTARG}"
			;;
		s)
			SOURCE_ONLY="y"
			;;
		h | *) # Display help.
			usage
			exit 0
			;;
	esac
done

# Validate required parameters
if [ -z "${BUILD_DIR-}" ] ; then
	#echo -e "${COLOR_RED}[ INFO ] Build dir is not set. So going to build into build ${COLOR_OFF}"
	BUILD_DIR=${ROOT_DIR}/build
	mkdir -p "$BUILD_DIR"
fi

cd "$BUILD_DIR" || exit
DEPS_DIR=$BUILD_DIR/deps
mkdir -p "$DEPS_DIR" || exit

if [ -z "${INSTALL_DIR-}" ] ; then
	#echo -e "${COLOR_RED}[ INFO ] Install dir is not set. So going to install into ${DEPS_DIR} ${COLOR_OFF}"
	INSTALL_DIR=${DEPS_DIR}
	mkdir -p "$INSTALL_DIR"
fi

if [ -n "$FORCE_INSTALL" ]; then
	rm -rf ./deps
	rm -rf "$BUILD_DIR"
fi

build_grpc() {
	if [ -f "${DEPS_DIR}/grpc_installed" ]; then
		echo -e "${COLOR_GREEN}grpc is installed ${COLOR_OFF}"
		return
	fi
	GRPC_DIR=$DEPS_DIR/grpc
	GRPC_BUILD_DIR=$DEPS_DIR/grpc/cmake/_build/
	rm -rf "$GRPC_DIR"
	pushd .
	cd "$DEPS_DIR"
	echo -e "${COLOR_GREEN}[ INFO ] Cloning grpc repo ${COLOR_OFF}"
	# pin specific release of grpc to avoid build failures
	# with new changes in grpc/absl
	git clone --recurse-submodules -b v1.30.0 https://github.com/grpc/grpc
	if [[ "$SOURCE_ONLY" == "y" ]]; then
		echo -e "${COLOR_GREEN}GRPC source download only ${COLOR_OFF}"
		return
	fi
	# this is to deal with a nested dir
	cd grpc
	mkdir -p "$GRPC_BUILD_DIR"
	cd "$GRPC_BUILD_DIR" || exit
	cmake -DgRPC_INSTALL=ON \
		-DgRPC_BUILD_TESTS=OFF \
		-DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
		../..

	make -j "$NCPUS"
	if [ 0 -ne $? ] ; then exit 1 ; fi
	make install
	echo -e "${COLOR_GREEN}grpc is installed ${COLOR_OFF}"
	popd
	touch "${DEPS_DIR}/grpc_installed"
}

build_session_offload() {
	if [ -f "${DEPS_DIR}/sessionOffload_installed" ]; then
		echo -e "${COLOR_GREEN}sessionOffload_installed is installed ${COLOR_OFF}"
		return
	fi
	export PATH=$INSTALL_DIR/bin:$PATH
	pushd .
	cd "$DEPS_DIR"
	git clone -b v1beta1 https://github.com/att/sessionOffload.git
	if [[ "$SOURCE_ONLY" == "y" ]]; then
		echo -e "${COLOR_GREEN}session offload source download only ${COLOR_OFF}"
		return
	fi
	cd sessionOffload/openoffload/cpp/framework
	make -j "$NCPUS" server
	if [ 0 -ne $? ] ; then exit 1 ; fi
	yes | cp lib/libopof_server.a $ROOT_DIR/lib
	touch "${DEPS_DIR}/sessionOffload_installed"
	echo -e "${COLOR_GREEN}sessionOffload is installed ${COLOR_OFF}"
	popd
}

build_firewall_offload() {
	if [[ "$SOURCE_ONLY" == "y" ]]; then
		return
	fi
	cd "$ROOT_DIR"
	export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/opt/mellanox/dpdk/lib/aarch64-linux-gnu/pkgconfig/
	make -j "$NCPUS"
	ln -sf ./build/nv_opof
	if [ 0 -ne $? ] ; then exit 1 ; fi
	echo -e "${COLOR_GREEN}firewall offload is compiled ${COLOR_OFF}"
}

build_kernel() {
	if [ -d "/tmp/ofa_kernel-5.2" ]; then
		echo -e "${COLOR_GREEN}driver is updated ${COLOR_OFF}"; return
	fi
	cd "$ROOT_DIR"/kernel
	./install_kernel_patch.sh *.patch
	echo -e "${COLOR_GREEN}driver is updated ${COLOR_OFF}"
}

build_grpc
build_session_offload
build_firewall_offload
