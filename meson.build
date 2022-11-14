#
# Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of NVIDIA CORPORATION &
# AFFILIATES (the "Company") and all right, title, and interest in and to the
# software product, including all associated intellectual property rights, are
# and shall remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.
#

project('opof', 'C', 'CPP',
	# Get version number from file.
	# Fallback to "more" for Windows compatibility.
	version: run_command(find_program('cat', 'more'), files('VERSION'), check: true).stdout().strip(),
	default_options: [
		'buildtype=debug',
		'b_staticpic=true',
		'prefix=/opt/mellanox/opof',
		'c_std=c11', 
		'cpp_std=c++11'
		],
	meson_version: '>= 0.56.0'
)

languages = ['c', 'cpp']

# Required for DPDK
add_project_arguments(
    '-D__STDC_WANT_LIB_EXT2__',
    '-D_GNU_SOURCE',
	'-DALLOW_EXPERIMENTAL_API', 
	language: languages)

pkg = import('pkgconfig')

dependency_libdpdk	= dependency('libdpdk')
dependency_grpc     = dependency('grpc++')
dependency_protobuf = dependency('protobuf')
dependency_threads	= dependency('threads')

# Our target is all C so Meson doesn't realize libstdc++ is needed.
# Supply it explicitly to the dependency list.
cc = meson.get_compiler('cpp')
dependency_stdcpp   = cc.find_library('stdc++', required : true)

grpc_dependencies = [
	dependency_protobuf,
	dependency_grpc,
	dependency_threads,
	dependency_stdcpp
]

proj_json_rpc = subproject('jsonrpc')
dependency_json_rpc = proj_json_rpc.get_variable('dependency_json_rpc')

proj_session_offload = subproject('session_offload')
dependency_open_offload = proj_session_offload.get_variable('dependency_open_offload')

subdir('src')

