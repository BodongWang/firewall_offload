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

app_srcs = [
    'opof_session_server.cc',
    'opof_server.cc',
    'opof_util.cc']

app_dependencies = [
    dependency_grpc,
    dependency_protobuf,
    dependency_threads,
    dependency_open_offload_grpc]

app_libs = []
app_inc_dirs = ['../include']
bin_install_dir = ''
install_apps = []

lib_open_offload = static_library('opof_server', app_srcs,
    override_options : ['warning_level=0'],
	dependencies : app_dependencies,
	link_with : app_libs,
	include_directories: app_inc_dirs,
	install_dir : bin_install_dir,
	install: install_apps)

dependency_open_offload = declare_dependency(
    include_directories: app_inc_dirs, 
    link_with: lib_open_offload)

test_srcs = [
    'opof_session_client.cc',
    'opof_clientlib.cc',
    'opof_client_main.c',
    'opof_util.cc',
    'opof_test_util.c',
    'opof_error.c',
    'opof_run_tests.c',
]
test_open_offload = executable('test_opof', test_srcs,
    override_options : ['warning_level=0'],
	dependencies : app_dependencies,
	link_with : app_libs,
	include_directories: app_inc_dirs,
	install_dir : bin_install_dir,
	install: install_apps)
