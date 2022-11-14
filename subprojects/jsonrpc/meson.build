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

project('jsonrpc', 'c')

app_srcs = files([
    'cJSON.c',
    'jsonrpc-c.c'
])

add_project_arguments(
    '-D__STDC_WANT_LIB_EXT2__', # strdup
    '-D_GNU_SOURCE', # getaddrinfo
    language: ['c'])

dependency_threads	= dependency('threads')
dependency_glib2	= dependency('glib-2.0')

cc = meson.get_compiler('c')
dependency_m = cc.find_library('m', required : false)

libev = dependency('ev', required: false)
if libev.found()
    dependency_ev = [ libev ]
elif cc.has_header('ev.h') and cc.has_function('ev_time', args: ['-lev'])
    dependency_ev = [ cc.find_library('ev') ]
else
    error('Couldn\'t find libev header / library')
endif

install_bins = files([])

app_dependencies = [dependency_threads, dependency_glib2, dependency_m, dependency_ev]
app_libs = []
app_inc_dirs = ['.']
bin_install_dir = ''
install_apps = []

lib_json_rpc = static_library('json_rpc', app_srcs,
    override_options : ['warning_level=0'],
	dependencies : app_dependencies,
	link_with : app_libs,
	include_directories: app_inc_dirs,
	install_dir : bin_install_dir,
	install: install_apps)

dependency_json_rpc = declare_dependency(
    include_directories: app_inc_dirs, 
    link_with: lib_json_rpc)
