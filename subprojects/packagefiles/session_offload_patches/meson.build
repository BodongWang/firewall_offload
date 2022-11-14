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

project('session_offload', 'C', 'CPP')

add_project_arguments(
    '-D_GNU_SOURCE', # strsignal
    language: ['C'])

pkg = import('pkgconfig')

dependency_grpc     = dependency('grpc++')
dependency_protobuf = dependency('protobuf')
dependency_threads	= dependency('threads')

app_dependencies = [
    dependency_grpc,
    dependency_protobuf,
    dependency_threads]

subdir('protos')
subdir('openoffload/cpp/framework/src')
