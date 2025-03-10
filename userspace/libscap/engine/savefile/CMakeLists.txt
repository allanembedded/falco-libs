# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
include_directories(${LIBSCAP_INCLUDE_DIRS} ../noop)

# Since we have circular dependencies between libscap and the savefile engine,
# make this library always static (directly linked into libscap)
add_library(scap_engine_savefile
    STATIC
    scap_savefile.c
    scap_reader_gzfile.c
    scap_reader_buffered.c)

add_dependencies(scap_engine_savefile zlib)
target_link_libraries(scap_engine_savefile scap_engine_noop scap_platform_util ${ZLIB_LIB})
