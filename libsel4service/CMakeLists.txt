#
# Copyright 2017, Data61, CSIRO (ABN 41 687 119 230)
#
# SPDX-License-Identifier: BSD-2-Clause
#

cmake_minimum_required(VERSION 3.7.2)

project(libsel4service C)

file(GLOB deps src/*.c)
list(SORT deps)

add_library(sel4service STATIC EXCLUDE_FROM_ALL ${deps})
target_include_directories(sel4service PUBLIC include)
target_link_libraries(
    sel4service
    PUBLIC
        muslc
        sel4
        sel4muslcsys
        sel4vka
        sel4utils
)
