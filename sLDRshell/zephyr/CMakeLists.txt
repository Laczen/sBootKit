# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.13.1)

# find_package(Zephyr) in order to load application boilerplate:
# http://docs.zephyrproject.org/application/application.html
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(sFSL)

zephyr_include_directories(
    ${CMAKE_CURRENT_LIST_DIR}/include
)

zephyr_linker_sources(SECTIONS iterables.ld)

FILE(GLOB app_sources src/main.c src/uart_handle.c src/tshell.c)

target_sources(app PRIVATE ${app_sources})