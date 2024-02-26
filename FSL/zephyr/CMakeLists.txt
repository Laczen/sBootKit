# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.13.1)

# find_package(Zephyr) in order to load application boilerplate:
# http://docs.zephyrproject.org/application/application.html
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(sFSL)

# Path to repository root.
get_filename_component(UPDIR ${CMAKE_CURRENT_LIST_DIR} DIRECTORY)

zephyr_include_directories(
    ${UPDIR}/include
)

FILE(GLOB app_sources ${UPDIR}/src/main.c)

target_sources(app PRIVATE ${app_sources})
