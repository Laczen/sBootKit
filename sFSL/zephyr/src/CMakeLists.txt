# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.13.1)

# find_package(Zephyr) in order to load application boilerplate:
# http://docs.zephyrproject.org/application/application.html
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(sFSL)

zephyr_library_sources_ifdef(CONFIG_ARM
    ./src/arm_jump.c
)

FILE(GLOB app_sources src/main.c)

target_sources(app PRIVATE ${app_sources})