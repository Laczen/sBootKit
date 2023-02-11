# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.13.1)

# find_package(Zephyr) in order to load application boilerplate:
# http://docs.zephyrproject.org/application/application.html
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(testMINCRYPT)

# Path to mincrypt test directory.
get_filename_component(MINCRYPT_TEST_DIR ${CMAKE_CURRENT_LIST_DIR} DIRECTORY)
assert_exists(MINCRYPT_TEST_DIR)

# Path to mincrypt directory.
get_filename_component(MINCRYPT_DIR ${MINCRYPT_TEST_DIR} DIRECTORY)
assert_exists(MINCRYPT_DIR)

zephyr_include_directories(
    ${MINCRYPT_DIR}/include
    ${MINCRYPT_TEST_DIR}/include
)

zephyr_library_sources(
    ${MINCRYPT_DIR}/src/crypto_sha256.c
    ${MINCRYPT_DIR}/src/crypto_chacha20poly1305.c
    ${MINCRYPT_TEST_DIR}/src/crypto_sha256_tvectors.c
    ${MINCRYPT_TEST_DIR}/src/crypto_chacha20poly1305_tvectors.c
)

FILE(GLOB app_sources src/*.c)

target_sources(app PRIVATE ${app_sources})