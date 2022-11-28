# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.13.1)

# find_package(Zephyr) in order to load application boilerplate:
# http://docs.zephyrproject.org/application/application.html
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

# Path to "os" subdirectory of repository root.
get_filename_component(ROOT_DIR ${CMAKE_CURRENT_LIST_DIR} DIRECTORY)
# get_filename_component(OS_DIR ${APPLICATION_SOURCE_DIR} DIRECTORY)
# Path to repository root.
# get_filename_component(ROOT_DIR ${OS_DIR} DIRECTORY)

file(READ "${ROOT_DIR}/VERSION" SBOOTKIT_VERSION)
# project(sbkboot_${SBOOTKIT_VERSION})

# Path to sdkboot library
set(SBOOTKIT_DIR "${ROOT_DIR}/lib")
assert_exists(SBOOTKIT_DIR)
# Path to tinycrypt library source subdirectory of root.
set(TINYCRYPT_DIR "${ROOT_DIR}/ext/tinycrypt/lib")
assert_exists(TINYCRYPT_DIR)
# Path to kvs library source subdirectory of root.
set(KVS_DIR "${ROOT_DIR}/ext/kvs/lib")
assert_exists(KVS_DIR)

if(CONFIG_SBK)

zephyr_include_directories(
    ${CMAKE_CURRENT_LIST_DIR}
    ${ROOT_DIR}/lib/include
)
zephyr_library_sources(
    ${SBOOTKIT_DIR}/src/sbk_board.c
    ${SBOOTKIT_DIR}/src/sbk_crypto.c
    ${SBOOTKIT_DIR}/src/sbk_image.c
    ${SBOOTKIT_DIR}/src/sbk_os.c
)

zephyr_include_directories_ifdef(CONFIG_SBK_TINYCRYPT
    ${TINYCRYPT_DIR}/include
)
zephyr_library_sources_ifdef(CONFIG_SBK_TINYCRYPT
    ${TINYCRYPT_DIR}/source/utils.c
    ${TINYCRYPT_DIR}/source/sha256.c
    ${TINYCRYPT_DIR}/source/ecc.c
    ${TINYCRYPT_DIR}/source/ecc_dh.c
    ${TINYCRYPT_DIR}/source/ecc_dsa.c
    ${TINYCRYPT_DIR}/source/aes_encrypt.c
    ${TINYCRYPT_DIR}/source/aes_decrypt.c
)

zephyr_compile_definitions(CONFIG_SBK_OS_INCLUDE=zephyr_os_config.h)

zephyr_library_sources(
    ${CMAKE_CURRENT_LIST_DIR}/zephyr_os.c
)

endif()