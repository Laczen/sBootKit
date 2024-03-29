# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.13.1)

# find_package(Zephyr) in order to load application boilerplate:
# http://docs.zephyrproject.org/application/application.html
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

# Path to repository root.
get_filename_component(ROOT_DIR ${CMAKE_CURRENT_LIST_DIR} DIRECTORY)

file(READ "${ROOT_DIR}/VERSION" SBOOTKIT_VERSION)
# project(sbkboot_${SBOOTKIT_VERSION})

# Path to sdkboot library
set(SBOOTKIT_DIR "${ROOT_DIR}/lib")
assert_exists(SBOOTKIT_DIR)
# Path to mincrypt library source subdirectory of root.
set(MINCRYPT_DIR "${ROOT_DIR}/ext/mincrypt")
assert_exists(MINCRYPT_DIR)
# Path to p256-m library source subdirectory of root.
set(P256M_DIR "${ROOT_DIR}/ext/p256-m")
assert_exists(P256M_DIR)

if(CONFIG_SBK)

zephyr_include_directories(
    ${CMAKE_CURRENT_LIST_DIR}
    ${ROOT_DIR}/lib/include
)
zephyr_library_sources(
    ${SBOOTKIT_DIR}/src/sbk_crypto.c
    ${SBOOTKIT_DIR}/src/sbk_image.c
    ${SBOOTKIT_DIR}/src/sbk_slot.c
    ${SBOOTKIT_DIR}/src/sbk_tlv.c
    ${SBOOTKIT_DIR}/src/sbk_util.c
    ${SBOOTKIT_DIR}/src/sbk_shell.c
)

zephyr_include_directories_ifdef(CONFIG_SBK_MINCRYPT
    ${MINCRYPT_DIR}/include
)
zephyr_library_sources_ifdef(CONFIG_SBK_MINCRYPT
    ${MINCRYPT_DIR}/src/crypto_chacha20poly1305.c
    ${MINCRYPT_DIR}/src/crypto_sha256.c
)

zephyr_include_directories_ifdef(CONFIG_SBK_P256M
    ${P256M_DIR}
)
zephyr_library_sources_ifdef(CONFIG_SBK_P256M
    ${P256M_DIR}/p256-m.c
)

zephyr_compile_definitions(CONFIG_SBK_UTIL_INCLUDE=zephyr_util.h)

zephyr_library_sources(
    ${CMAKE_CURRENT_LIST_DIR}/zephyr_os.c
)

zephyr_library_sources_ifdef(CONFIG_ARM
    ${CMAKE_CURRENT_LIST_DIR}/zephyr_os_arm.c
)

zephyr_library_sources_ifdef(CONFIG_TARGET_QEMU
    ${CMAKE_CURRENT_LIST_DIR}/zephyr_os_qemu.c
)
endif()
