#ifndef ZEPHYR_UTIL_H_
#define ZEPHYR_UTIL_H_

#include <zephyr/sys/__assert.h>
#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(sbk, CONFIG_SBK_LOG_LEVEL);

#ifdef __cplusplus
extern "C"
{
#endif

#define SBK_ASSERT(test) __ASSERT_NO_MSG(test)
#define SBK_LOG_ERR(fmt, ...) LOG_ERR(fmt, ## __VA_ARGS__)
#define SBK_LOG_INF(fmt, ...) LOG_INF(fmt, ## __VA_ARGS__)
#define SBK_LOG_WRN(fmt, ...) LOG_WRN(fmt, ## __VA_ARGS__)
#define SBK_LOG_DBG(fmt, ...) LOG_DBG(fmt, ## __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_OS_CONFIG_H_*/
