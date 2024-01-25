#ifndef ZEPHYR_OS_H_
#define ZEPHYR_OS_H_

#ifdef __cplusplus
extern "C" {
#endif

#if CONFIG_FLASH
#define GET_PARTITION_DEV(label)                                                \
	DEVICE_DT_GET_OR_NULL(DT_MTD_FROM_FIXED_PARTITION(DT_NODELABEL(label)))
#else
#define GET_PARTITION_DEV(label) NULL
#endif
#define GET_PARTITION_SIZE(label)   DT_REG_SIZE(DT_NODELABEL(label))
#define GET_PARTITION_OFFSET(label) DT_REG_ADDR(DT_NODELABEL(label))
#define GET_PARTITION_EBS(label)                                                \
	DT_PROP_OR(DT_GPARENT(DT_NODELABEL(label)), erase_block_size,           \
		   (GET_PARTITION_SIZE(label)))
#define GET_PARTITION_WBS(label)                                                \
	DT_PROP_OR(DT_GPARENT(DT_NODELABEL(label)), write_block_size,           \
		   (GET_PARTITION_EBS(label)))

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_OS_H_*/
