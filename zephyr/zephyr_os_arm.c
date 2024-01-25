#include <soc.h>
#include <zephyr/irq.h>
#include <cmsis_core.h>
#include <zephyr/drivers/timer/system_timer.h>
#include <zephyr/sys/reboot.h>

#if defined(CONFIG_SW_VECTOR_RELAY)
extern void *_vector_table_pointer;
#endif

struct arm_vector_table {
	uint32_t msp;
	uint32_t reset;
};

void sbk_jump_image(unsigned long address)
{
	struct arm_vector_table {
		uint32_t msp;
		uint32_t reset;
	} * vt;

	vt = (struct arm_vector_table *)(address);

	if (IS_ENABLED(CONFIG_SYSTEM_TIMER_HAS_DISABLE_SUPPORT)) {
		sys_clock_disable();
	}

	/* Allow any pending interrupts to be recognized */
	__ISB();
	__disable_irq();

	/* Disable NVIC interrupts */
	for (uint8_t i = 0; i < ARRAY_SIZE(NVIC->ICER); i++) {
		NVIC->ICER[i] = 0xFFFFFFFF;
	}
	/* Clear pending NVIC interrupts */
	for (uint8_t i = 0; i < ARRAY_SIZE(NVIC->ICPR); i++) {
		NVIC->ICPR[i] = 0xFFFFFFFF;
	}

#ifdef CONFIG_CPU_CORTEX_M_HAS_CACHE
	SCB_DisableDCache();
	SCB_DisableICache();
#endif

#if CONFIG_CPU_HAS_ARM_MPU
	int num_regions =
		((MPU->TYPE & MPU_TYPE_DREGION_Msk) >> MPU_TYPE_DREGION_Pos);

	for (int i = 0; i < num_regions; i++) {
		ARM_MPU_ClrRegion(i);
	}
#endif

#if defined(CONFIG_BUILTIN_STACK_GUARD) && defined(CONFIG_CPU_CORTEX_M_HAS_SPLIM)
	/* Reset limit registers */
	__set_PSPLIM(0);
	__set_MSPLIM(0);
#endif

#ifdef CONFIG_BOOT_INTR_VEC_RELOC
#if defined(CONFIG_SW_VECTOR_RELAY)
	_vector_table_pointer = vt;
#ifdef CONFIG_CPU_CORTEX_M_HAS_VTOR
	SCB->VTOR = (uint32_t)__vector_relay_table;
#endif
#elif defined(CONFIG_CPU_CORTEX_M_HAS_VTOR)
	SCB->VTOR = (uint32_t)vt;
#endif /* CONFIG_SW_VECTOR_RELAY */
#else  /* CONFIG_BOOT_INTR_VEC_RELOC */
#if defined(CONFIG_CPU_CORTEX_M_HAS_VTOR) && defined(CONFIG_SW_VECTOR_RELAY)
	_vector_table_pointer = _vector_start;
	SCB->VTOR = (uint32_t)__vector_relay_table;
#endif
#endif /* CONFIG_BOOT_INTR_VEC_RELOC */

	__set_MSP(vt->msp);
	__set_CONTROL(0x00); /* application will configures core on its own */
	__ISB();
	((void (*)(void))vt->reset)();
}

void sbk_reboot(void)
{
	sys_reboot(0);
}

void sbk_boot_prep(unsigned long address)
{
	/* This can be used for setup before calling sbk_jump_image */
}