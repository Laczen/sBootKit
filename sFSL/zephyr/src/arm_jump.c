/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <soc.h>
#include <zephyr/irq.h>

#if defined(CONFIG_CPU_AARCH32_CORTEX_A) || defined(CONFIG_CPU_AARCH32_CORTEX_R)
#include <zephyr/arch/arm/aarch32/cortex_a_r/cmsis.h>
#elif defined(CONFIG_CPU_CORTEX_M)
#include <zephyr/arch/arm/aarch32/cortex_m/cmsis.h>
#endif

#if defined(CONFIG_SW_VECTOR_RELAY)
extern void *_vector_table_pointer;
#endif

struct arm_vector_table {
    uint32_t msp;
    uint32_t reset;
};

void jump_image(uint32_t address)
{
        struct arm_vector_table {
                uint32_t msp;
                uint32_t reset;
        } *vt;

        vt = (struct arm_vector_table *)(address);

#ifdef CONFIG_CPU_CORTEX_M_HAS_CACHE
        SCB_DisableDCache();
        SCB_DisableICache();
#endif

#if defined(CONFIG_BUILTIN_STACK_GUARD) && \
    defined(CONFIG_CPU_CORTEX_M_HAS_SPLIM)
    /* Reset limit registers */
        __set_PSPLIM(0);
        __set_MSPLIM(0);
#endif

        irq_lock();

#if defined(CONFIG_SW_VECTOR_RELAY)
        _vector_table_pointer = vt;
#ifdef CONFIG_CPU_CORTEX_M_HAS_VTOR
        _vector_table_pointer = _vector_start;
        SCB->VTOR = (uint32_t)__vector_relay_table;
#endif
#elif defined(CONFIG_CPU_CORTEX_M_HAS_VTOR)
        SCB->VTOR = (uint32_t)vt;
#endif /* CONFIG_SW_VECTOR_RELAY */

        ((void (*)(void))vt->reset)();
}
