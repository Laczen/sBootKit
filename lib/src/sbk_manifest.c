#include "sbk/sbk_manifest.h"

#ifdef CONFIG_SBK_TLV_MANIFEST

//#include "sbk/sbk_tlv_manifest.h"

uint64_t sbk_manifest_epoch(struct sbk_os_slot *slot)
{
        return 0U;
}

uint32_t sbk_manifest_slot(struct sbk_os_slot *slot)
{
        return 0U;
}

bool sbk_manifest_valid(const struct sbk_os_slot *slot)
{
        return true;
}

bool sbk_manifest_run_digest_valid(const struct sbk_os_slot *slot)
{
        return true;
}

bool sbk_manifest_upl_digest_valid(const struct sbk_os_slot *slot)
{
        return true;
}

bool sbk_manifest_is_test(const struct sbk_os_slot *slot)
{
        return true;
}

#endif