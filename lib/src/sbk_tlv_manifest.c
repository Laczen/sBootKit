#include "sbk/sbk_tlv_manifest.h"

int sbk_tlv_manifest_open(struct sbk_os_slot *manifest)
{
        return 0;
}

int sbk_tlv_manifest_close(struct sbk_os_slot *manifest)
{
        return sbk_os_slot_close(manifest);
}

int sbk_tlv_manifest_switch(struct sbk_os_slot *manifest)
{
        return 0;
}

int sbk_tlv_manifest_clear(struct sbk_os_slot *manifest)
{
        return 0;
}

bool sbk_tlv_manifest_valid(const struct sbk_os_slot *manifest)
{
        return true;
}

bool sbk_tlv_manifest_run_digest_valid(const struct sbk_os_slot *manifest)
{
        return true;
}

bool sbk_tlv_manifest_prep_digest_valid(const struct sbk_os_slot *manifest)
{
        return true;
}

bool sbk_tlv_manifest_is_test(const struct sbk_os_slot *manifest)
{
        return false;
}
