/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sbk/sbk_tlv.h"
#include "sbk/sbk_slot.h"
#include "sbk/sbk_util.h"
#include "sbk/sbk_log.h"

int sbk_tlv_get_erhdr(const struct sbk_slot *slot, uint16_t tag,
		      struct sbk_tlv_erhdr *erhdr)
{
	const size_t rdsz = sizeof(struct sbk_tlv_rhdr);

	while (true) {
		erhdr->pos += erhdr->rhdr.len;
		if (sbk_slot_read(slot, erhdr->pos, &erhdr->rhdr, rdsz) != 0) {
			break;
		}

		if (erhdr->rhdr.len < rdsz) { /* stop at invalid entries */
			break;
		}

		if (erhdr->rhdr.tag == tag) {
			break;
		}
	}

	return (erhdr->rhdr.tag == tag) ? 0 : -SBK_EC_ENOENT;
}

int sbk_tlv_get_data(const struct sbk_slot *slot, uint16_t tag, void *data,
		     size_t size)
{
	struct sbk_tlv_erhdr erhdr = {
		.pos = 0U,
		.rhdr.len = 0U,
	};
	size_t rdsize;
	int rc;

	rc = sbk_tlv_get_erhdr(slot, tag, &erhdr);
	if (rc != 0) {
		goto end;
	}

	rdsize = SBK_MIN(size, erhdr.rhdr.len);
	rc = sbk_slot_read(slot, erhdr.pos, data, rdsize);
end:
	return rc;
}

static uint32_t sbk_version_u32(const struct sbk_version *ver)
{
	return (uint32_t)((ver->major << 24) + (ver->minor << 16) +
			  ver->revision);
}

bool sbk_version_in_range(const struct sbk_version *ver,
			  const struct sbk_version_range *range)
{
	const struct sbk_version min = range->min_version;
	const struct sbk_version max = range->max_version;

	if (sbk_version_u32(ver) < sbk_version_u32(&min)) {
		return false;
	}

	if (sbk_version_u32(ver) > sbk_version_u32(&max)) {
		return false;
	}

	return true;
}

int sbk_tlv_get_product_data(struct sbk_tlv_product_data *data)
{
	struct sbk_slot slot;
	int rc;

	rc = sbk_open_productdata_slot(&slot);
	if (rc != 0) {
		goto end;
	}

	rc = sbk_tlv_get_data(&slot, SBK_PRODUCT_DATA_TAG, data,
			      sizeof(struct sbk_tlv_product_data));
	(void)sbk_slot_close(&slot);
end:
	return rc;
}

int sbk_tlv_get_product_name(char *name, size_t size)
{
	struct sbk_slot slot;
	struct sbk_tlv_erhdr erhdr = {
		.pos = 0U,
		.rhdr.len = 0U,
	};
	int rc;

	rc = sbk_open_productdata_slot(&slot);
	if (rc != 0) {
		goto end;
	}

	rc = sbk_tlv_get_erhdr(&slot, SBK_PRODUCT_NAME_TAG, &erhdr);
	if (rc != 0) {
		goto end;
	}

	erhdr.rhdr.len -= sizeof(struct sbk_tlv_rhdr);
	erhdr.pos += sizeof(struct sbk_tlv_rhdr);
	rc = sbk_slot_read(&slot, erhdr.pos, name, SBK_MIN(size, erhdr.rhdr.len));
	(void)sbk_slot_close(&slot);

end:
	return rc;	
}

int sbk_tlv_get_bootinfo(struct sbk_tlv_bootinfo *data)
{
	struct sbk_slot slot;
	int rc;

	rc = sbk_open_shareddata_slot(&slot);
	if (rc != 0) {
		goto end;
	}

	rc = sbk_tlv_get_data(&slot, SBK_BOOTINFO_TAG, data,
			      sizeof(struct sbk_tlv_bootinfo));
	(void)sbk_slot_close(&slot);

	SBK_LOG_DBG("get_bootinfo [%d]", rc);
end:
	return rc;

}

int sbk_tlv_set_bootinfo(struct sbk_tlv_bootinfo *data)
{
	struct sbk_slot slot;
	int rc;

	rc = sbk_open_shareddata_slot(&slot);
	if (rc != 0) {
		goto end;
	}

	data->rhdr.tag = SBK_BOOTINFO_TAG;
	data->rhdr.len = sizeof(struct sbk_tlv_bootinfo);

	rc = sbk_slot_prog(&slot, 0, data, sizeof(struct sbk_tlv_bootinfo));
	(void)sbk_slot_close(&slot);

end:
	return rc;

}