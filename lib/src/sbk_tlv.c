/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sbk/sbk_tlv.h"
#include "sbk/sbk_slot.h"
#include "sbk/sbk_util.h"
#include "sbk/sbk_log.h"

bool sbk_tlv_tag_cb(const struct sbk_slot *slot, uint16_t tag,
		   bool (*cb)(const struct sbk_tlv_info *info, void *cb_arg),
		   void *cb_arg)
{
	struct sbk_tlv_rhdr rhdr;
	const size_t sz = sizeof(rhdr);
	struct sbk_tlv_info info = {
		.slot = slot,
		.pos = 0U,
		.size = 0U,
	};
	bool rv = false;

	while (true) {
		info.pos += info.size;
		if ((sbk_slot_read(info.slot, info.pos, &rhdr, sz) != 0) ||
		    (rhdr.len > SBK_MAX_TLV_SIZE) || (rhdr.len < sz)) {
			break;
		}

		info.size = rhdr.len;
		if (rhdr.tag != tag) {
			continue;
		}

		rv = cb(&info, cb_arg);
		break;
	}

	return rv;
}

bool sbk_tlv_pos_cb(const struct sbk_tlv_info *info, void *cb_arg)
{
	uint32_t *pos = (uint32_t *)cb_arg;

	*pos = info->pos;
	return true;
}

int sbk_tlv_get_pos(const struct sbk_slot *slot, uint16_t tag, uint32_t *pos)
{
	int rc = -SBK_EC_ENOENT;

	if (sbk_tlv_tag_cb(slot, tag, sbk_tlv_pos_cb, (void *)pos)) {
		rc = 0;
	}

	return rc;
}

struct sbk_tlv_data_cb_arg {
	size_t size;
	void *data;
};

bool sbk_tlv_data_cb(const struct sbk_tlv_info *info, void *cb_arg)
{
	struct sbk_tlv_data_cb_arg *arg = (struct sbk_tlv_data_cb_arg *)cb_arg;
	const uint32_t rdpos = info->pos + sizeof(struct sbk_tlv_rhdr);
	
	if (((info->pos + info->size) != (rdpos + arg->size)) ||
	    (sbk_slot_read(info->slot, rdpos, arg->data, arg->size) != 0)) {
		return false;
	}

	return true;
}

int sbk_tlv_get_data(const struct sbk_slot *slot, uint16_t tag, void *data,
		     size_t size)
{
	struct sbk_tlv_data_cb_arg cb_arg = {
		.size = size,
		.data = data,
	};
	int rc = -SBK_EC_ENOENT;

	if (sbk_tlv_tag_cb(slot, tag, sbk_tlv_data_cb, (void *)&cb_arg)) {
		rc = 0;
	};

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
 
int sbk_tlv_get_product_data(struct sbk_product_data *data)
{
	struct sbk_slot slot;
	int rc;

	rc = sbk_open_productdata_slot(&slot);
	if (rc != 0) {
		goto end;
	}

	rc = sbk_tlv_get_data(&slot, SBK_PRODUCT_DATA_TAG, data,
			      sizeof(struct sbk_product_data));
	(void)sbk_slot_close(&slot);
end:
	return rc;
}

int sbk_tlv_get_product_name(char *name, size_t size)
{
	struct sbk_slot slot;
	struct sbk_tlv_data_cb_arg cb_arg = {
		.size = size,
		.data = name,
	};
	int rc;

	rc = sbk_open_productdata_slot(&slot);
	if (rc != 0) {
		goto end;
	}
	
	rc = sbk_tlv_tag_cb(&slot, SBK_PRODUCT_NAME_TAG, sbk_tlv_data_cb, 
			    (void *)&cb_arg);
	(void)sbk_slot_close(&slot);
end:
	return rc;
}

int sbk_tlv_get_bootinfo(struct sbk_bootinfo *data)
{
	struct sbk_slot slot;
	int rc;

	rc = sbk_open_shareddata_slot(&slot);
	if (rc != 0) {
		goto end;
	}

	rc = sbk_tlv_get_data(&slot, SBK_BOOTINFO_TAG, data,
			      sizeof(struct sbk_bootinfo));
	(void)sbk_slot_close(&slot);
end:
	return rc;
}

int sbk_tlv_set_bootinfo(struct sbk_bootinfo *data)
{
	const size_t sz = sizeof(struct sbk_bootinfo);
	struct sbk_slot slot;
	struct sbk_tlv_rhdr rhdr;
	uint8_t bootinfo[sizeof(rhdr) + sz];
	int rc;

	rc = sbk_open_shareddata_slot(&slot);
	if (rc != 0) {
		goto end;
	}
	
	rhdr.tag = SBK_BOOTINFO_TAG;
	rhdr.len = sizeof(rhdr) + sz;
	memcpy(&bootinfo[0], (void *)&rhdr, sizeof(rhdr));
	memcpy(&bootinfo[sizeof(rhdr)], (void *)data, sz); 
	rc = sbk_slot_prog(&slot, 0, bootinfo, sizeof(bootinfo));
	(void)sbk_slot_close(&slot);
end:
	return rc;
}