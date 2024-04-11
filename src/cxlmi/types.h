#ifndef _LIBCXLMI_TYPES_H
#define _LIBCXLMI_TYPES_H

#include <stdint.h>
#include <stdbool.h>

#include <linux/types.h>

/**
 * DOC: types.h
 *
 * CXL standard definitions
 */

struct cxlmi_cci_infostat_identify {
	uint16_t vendor_id;
	uint16_t device_id;
	uint16_t subsys_vendor_id;
	uint16_t subsys_id;
	uint8_t serial_num[8];
	uint8_t max_msg;
	uint8_t component_type;
} __attribute__((packed));

/* CXL r3.0 Section 8.2.9.4.1: Get Timestamp (Opcode 0300h) */
struct cxlmi_cci_get_timestamp {
	uint64_t timestamp;
} __attribute__((packed));

#endif
