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

/* CXL r3.1 Section 8.2.9.1.1: Identify (Opcode 0001h) */
struct cxlmi_cci_infostat_identify {
	uint16_t vendor_id;
	uint16_t device_id;
	uint16_t subsys_vendor_id;
	uint16_t subsys_id;
	uint8_t serial_num[8];
	uint8_t max_msg;
	uint8_t component_type;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.1.2: Background Operation Status (Opcode 0002h) */
struct cxlmi_cci_bg_operation_status {
	uint8_t status;
	uint8_t rsvd;
	uint16_t opcode;
	uint16_t returncode;
	uint16_t vendor_ext_status;
}__attribute__((packed));

/* CXL r3.1 Section 8.2.9.1.3: Get Response Message Limit (Opcode 0003h) */
struct cxlmi_cci_get_response_msg_limit {
	uint8_t limit;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.1.4: Set Response Message Limit (Opcode 0004h) */
struct cxlmi_cci_set_response_msg_limit {
	uint8_t limit;
} __attribute__((packed));

/* CXL r3.0 Section 8.2.9.4.1: Get Timestamp (Opcode 0300h) */
struct cxlmi_cci_get_timestamp {
	uint64_t timestamp;
} __attribute__((packed));

#endif
