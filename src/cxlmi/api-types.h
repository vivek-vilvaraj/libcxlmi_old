#ifndef _LIBCXLMI_TYPES_H
#define _LIBCXLMI_TYPES_H

#include <stdint.h>
#include <stdbool.h>

#include <linux/types.h>

/*  CXL r3.1 Section 7.6.7.1.1: Identify Switch Device (Opcode 5100h) */
struct cxlmi_cci_identify_switch {
	uint8_t ingress_port_id;
        uint8_t rsvd;
        uint8_t num_physical_ports;
        uint8_t num_vcss;
        uint8_t active_port_bitmask[0x20];
        uint8_t active_vcs_bitmask[0x20];
        uint16_t total_vppbs;
        uint16_t bound_vppbs;
        uint8_t num_hdm_decoders_per_usp;
}__attribute__((packed)); 

/* CXL r3.1 Section 8.2.9.1.1: Identify (Opcode 0001h) */
struct cxlmi_cci_infostat_identify {
	uint16_t vendor_id;
	uint16_t device_id;
	uint16_t subsys_vendor_id;
	uint16_t subsys_id;
	uint64_t serial_num;
	uint8_t max_msg_size;
	uint8_t component_type;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.1.2: Background Operation Status (Opcode 0002h) */
struct cxlmi_cci_infostat_bg_op_status {
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

/* CXL r3.1 Section 8.2.9.4.1: Get Timestamp (Opcode 0300h) */
struct cxlmi_cci_get_timestamp {
	uint64_t timestamp;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.4.2: Set Timestamp (Opcode 0301h) */
struct cxlmi_cci_set_timestamp {
	uint64_t timestamp;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.5.1: Get Supported Logs (Opcode 0400h) */
struct cxlmi_supported_log_entry {
	uint8_t uuid[0x10];
	uint32_t log_size;
} __attribute__((packed));

struct cxlmi_cci_get_supported_logs {
	uint16_t num_supported_log_entries;
	uint8_t reserved[6];
	struct cxlmi_supported_log_entry entries[];
} __attribute__((packed));

/*  CXL r3.1 Section 8.2.9.5.2: Get Log (Opcode 0401h) */
struct cxlmi_cci_get_log_req {
	uint8_t uuid[0x10];
	uint32_t offset;
	uint32_t length;
} __attribute__((packed));

struct cxlmi_cci_get_log_cel_rsp {
	uint16_t opcode;
	uint16_t commandeffect;
} __attribute__((packed));

/*  CXL r3.1 Section 8.2.9.9.1.1: Identify Memory Device (Opcode 4000h) */
struct cxlmi_cci_identify_memdev {
	char fw_revision[0x10];
	uint64_t total_capacity;
	uint64_t volatile_capacity;
	uint64_t persistent_capacity;
	uint64_t partition_align;
	uint16_t info_event_log_size;
	uint16_t warning_event_log_size;
	uint16_t failure_event_log_size;
	uint16_t fatal_event_log_size;
	uint32_t lsa_size;
	uint8_t poison_list_max_mer[3];
	uint16_t inject_poison_limit;
	uint8_t poison_caps;
	uint8_t qos_telemetry_caps;
	uint16_t dc_event_log_size;
}  __attribute__((packed));

#endif
