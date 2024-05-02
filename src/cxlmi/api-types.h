#ifndef _LIBCXLMI_TYPES_H
#define _LIBCXLMI_TYPES_H

#include <stdint.h>
#include <stdbool.h>

#include <linux/types.h>

/* CXL r3.1 Figure 7-19: CCI Message Format */
struct cxlmi_cci_msg {
	uint8_t category;
	uint8_t tag;
	uint8_t rsv1;
	uint8_t command;
	uint8_t command_set;
	uint8_t pl_length[3]; /* 20 bit little endian, BO bit at bit 23 */
	uint16_t return_code;
	uint16_t vendor_ext_status;
	uint8_t payload[];
} __attribute__ ((packed));

/* CXL r3.1 Section 8.2.9.1.1: Identify (Opcode 0001h) */
struct cxlmi_cmd_identify {
	uint16_t vendor_id;
	uint16_t device_id;
	uint16_t subsys_vendor_id;
	uint16_t subsys_id;
	uint64_t serial_num;
	uint8_t max_msg_size;
	uint8_t component_type;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.1.2: Background Operation Status (Opcode 0002h) */
struct cxlmi_cmd_bg_op_status {
	uint8_t status;
	uint8_t rsvd;
	uint16_t opcode;
	uint16_t returncode;
	uint16_t vendor_ext_status;
}__attribute__((packed));

/* CXL r3.1 Section 8.2.9.1.3: Get Response Message Limit (Opcode 0003h) */
struct cxlmi_cmd_get_response_msg_limit {
	uint8_t limit;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.1.4: Set Response Message Limit (Opcode 0004h) */
struct cxlmi_cmd_set_response_msg_limit {
	uint8_t limit;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.4.1: Get Timestamp (Opcode 0300h) */
struct cxlmi_cmd_get_timestamp {
	uint64_t timestamp;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.4.2: Set Timestamp (Opcode 0301h) */
struct cxlmi_cmd_set_timestamp {
	uint64_t timestamp;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.5.1: Get Supported Logs (Opcode 0400h) */
struct cxlmi_supported_log_entry {
	uint8_t uuid[0x10];
	uint32_t log_size;
} __attribute__((packed));

struct cxlmi_cmd_get_supported_logs {
	uint16_t num_supported_log_entries;
	uint8_t reserved[6];
	struct cxlmi_supported_log_entry entries[];
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.5.2: Get Log (Opcode 0401h) */
struct cxlmi_cmd_get_log {
	uint8_t uuid[0x10];
	uint32_t offset;
	uint32_t length;
} __attribute__((packed));

struct cxlmi_cmd_get_log_cel_rsp {
	uint16_t opcode;
	uint16_t command_effect;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.5.4: Clear Log (Opcode 0403h) */
struct cxlmi_cmd_clear_log {
	uint8_t uuid[0x10];
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.5.4: Populate Log (Opcode 0404h) */
struct cxlmi_cmd_populate_log {
	uint8_t uuid[0x10];
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.5.5: Get Supported Logs Sub-List (Opcode 0405h) */
struct cxlmi_cmd_get_supported_logs_sublist_in {
	uint8_t max_supported_log_entries;
	uint8_t start_log_entry_index;
} __attribute__((packed));

struct cxlmi_cmd_get_supported_logs_sublist_out {
	uint8_t num_supported_log_entries;
	uint8_t rsvd1;
	uint16_t total_num_supported_log_entries;
	uint8_t start_log_entry_index;
	uint8_t rsvd2[0x3];
	struct cxlmi_supported_log_entry entries[];
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.9.1.1: Identify Memory Device (Opcode 4000h) */
struct cxlmi_cmd_memdev_identify {
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
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.9.3.1: Get Health Info (Opcode 4200h) */
struct cxlmi_cmd_memdev_get_health_info {
	uint8_t health_status;
	uint8_t media_status;
	uint8_t additional_status;
	uint8_t life_used;
	uint16_t device_temperature;
	uint32_t dirty_shutdown_count;
	uint32_t corrected_volatile_error_count;
	uint32_t corrected_persistent_error_count;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.9.3.2: Get Alert Config (Opcode 4201h) */
struct cxlmi_cmd_memdev_get_alert_config {
	uint8_t valid_alerts;
	uint8_t programmable_alerts;
	uint8_t life_used_critical_alert_threshold;
	uint8_t life_used_programmable_warning_threshold;
	uint16_t device_over_temperature_critical_alert_threshold;
	uint16_t device_under_temperature_critical_alert_threshold;
	uint16_t device_over_temperature_programmable_warning_threshold;
	uint16_t device_under_temperature_programmable_warning_threshold;
	uint16_t corrected_volatile_mem_error_programmable_warning_threshold;
	uint16_t corrected_persistent_mem_error_programmable_warning_threshold;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.9.3.3: Set Alert Config (Opcode 4202h) */
struct cxlmi_cmd_memdev_set_alert_config {
	uint8_t valid_alert_actions;
	uint8_t enable_alert_actions;
	uint8_t life_used_programmable_warning_threshold;
	uint8_t rsvd1;
	uint16_t device_over_temperature_programmable_warning_threshold;
	uint16_t device_under_temperature_programmable_warning_threshold;
	uint16_t corrected_volatile_mem_error_programmable_warning_threshold;
	uint16_t corrected_persistent_mem_error_programmable_warning_threshold;
} __attribute__((packed));

/* CXL r3.1 Section 7.6.7.1.1: Identify Switch Device (Opcode 5100h) */
struct cxlmi_cmd_fmapi_identify_switch_device {
	uint8_t ingres_port_id;
	uint8_t rsv1;
	uint8_t num_physical_ports;
	uint8_t num_vcs;
	uint8_t active_port_bitmask[32];
	uint8_t active_vcs_bitmask[32];
	uint16_t num_total_vppb;
	uint16_t num_active_vppb;
	uint8_t num_hdm_decoder_per_usp;
} __attribute__((packed));

/* CXL r3.1 Section 7.6.7.3.2: Tunnel Management Command (Opcode 5300h) */
struct cxl_fmapi_tunnel_command_req {
	uint8_t id; /* Port or LD ID as appropriate */
	uint8_t target_type;
#define TUNNEL_TARGET_TYPE_PORT_OR_LD  0
#define TUNNEL_TARGET_TYPE_LD_POOL_CCI 1
	uint16_t command_size;
	struct cxlmi_cci_msg message[];
} __attribute__((packed));

struct cxl_fmapi_tunnel_command_rsp {
	uint16_t length;
	uint16_t resv;
	struct cxlmi_cci_msg message[]; /* only one but lets closs over that */
} __attribute__((packed));

#endif
