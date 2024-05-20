The following are the supported CXL commands belonging to the Generic Component
command set, as per the latest specification.

<!--ts-->
* [Information and Status (00h)](#information-and-status-00h)
   * [Identify (0001h)](#identify-0001h)
   * [Background Operation Status (0002h)](#background-operation-status-0002h)
   * [Get Response Message Limit (0003h)](#get-response-message-limit-0003h)
   * [Set Response Message Limit (0004h)](#set-response-message-limit-0004h)
   * [Request Abort Background Operation (0005h)](#request-abort-background-operation-0005h)
* [Events (01h)](#events-01h)
   * [Clear Event Records (0101h)](#clear-event-records-0101h)
   * [Get Event Interrupt Policy (0102h)](#get-event-interrupt-policy-0102h)
   * [Set Event Interrupt Policy (0103h)](#set-event-interrupt-policy-0103h)
   * [Get MCTP Event Interrupt Policy (0105h)](#get-mctp-event-interrupt-policy-0105h)
   * [Set MCTP Event Interrupt Policy (0105h)](#set-mctp-event-interrupt-policy-0105h)
   * [Event Notification (0106h)](#event-notification-0106h)
* [Firmware Update (02h)](#firmware-update-02h)
   * [Get FW Info (0200h)](#get-fw-info-0200h)
   * [Transfer FW (0201h)](#transfer-fw-0201h)
   * [Activate FW (0202h)](#activate-fw-0202h)
* [Timestamp (03h)](#timestamp-03h)
   * [Get Timestamp (Opcode 0300h)](#get-timestamp-opcode-0300h)
   * [Set Timestamp (Opcode 0301h)](#set-timestamp-opcode-0301h)
* [Logs (04h)](#logs-04h)
   * [Get Supported Logs (0400h)](#get-supported-logs-0400h)
   * [Clear Log (0403h)](#clear-log-0403h)
   * [Populate Log (0404h)](#populate-log-0404h)
   * [Get Supported Logs Sub-List (0405h)](#get-supported-logs-sub-list-0405h)

<!-- Created by https://github.com/ekalinin/github-markdown-toc -->
<!-- Added by: dave, at: Sun May 19 07:45:06 PM PDT 2024 -->

<!--te-->

# Information and Status (00h)

## Identify (0001h)

Output payload:

   ```C
struct cxlmi_cmd_identify {
	uint16_t vendor_id;
	uint16_t device_id;
	uint16_t subsys_vendor_id;
	uint16_t subsys_id;
	uint64_t serial_num;
	uint8_t max_msg_size;
	uint8_t component_type;
};
   ```

Command name:

   ```C
int cxlmi_cmd_identify(struct cxlmi_endpoint *ep, struct cxlmi_tunnel_info *ti, struct cxlmi_cmd_identify *ret)
   ```

## Background Operation Status (0002h)

Output payload:

   ```C
struct cxlmi_cmd_bg_op_status {
	uint8_t status;
	uint8_t rsvd;
	uint16_t opcode;
	uint16_t returncode;
	uint16_t vendor_ext_status;
};
   ```
Command name:

   ```C
int cxlmi_cmd_bg_op_status(struct cxlmi_endpoint *ep, struct cxlmi_tunnel_info *ti, struct cxlmi_cmd_bg_op_status *ret);
   ```

## Get Response Message Limit (0003h)

Output payload:

   ```C
struct cxlmi_cmd_get_response_msg_limit {
	uint8_t limit;
};
   ```
Command name:

   ```C
int cxlmi_cmd_get_response_msg_limit(struct cxlmi_endpoint *ep,
			     struct cxlmi_tunnel_info *ti,
			     struct cxlmi_cmd_get_response_msg_limit *ret);
   ```

## Set Response Message Limit (0004h)

Input payload:

   ```C
struct cxlmi_cmd_set_response_msg_limit {
	uint8_t limit;
};
   ```

Command name:

   ```C
int cxlmi_cmd_set_response_msg_limit(struct cxlmi_endpoint *ep,
				     struct cxlmi_tunnel_info *ti,
				     struct cxlmi_cmd_set_response_msg_limit *in);
   ```

## Request Abort Background Operation (0005h)

No payload.

Command Name

   ```C
int cxlmi_cmd_request_bg_op_abort(struct cxlmi_endpoint *ep, struct cxlmi_tunnel_info *ti);
   ```

# Events (01h)

## Clear Event Records (0101h)

Input payload:


   ```C
struct cxlmi_cmd_clear_event_records {
	uint8_t event_log;
	uint8_t clear_flags;
	uint8_t nr_recs;
	uint8_t reserved[3];
	uint16_t handles[];
};
   ```

Command name:

   ```C
int cxlmi_cmd_clear_event_records(struct cxlmi_endpoint *ep,
				  struct cxlmi_tunnel_info *ti,
				  struct cxlmi_cmd_clear_event_records *in);
   ```

## Get Event Interrupt Policy (0102h)

Output payload:

   ```C
struct cxlmi_cmd_get_event_interrupt_policy {
	uint8_t informational_settings;
	uint8_t warning_settings;
	uint8_t failure_settings;
	uint8_t fatal_settings;
	uint8_t dcd_settings;
};
   ```

Command name:

   ```C
int cxlmi_cmd_get_event_interrupt_policy(struct cxlmi_endpoint *ep,
				 struct cxlmi_tunnel_info *ti,
				 struct cxlmi_cmd_get_event_interrupt_policy *ret);
   ```

## Set Event Interrupt Policy (0103h)

Input payload:

   ```C
struct cxlmi_cmd_set_event_interrupt_policy {
	uint8_t informational_settings;
	uint8_t warning_settings;
	uint8_t failure_settings;
	uint8_t fatal_settings;
	uint8_t dcd_settings;
};
   ```

Command name:

   ```C
int cxlmi_cmd_set_event_interrupt_policy(struct cxlmi_endpoint *ep,
				 struct cxlmi_tunnel_info *ti,
				 struct cxlmi_cmd_set_event_interrupt_policy *in);
   ```

## Get MCTP Event Interrupt Policy (0104h)

## Set MCTP Event Interrupt Policy (0105h)

## Event Notification (0106h)

# Firmware Update (02h)

## Get FW Info (0200h)

Output payload:

   ```C

struct cxlmi_cmd_get_fw_info {
	uint8_t slots_supported;
	uint8_t slot_info;
	uint8_t caps;
	uint8_t rsvd[0xd];
	char fw_rev1[0x10];
	char fw_rev2[0x10];
	char fw_rev3[0x10];
	char fw_rev4[0x10];
};
   ```

Command Name:

   ```C
int cxlmi_cmd_request_bg_op_abort(struct cxlmi_endpoint *ep, struct cxlmi_tunnel_info *ti);
   ```

## Transfer FW (0201h)

Input payload:

   ```C
struct cxlmi_cmd_transfer_fw {
	uint8_t action;
	uint8_t slot;
	uint8_t rsvd1[2];
	uint32_t offset;
	uint8_t rsvd2[0x78];
	uint8_t data[];
};
   ```

Command name:

   ```C
int cxlmi_cmd_transfer_fw(struct cxlmi_endpoint *ep,
			  struct cxlmi_tunnel_info *ti,
			  struct cxlmi_cmd_transfer_fw *in);
   ```

## Activate FW (0202h)

Input payload:

   ```C
struct cxlmi_cmd_activate_fw {
	uint8_t action;
	uint8_t slot;
};
   ```

Command name:

   ```C
int cxlmi_cmd_activate_fw(struct cxlmi_endpoint *ep,
			  struct cxlmi_tunnel_info *ti,
			  struct cxlmi_cmd_activate_fw *in);
   ```

# Timestamp (03h)

## Get Timestamp (Opcode 0300h)

Output payload:
   ```C
struct cxlmi_cmd_set_timestamp {
	uint64_t timestamp;
};
   ```

Command name:

   ```C
int cxlmi_cmd_get_timestamp(struct cxlmi_endpoint *ep,
			    struct cxlmi_tunnel_info *ti,
			    struct cxlmi_cmd_get_timestamp *ret);
   ```

## Set Timestamp (Opcode 0301h)

Input payload:

   ```C
struct cxlmi_cmd_set_timestamp {
	uint64_t timestamp;
};
   ```

Command name:

   ```C
int cxlmi_cmd_set_timestamp(struct cxlmi_endpoint *ep,
			    struct cxlmi_tunnel_info *ti,
			    struct cxlmi_cmd_set_timestamp *in);
   ```

# Logs (04h)

## Get Supported Logs (0400h)

Output payload:

  ```C
struct cxlmi_supported_log_entry {
	uint8_t uuid[0x10];
	uint32_t log_size;
};

struct cxlmi_cmd_get_supported_logs {
	uint16_t num_supported_log_entries;
	uint8_t reserved[6];
	struct cxlmi_supported_log_entry entries[];
};
  ```

Command name:

   ```C
int cxlmi_cmd_get_supported_logs(struct cxlmi_endpoint *ep,
				 struct cxlmi_tunnel_info *ti,
				 struct cxlmi_cmd_get_supported_logs *ret);
   ```

## Clear Log (0403h)

Input payload:

   ```C
struct cxlmi_cmd_clear_log {
	uint8_t uuid[0x10];
};
   ```

Command name:

   ```C
int cxlmi_cmd_clear_log(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_clear_log *in);
   ```

## Populate Log (0404h)

Input payload:

   ```C
struct cxlmi_cmd_populate_log {
	uint8_t uuid[0x10];
};
   ```

Command name:

   ```C
int cxlmi_cmd_populate_log(struct cxlmi_endpoint *ep,
			   struct cxlmi_tunnel_info *ti,
			   struct cxlmi_cmd_populate_log *in);
   ```

## Get Supported Logs Sub-List (0405h)

Input payload:

   ```C
struct cxlmi_cmd_get_supported_logs_sublist_req {
	uint8_t max_supported_log_entries;
	uint8_t start_log_entry_index;
};
   ```

Oyutput payload

   ```C
struct cxlmi_cmd_get_supported_logs_sublist_req {
	uint8_t max_supported_log_entries;
	uint8_t start_log_entry_index;
};
   ```

Command name:

   ```C
int cxlmi_cmd_get_supported_logs_sublist(struct cxlmi_endpoint *ep,
			  struct cxlmi_tunnel_info *ti,
			  struct cxlmi_cmd_get_supported_logs_sublist_req *in,
			  struct cxlmi_cmd_get_supported_logs_sublist_rsp *ret);
   ```