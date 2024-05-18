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
* [Firmware Update (02h)](#firmware-update-02h)
* [Timestamp (03h)](#timestamp-03h)
   * [Get Timestamp (Opcode 0300h)](#get-timestamp-opcode-0300h)
   * [Set Timestamp (Opcode 0301h)](#set-timestamp-opcode-0301h)
* [Logs (04h)](#logs-04h)

<!-- Created by https://github.com/ekalinin/github-markdown-toc -->
<!-- Added by: dave, at: Sat May 18 11:57:48 AM PDT 2024 -->

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

# Firmware Update (02h)

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
