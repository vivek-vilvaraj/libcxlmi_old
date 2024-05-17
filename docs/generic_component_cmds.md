# Generic Component Commands

## Information and Status (00h)

### Identify (0001h)

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
int cxlmi_cmd_identify(struct cxlmi_endpoint *ep, struct cxlmi_tunnel_info *ti,
		       struct cxlmi_cmd_identify *ret)
   ```

### Background Operation Status (0002h)

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
int cxlmi_cmd_bg_op_status(struct cxlmi_endpoint *ep,
				struct cxlmi_tunnel_info *ti,
				struct cxlmi_cmd_bg_op_status *ret)