The following are the supported CXL commands belonging to the FM-API
command set, as per the latest specification.

<!--ts-->
* [Physical Switch (51h)](#physical-switch-51h)
   * [Identify Switch Device (5100h)](#identify-switch-device-5100h)
   * [Get Physical Port State (5101h)](#get-physical-port-state-5101h)

<!-- Created by https://github.com/ekalinin/github-markdown-toc -->
<!-- Added by: dave, at: Mon May 20 12:47:25 PM PDT 2024 -->

<!--te-->

# Physical Switch (51h)

## Identify Switch Device (5100h)

Output payload:

   ```C
struct cxlmi_cmd_fmapi_identify_sw_device {
	uint8_t ingres_port_id;
	uint8_t rsv1;
	uint8_t num_physical_ports;
	uint8_t num_vcs;
	uint8_t active_port_bitmask[32];
	uint8_t active_vcs_bitmask[32];
	uint16_t num_total_vppb;
	uint16_t num_active_vppb;
	uint8_t num_hdm_decoder_per_usp;
};
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_identify_sw_device(struct cxlmi_endpoint *ep,
		       struct cxlmi_tunnel_info *ti,
		       struct cxlmi_cmd_fmapi_identify_sw_device *ret);
   ```

## Get Physical Port State (5101h)

Input payload:

   ```C
struct cxlmi_cmd_fmapi_get_phys_port_state_req {
	uint8_t num_ports;
	uint8_t ports[];
} __attribute__((packed));
   ```

Output payload:

   ```C
struct cxlmi_cmd_fmapi_port_state_info_block {
	uint8_t port_id;
	uint8_t config_state;
	uint8_t conn_dev_cxl_ver;
	uint8_t rsv1;
	uint8_t conn_dev_type;
	uint8_t port_cxl_ver_bitmask;
	uint8_t max_link_width;
	uint8_t negotiated_link_width;
	uint8_t supported_link_speeds_vector;
	uint8_t max_link_speed;
	uint8_t current_link_speed;
	uint8_t ltssm_state;
	uint8_t first_lane_num;
	uint16_t link_state;
	uint8_t supported_ld_count;
};

struct cxlmi_cmd_fmapi_get_phys_port_state_rsp {
	uint8_t num_ports;
	uint8_t rsv1[3];
	struct cxlmi_cmd_fmapi_port_state_info_block ports[];
};
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_get_phys_port_state(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_get_phys_port_state_req *in,
			struct cxlmi_cmd_fmapi_get_phys_port_state_rsp *ret);   
   ```   
