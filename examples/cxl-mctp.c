// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libcxlmi.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <libcxlmi.h>

static int show_memdev_info(struct cxlmi_endpoint *ep)
{
	int rc;
	struct cxlmi_cmd_memdev_identify id;

	rc = cxlmi_cmd_memdev_identify(ep, NULL, &id);
	if (rc)
		return rc;

	printf("FW revision: %s\n", id.fw_revision);
	printf("total capacity: %ld Mb\n", 256 * id.total_capacity);
	printf("\tvolatile: %ld Mb\n", 256 * id.volatile_capacity);
	printf("\tpersistent: %ld Mb\n", 256 * id.persistent_capacity);
	printf("lsa size: %d bytes\n", id.lsa_size);
	printf("poison injection limit: %d\n", id.inject_poison_limit);
	printf("poison caps 0x%x\n", id.poison_caps);
	printf("DC event log size %d\n", id.dc_event_log_size);

       return 0;
}

static int show_switch_info(struct cxlmi_endpoint *ep)
{
	int rc, i, num_ports;
	int *ds_dev_types;
	uint8_t *b;
	struct cxlmi_cmd_fmapi_identify_sw_device sw_id;
	struct cxlmi_cmd_fmapi_get_phys_port_state_req *in;
	struct cxlmi_cmd_fmapi_get_phys_port_state_rsp *ret;

	rc = cxlmi_cmd_fmapi_identify_sw_device(ep, NULL, &sw_id);
	if (rc)
		return rc;

	printf("Num tot vppb %d, Num Bound vPPB %d, Num HDM dec per USP %d\n",
	       sw_id.num_total_vppb, sw_id.num_active_vppb,
	       sw_id.num_hdm_decoder_per_usp);
	printf("\tPorts %d\n", sw_id.num_physical_ports);

	b = sw_id.active_port_bitmask;
	printf("\tActivePortMask ");
	for (int i = 0; i < 32; i++)
		printf("%02x", b[i]);
	printf("\n");

	num_ports = sw_id.num_physical_ports;

	ds_dev_types = malloc(sizeof(*ds_dev_types) * num_ports);
	if (!ds_dev_types)
		return -1;

	/* port_list = malloc(sizeof(*port_list) * num_ports); */
	/* if (!port_list) */
	/* 	return -1; */
	/* for (i = 0; i < num_ports; i++) { */
	/* 	/\* Done like this to allow easy testing of nonsequential lists *\/ */
	/* 	port_list[i] = i; */
	/* } */
	
	in = calloc(1, sizeof(*in) + num_ports);
	if (!in)
		return -1;

	in->num_ports = num_ports;
	for (i = 0; i < num_ports; i++) {
		/* allow easy testing of nonsequential lists */
		in->ports[i] = i;
	}

	ret = calloc(1, sizeof(*ret) + num_ports);
	if (!ret)
	
	rc = cxlmi_cmd_fmapi_get_phys_port_state(ep, NULL, in, ret);
	if (rc)
		return rc;

	for (i = 0; i < num_ports; i++) {
		struct cxlmi_cmd_fmapi_port_state_info_block *port = &ret->ports[i];
		const char *port_states[] = {
			[0x0] = "Disabled",
			[0x1] = "Bind in progress",
			[0x2] = "Unbind in progress",
			[0x3] = "DSP",
			[0x4] = "USP",
			[0x5] = "Reserved",
			//other values not present.
			[0xf] = "Invalid Port ID"
		};
		const char *conn_dev_modes[] = {
			[0] = "Not CXL / connected",
			[1] = "CXL 1.1",
			[2] = "CXL 2.0",
		};
		const char *conn_dev_type[] = {
			[0] = "No device detected",
			[1] = "PCIe device",
			[2] = "CXL type 1 device",
			[3] = "CXL type 2 device",
			[4] = "CXL type 3 device",
			[5] = "CXL type 3 pooled device",
			[6] = "Reserved",
		};
		const char *ltssm_states[] = {
			[0] = "Detect",
			[1] = "Polling",
			[2] = "Configuration",
			[3] = "Recovery",
			[4] = "L0",
			[5] = "L0s",
			[6] = "L1",
			[7] = "L2",
			[8] = "Disabled",
			[9] = "Loop Back",
			[10] = "Hot Reset",
		};

		if (port->port_id != in->ports[i]) {
			printf("port id wrong %d %d\n",
			       port->port_id, in->ports[i]);
			return -1;
		}
		printf("Port%02d:\n ", port->port_id);
		printf("\tPort state: ");
		if (port_states[port->config_state & 0xf])
			printf("%s\n", port_states[port->config_state]);
		else
			printf("Unknown state\n");

		/* DSP so device could be there */
		if (port->config_state == 3) {
			printf("\tConnected Device CXL Version: ");
			if (port->conn_dev_cxl_ver > 2)
				printf("Unknown CXL Version\n");
			else
				printf("%s\n",
				       conn_dev_modes[port->conn_dev_cxl_ver]);
			
			printf("\tConnected Device Type: ");
			ds_dev_types[i] = port->conn_dev_type;
			if (port->conn_dev_type > 7)
				printf("Unknown\n");
			else
				printf("%s\n",
				       conn_dev_type[port->conn_dev_type]);
		}

		printf("\tSupported CXL Modes:");
		if (port->port_cxl_ver_bitmask & 0x1)
			printf(" 1.1");
		if (port->port_cxl_ver_bitmask & 0x2)
			printf(" 2.0");
		printf("\n");

		printf("\tMaximum Link Width: %d Negotiated Width %d\n",
			   port->max_link_width,
			   port->negotiated_link_width);
		printf("\tSupported Speeds: ");
		if (port->supported_link_speeds_vector & 0x1)
			printf(" 2.5 GT/s");
		if (port->supported_link_speeds_vector & 0x2)
			printf(" 5.0 GT/s");
		if (port->supported_link_speeds_vector & 0x4)
			printf(" 8.0 GT/s");
		if (port->supported_link_speeds_vector & 0x8)
			printf(" 16.0 GT/s");
		if (port->supported_link_speeds_vector & 0x10)
			printf(" 32.0 GT/s");
		if (port->supported_link_speeds_vector & 0x20)
			printf(" 64.0 GT/s");
		printf("\n");

		printf("\tLTSSM: ");
		if (port->ltssm_state >= sizeof(ltssm_states))
			printf("Unkown\n");
		else
			printf("%s\n", ltssm_states[port->ltssm_state]);
	}

	for (i = 0; i < num_ports; i++) {
		switch (ds_dev_types[i]) {
		case 5: /* MLD */ {
			/* size_t cel_size = 0; */
			struct cxlmi_cmd_identify id;
			struct cxlmi_tunnel_info ti = {
				.level = 1,
				.port = i,
				.id = 0,
			};
			
			printf("Query the FM-Owned LD.....\n");
			rc = cxlmi_cmd_identify(ep, &ti, &id);
			/* if (rc) */
			/* 	goto err_free_ds_dev_types; */

			/* rc = get_supported_logs(fmapi_sd, &fmapi_addr, &tag, */
			/* 			&cel_size, tunnel1, i, 0); */
			/* if (rc) */
			/* 	goto err_free_ds_dev_types; */

			/* rc = get_cel(fmapi_sd, &fmapi_addr, &tag, */
			/* 	     cel_size, tunnel1, i, 0); */
			/* if (rc) */
			/* 	goto err_free_ds_dev_types; */
			/* printf("Query LD%d.......\n", 0); */

			/* rc = query_cci_identify(fmapi_sd, &fmapi_addr, &tag, */
			/* 			&target_type, */
			/* 			tunnel2, i, 0); */
			/* if (rc) */
			/* 	goto err_free_ds_dev_types; */
			/* rc = get_supported_logs(fmapi_sd, &fmapi_addr, &tag, */
			/* 			&cel_size, tunnel2, i, 0); */
			/* if (rc) */
			/* 	goto err_free_ds_dev_types; */

			/* rc = get_cel(fmapi_sd, &fmapi_addr, &tag, */
			/* 	     cel_size, tunnel2, i, 0); */
			/* if (rc) */
			/* 	goto err_free_ds_dev_types; */

			break;
		}
		default:
			/* Ignoring other types for now */
			break;
		}
	}


	free(ret);
	free(in);
	
	return rc;
}

static int show_device_info(struct cxlmi_endpoint *ep)
{
	int rc = 0;
	struct cxlmi_cmd_identify id;

	rc = cxlmi_cmd_identify(ep, NULL, &id);
	if (rc)
		return rc;

	printf("serial number: 0x%lx\n", (uint64_t)id.serial_num);

	switch (id.component_type) {
	case 0x00:
		printf("device type: CXL Switch\n");
		printf("VID:%04x DID:%04x\n", id.vendor_id, id.device_id);

		show_switch_info(ep);
		break;
	case 0x03:
		printf("device type: CXL Type3 Device\n");
		printf("VID:%04x DID:%04x SubsysVID:%04x SubsysID:%04x\n",
		       id.vendor_id, id.device_id,
		       id.subsys_vendor_id, id.subsys_id);

		show_memdev_info(ep);
		break;
	case 0x04:
		printf("GFD not supported\n");
		/* fallthrough */
	default:
		break;
	}

	return rc;
}


static int toggle_abort(struct cxlmi_endpoint *ep)
{
	int rc;
	struct cxlmi_cmd_bg_op_status sts;

	rc = cxlmi_cmd_bg_op_status(ep, NULL, &sts);
	if (rc)
		goto done;

	if (!(sts.status & (1 << 0))) {
		printf("no background operation in progress...\n");

		rc = cxlmi_cmd_memdev_sanitize(ep, NULL);
		if (rc && rc != CXLMI_RET_BACKGROUND) {
			printf("could not start sanitize: %s\n",
			       cxlmi_cmd_retcode_tostr(rc));
			goto done;
		} else {
			printf("sanitizing op started\n");
			sleep(1);
		}
	}

	rc = cxlmi_cmd_request_bg_op_abort(ep, NULL);
	if (rc) {
		if (rc > 0)
			printf("request_bg_operation_abort error: %s\n",
			       cxlmi_cmd_retcode_tostr(rc));
	} else
		printf("background operation abort requested\n");
done:
	return rc;
}

static int play_with_device_timestamp(struct cxlmi_endpoint *ep)
{
	int rc;
	uint64_t orig_ts;
	struct cxlmi_cmd_get_timestamp get_ts;
	struct cxlmi_cmd_set_timestamp set_ts = {
		.timestamp = 946684800, /* Jan 1, 2000 */
	};

	rc = cxlmi_cmd_get_timestamp(ep, NULL, &get_ts);
	if (rc)
		return rc;
	printf("device timestamp: %lu\n", get_ts.timestamp);
	orig_ts = get_ts.timestamp;

	rc = cxlmi_cmd_set_timestamp(ep, NULL, &set_ts);
	if (rc)
		return rc;

	memset(&get_ts, 0, sizeof(get_ts));
	rc = cxlmi_cmd_get_timestamp(ep, NULL, &get_ts);
	if (rc)
		return rc;
	printf("new device timestamp: %lu\n", get_ts.timestamp);

	memset(&set_ts, 0, sizeof(set_ts));
	set_ts.timestamp = orig_ts;
	rc = cxlmi_cmd_set_timestamp(ep, NULL, &set_ts);
	if (rc) {
		if (rc > 0)
			printf("set_timestamp error: %s\n",
			       cxlmi_cmd_retcode_tostr(rc));
		return rc;
	}

	memset(&get_ts, 0, sizeof(get_ts));
	rc = cxlmi_cmd_get_timestamp(ep, NULL, &get_ts);
	if (rc)
		return rc;
	printf("reset back to original device timestamp: %lu\n", get_ts.timestamp);

	return 0;
}

static const uint8_t cel_uuid[0x10] = { 0x0d, 0xa9, 0xc0, 0xb5,
					0xbf, 0x41,
					0x4b, 0x78,
					0x8f, 0x79,
					0x96, 0xb1, 0x62, 0x3b, 0x3f, 0x17 };

static const uint8_t ven_dbg[0x10] = { 0x5e, 0x18, 0x19, 0xd9,
				       0x11, 0xa9,
				       0x40, 0x0c,
				       0x81, 0x1f,
				       0xd6, 0x07, 0x19, 0x40, 0x3d, 0x86 };

static const uint8_t c_s_dump[0x10] = { 0xb3, 0xfa, 0xb4, 0xcf,
					0x01, 0xb6,
					0x43, 0x32,
					0x94, 0x3e,
					0x5e, 0x99, 0x62, 0xf2, 0x35, 0x67 };

static const int maxlogs = 10; /* Only 7 in CXL r3.1, but let us leave room */
static int parse_supported_logs(struct cxlmi_cmd_get_supported_logs *pl,
				size_t *cel_size)
{
	int i, j;

	*cel_size = 0;
	printf("Get Supported Logs Response %d\n",
	       pl->num_supported_log_entries);

	for (i = 0; i < pl->num_supported_log_entries; i++) {
		for (j = 0; j < sizeof(pl->entries[i].uuid); j++) {
			if (pl->entries[i].uuid[j] != cel_uuid[j])
				break;
		}
		if (j == 0x10) {
			*cel_size = pl->entries[i].log_size;
			printf("\tCommand Effects Log (CEL) available\n");
		}
		for (j = 0; j < sizeof(pl->entries[i].uuid); j++) {
			if (pl->entries[i].uuid[j] != ven_dbg[j])
				break;
		}
		if (j == 0x10)
			printf("\tVendor Debug Log available\n");
		for (j = 0; j < sizeof(pl->entries[i].uuid); j++) {
			if (pl->entries[i].uuid[j] != c_s_dump[j])
				break;
		}
		if (j == 0x10)
			printf("\tComponent State Dump Log available\n");
	}
	if (cel_size == 0) {
		return -1;
	}
	return 0;
}

static int show_cel(struct cxlmi_endpoint *ep, int cel_size)
{
	struct cxlmi_cmd_get_log in = {
		.offset = 0,
		.length = cel_size,
	};
	struct cxlmi_cmd_get_log_cel_rsp *ret;
	int i, rc;

	ret = calloc(1, sizeof(*ret) + cel_size);
	if (!ret)
		return -1;

	memcpy(in.uuid, cel_uuid, sizeof(in.uuid));
	rc = cxlmi_cmd_get_log_cel(ep, NULL, &in, ret);
	if (rc)
		goto done;

	for (i = 0; i < cel_size / sizeof(*ret); i++) {
		printf("\t[%04x] %s%s%s%s%s%s%s%s\n",
		       ret[i].opcode,
		       ret[i].command_effect & 0x1 ? "ColdReset " : "",
		       ret[i].command_effect & 0x2 ? "ImConf " : "",
		       ret[i].command_effect & 0x4 ? "ImData " : "",
		       ret[i].command_effect & 0x8 ? "ImPol " : "",
		       ret[i].command_effect & 0x10 ? "ImLog " : "",
		       ret[i].command_effect & 0x20 ? "ImSec" : "",
		       ret[i].command_effect & 0x40 ? "BgOp" : "",
		       ret[i].command_effect & 0x80 ? "SecSup" : "");
	}
done:
	free(ret);
	return rc;
}

static int get_device_logs(struct cxlmi_endpoint *ep)
{
	int rc;
	size_t cel_size;
	struct cxlmi_cmd_get_supported_logs *gsl;

	gsl = calloc(1, sizeof(*gsl) + maxlogs * sizeof(*gsl->entries));
	if (!gsl)
		return -1;

	rc = cxlmi_cmd_get_supported_logs(ep, NULL, gsl);
	if (rc)
		return rc;

	rc = parse_supported_logs(gsl, &cel_size);
	if (rc)
		return rc;
	else {
		/* we know there is a CEL */
		rc = show_cel(ep, cel_size);
	}

	free(gsl);
	return rc;
}

int main(int argc, char **argv)
{
	struct cxlmi_ctx *ctx;
	struct cxlmi_endpoint *ep;
	int rc = EXIT_FAILURE;

	ctx = cxlmi_new_ctx(stdout, DEFAULT_LOGLEVEL);
	if (!ctx) {
		fprintf(stderr, "cannot create new context object\n");
		goto exit;
	}

	if (argc == 1) {
		int num_ep = cxlmi_scan_mctp(ctx);

		printf("scanning dbus...\n");

		if (num_ep < 0) {
			fprintf(stderr, "dbus scan error\n");
			goto exit_free_ctx;
		} else if (num_ep == 0) {
			printf("no endpoints found\n");
		} else
			printf("found %d endpoint(s)\n", num_ep);
	} else if (argc == 3) {
		unsigned int nid;
		uint8_t eid;

		nid = atoi(argv[1]);
		eid = atoi(argv[2]);
		printf("ep %d:%d\n", nid, eid);

		ep = cxlmi_open_mctp(ctx, nid, eid);
		if (!ep) {
			fprintf(stderr, "cannot open MCTP endpoint %d:%d\n", nid, eid);
			goto exit_free_ctx;
		}

		if (cxlmi_endpoint_has_fmapi(ep)) {
			printf("FM-API supported\n");
		} else
			printf("FM-API unsupported\n");
	} else {
		fprintf(stderr, "must provide MCTP endpoint nid:eid touple\n");
		goto exit_free_ctx;
	}

	cxlmi_for_each_endpoint(ctx, ep) {
		rc = show_device_info(ep);

		/* rc = play_with_device_timestamp(ep); */

		/* rc = get_device_logs(ep); */

		/* rc = toggle_abort(ep); */

		cxlmi_close(ep);
	}

exit_free_ctx:
	cxlmi_free_ctx(ctx);
exit:
	return rc;
}
