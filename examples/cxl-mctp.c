#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <libcxlmi.h>

static int show_some_info_from_all_devices(struct cxlmi_ctx *ctx)
{
	int rc = 0;
	struct cxlmi_endpoint *ep;

	cxlmi_for_each_endpoint(ctx, ep) {
		struct cxlmi_cci_infostat_identify id;

		rc = cxlmi_cmd_infostat_identify(ep, &id);
		if (rc)
			break;
		if (id.component_type == 0x03) {
			printf("device type: CXL Type3 Device\n");
			printf("\tVID:%04x DID:%04x SubsysVID:%04x SubsysID:%04x\n",
			       id.vendor_id, id.device_id,
			       id.subsys_vendor_id, id.subsys_id);
		} else if (id.component_type == 0x00) {
			printf("device type: CXL Switch\n");
			printf("\tVID:%04x DID:%04x\n", id.vendor_id, id.device_id);
		}
		printf("\tserial number: 0x%lx\n", (uint64_t)id.serial_num);
	}

	return rc;
}

static int toggle_abort(struct cxlmi_endpoint *ep)
{
	int rc;

	rc = cxlmi_cmd_request_bg_operation_abort(ep);
	if (rc) {
		if (rc > 0)
			printf("request_bg_operation_abort error: %s\n",
			       cxlmi_retcode_to_str(rc));
	} else
		printf("requested\n");

	return rc;
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
#define min(a, b) \
	({ __typeof__ (a) _a = (a); \
	__typeof__ (b) _b = (b); \
	_a < _b ? _a : _b; })

static int parse_supported_logs(struct cxlmi_cci_get_supported_logs *pl,
				size_t *cel_size)
{
	int i, j;

	*cel_size = 0;
	printf("Get Supported Logs Response %d\n",
	       pl->num_supported_log_entries);

	for (i = 0; i < min(10, pl->num_supported_log_entries); i++) {
		for (j = 0; j < sizeof(pl->entries[i].uuid); j++) {
			if (pl->entries[i].uuid[j] != cel_uuid[j])
				break;
		}
		if (j == 0x10) {
			*cel_size = pl->entries[i].log_size;
			printf("\tCommand Effects Log available\n");
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
		printf("\tNo Command Effects Log - so don't continue\n");
		return -1;
	}
	return 0;
}

static int get_device_logs(struct cxlmi_endpoint *ep)
{
	int rc;
	size_t cel_size;
	struct cxlmi_cci_get_supported_logs ret;

	printf("Supported Logs: Get Request...\n");
	rc = cxlmi_cmd_get_supported_logs(ep, &ret);
	if (rc)
		return rc;

	parse_supported_logs(&ret, &cel_size);
	return rc;
}

static int play_with_device_timestamp(struct cxlmi_endpoint *ep)
{
	int rc;
	uint64_t orig_ts;
	struct cxlmi_cci_get_timestamp get_ts;
	struct cxlmi_cci_set_timestamp set_ts = { 0 };

	rc = cxlmi_cmd_get_timestamp(ep, &get_ts);
	if (rc)
		return rc;
	printf("device timestamp: %lu\n", get_ts.timestamp);
	orig_ts = get_ts.timestamp;

	set_ts.timestamp = get_ts.timestamp * 2;
	rc = cxlmi_cmd_set_timestamp(ep, &set_ts);
	if (rc)
		return rc;

	memset(&get_ts, 0, sizeof(get_ts));
	rc = cxlmi_cmd_get_timestamp(ep, &get_ts);
	if (rc)
		return rc;
	printf("new device timestamp: %lu\n", get_ts.timestamp);

	memset(&set_ts, 0, sizeof(set_ts));
	set_ts.timestamp = orig_ts;
	rc = cxlmi_cmd_set_timestamp(ep, &set_ts);
	if (rc) {
		if (rc > 0)
			printf("set_timestamp error: %s\n",
			       cxlmi_retcode_to_str(rc));
		return rc;
	}

	memset(&get_ts, 0, sizeof(get_ts));
	rc = cxlmi_cmd_get_timestamp(ep, &get_ts);
	if (rc)
		return rc;
	printf("reset back to original device timestamp: %lu\n", get_ts.timestamp);

	return 0;
}

int main(int argc, char **argv)
{
	struct cxlmi_ctx *ctx;
	struct cxlmi_endpoint *ep;
	unsigned int nid;
	uint8_t eid;
	int rc = EXIT_FAILURE;

	if (argc != 3) {
		fprintf(stderr, "Must provide a mctp identifier touple\n");
		fprintf(stderr, "Usage: cxl-mctp <netid> <epid>\n");
		goto exit;
	}

	nid = strtol(argv[1], NULL, 10);
	eid = strtol(argv[2], NULL, 10);

	printf("ep %d:%d\n", nid, eid);

	ctx = cxlmi_new_ctx(stdout, DEFAULT_LOGLEVEL);
	if (!ctx) {
		fprintf(stderr, "cannot create new context object\n");
		goto exit;
	}

	ep = cxlmi_open_mctp(ctx, nid, eid);
	if (!ep) {
		fprintf(stderr, "cannot open MCTP endpoint %d:%d\n", nid, eid);
		goto exit_free_ctx;
	}

	/* yes, only 1 endpoint, but might add more */
	/* rc = show_some_info_from_all_devices(ctx); */

	/* rc = get_device_logs(ep); */

	rc = play_with_device_timestamp(ep);

	/* sleep(2); */

	rc = toggle_abort(ep);

	cxlmi_close(ep);
exit_free_ctx:
	cxlmi_free_ctx(ctx);
exit:
	return rc;
}
