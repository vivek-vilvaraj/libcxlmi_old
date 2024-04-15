#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include <libcxlmi.h>

static int show_some_info_from_all_devices(struct cxlmi_ctx *ctx)
{
	int rc = 0;
	struct cxlmi_endpoint *ep;

	cxlmi_for_each_endpoint(ctx, ep) {
		struct cxlmi_cci_infostat_identify id;
		struct cxlmi_cci_get_timestamp ts;

		rc = cxlmi_query_cci_identify(ep, &id);
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

		rc = cxlmi_query_cci_timestamp(ep, &ts);
		if (rc)
			break;
		printf("\tdevice timestamp: %lu\n", ts.timestamp);
	}

	return rc;
}

static int toggle_abort(struct cxlmi_endpoint *ep)
{
	int rc;

	rc = cxlmi_request_bg_operation_abort(ep);
	if (rc) {
		printf("request not successful\n");
	}

	return rc;
}

static int modify_timestamp(struct cxlmi_endpoint *ep)
{
	int rc;
	struct cxlmi_cci_get_timestamp get_ts;
	struct cxlmi_cci_set_timestamp set_ts;

	rc = cxlmi_query_cci_timestamp(ep, &get_ts);
	if (rc)
		return rc;
	printf("device timestamp: %lu\n", get_ts.timestamp);
	set_ts.timestamp = get_ts.timestamp * 2;

	sleep(1);

	rc = cxlmi_cmd_set_timestamp(ep, &set_ts);
	if (rc)
		return rc;
	printf("new device timestamp: %lu\n", set_ts.timestamp);

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

	ctx = cxlmi_new_ctx(stdout, 1);
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
	rc = show_some_info_from_all_devices(ctx);

	sleep(2);

	rc = modify_timestamp(ep);

	sleep(2);

	rc = toggle_abort(ep);

	cxlmi_close(ep);
exit_free_ctx:
	cxlmi_free_ctx(ctx);
exit:
	return rc;
}
