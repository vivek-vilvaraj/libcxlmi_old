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
	struct cxlmi_cci_identify_memdev id;

	rc = cxlmi_cmd_identify_memdev(ep, &id);
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

static int show_some_info_from_all_devices(struct cxlmi_ctx *ctx)
{
	int rc = 0;
	struct cxlmi_endpoint *ep;

	cxlmi_for_each_endpoint(ctx, ep) {
		struct cxlmi_cci_infostat_identify id;

		rc = cxlmi_cmd_infostat_identify(ep, &id);
		if (rc)
			break;

		printf("serial number: 0x%lx\n", (uint64_t)id.serial_num);

		switch (id.component_type) {
		case 0x00:
			printf("device type: CXL Switch\n");
			printf("VID:%04x DID:%04x\n", id.vendor_id, id.device_id);
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
	}

	return rc;
}

static int toggle_abort(struct cxlmi_endpoint *ep)
{
	int rc;
	struct cxlmi_cci_infostat_bg_op_status sts;

	rc = cxlmi_cmd_infostat_bg_op_status(ep, &sts);
	if (rc)
		goto done;

	if (!(sts.status & (1 << 0))) {
		printf("no background operation in progress...\n");

		rc = cxlmi_cmd_memdev_sanitize(ep);
		if (rc && rc != CXLMI_RET_BACKGROUND) {
			printf("could not start sanitize: %s\n",
			       cxlmi_cmd_retcode_tostr(rc));;
			goto done;
		} else {
			printf("sanitizing op started\n");
			sleep(1);
		}
	}

	rc = cxlmi_cmd_infostat_request_bg_op_abort(ep);
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
	struct cxlmi_cci_get_timestamp get_ts;
	struct cxlmi_cci_set_timestamp set_ts = {
		.timestamp = 946684800, /* Jan 1, 2000 */
	};

	rc = cxlmi_cmd_get_timestamp(ep, &get_ts);
	if (rc)
		return rc;
	printf("device timestamp: %lu\n", get_ts.timestamp);
	orig_ts = get_ts.timestamp;

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
			       cxlmi_cmd_retcode_tostr(rc));
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

	rc = play_with_device_timestamp(ep);

	rc = toggle_abort(ep);

	cxlmi_close(ep);
exit_free_ctx:
	cxlmi_free_ctx(ctx);
exit:
	return rc;
}
