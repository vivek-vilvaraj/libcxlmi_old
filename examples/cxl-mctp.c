#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

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
		printf("device type: %s\n",
		       id.component_type == 0x03 ? "type3":"switch");

		rc = cxlmi_query_cci_timestamp(ep, &ts);
		if (rc)
			break;
		printf("device timestamp: %lu\n", ts.timestamp);
	}

	return rc;
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

	ctx = cxlmi_new_ctx(stderr, 1);
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

	cxlmi_close(ep);
exit_free_ctx:
	cxlmi_free_ctx(ctx);
exit:
	return rc;
}
