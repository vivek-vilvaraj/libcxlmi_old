// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libcxlmi.
 *
 * Do some simple API verifications.
 */
#include <stdio.h>
#include <stdlib.h>

#include <libcxlmi.h>

static int verify_num_endpoints(struct cxlmi_ctx *ctx, int expected)
{
	int num_ep = 0;
	struct cxlmi_endpoint *ep;

	cxlmi_for_each_endpoint(ctx, ep)
		num_ep++;

	if (num_ep != expected) {
		fprintf(stderr, "[FAIL] have %d endpoints, expected %d\n",
			num_ep, expected);
		return -1;
	}

	return 0;
}

static int verify_ep_fmapi(struct cxlmi_endpoint *ep)
{
	if (cxlmi_endpoint_has_fmapi(ep) && cxlmi_endpoint_disable_fmapi(ep)) {
		int rc;
		struct cxlmi_cmd_identify id;
		struct cxlmi_tunnel_info ti = {
			.level = 1,
			.port = 0,
			.id = 0,
		};

		rc = cxlmi_cmd_identify(ep, &ti, &id);

		if (rc != -1) {
			fprintf(stderr,
				"[FAIL] unexpected return code (0x%x)\n", rc);
			return -1;
		}
		if (cxlmi_endpoint_has_fmapi(ep)) {
			fprintf(stderr, "[FAIL] FM-API is enabled\n");
			return -1;
		}

		if (cxlmi_endpoint_enable_fmapi(ep)) {
			/*
			 * Test may trigger false positives simple because of
			 * spurious qemu/mctp failures (Not expected fixed
			 * length of response), so don't check for -1 here.
			 */
			rc = cxlmi_cmd_identify(ep, &ti, &id);
			if (rc > 0)
				fprintf(stderr,
				"[FAIL] unexpected return code (0x%x)\n", rc);
		}
	}

	return 0;
}

/* Ensure no duplicate mctp endpoints are opened */
static int test_ep_duplicates_mctp(unsigned int nid, int8_t eid)
{

	struct cxlmi_endpoint *ep1, *ep2;
	struct cxlmi_ctx *ctx;
	int rc = 0;

	ctx = cxlmi_new_ctx(stdout, DEFAULT_LOGLEVEL);
	if (!ctx) {
		fprintf(stderr, "cannot create new context object\n");
		return -1;
	}

	ep1 = cxlmi_open_mctp(ctx, nid, eid);
	if (!ep1) {
		fprintf(stderr, "cannot open endpoint\n");
		goto free_ctx;
	}

	ep2 = cxlmi_open_mctp(ctx, nid, eid);
	if (ep2) {
		fprintf(stderr,
			"[FAIL] no duplicate endpoints should be allowed\n");
		cxlmi_close(ep2);
		rc = -1;
	}

	rc = verify_ep_fmapi(ep1);
	if (rc)
		goto free_ctx;

	cxlmi_close(ep1);
	verify_num_endpoints(ctx, 0);
free_ctx:
	cxlmi_free_ctx(ctx);
	return rc;
}

/* ensure no duplicate ioctl endpoints are opened */
static int test_ep_duplicates_ioctl(char *devname)
{

	struct cxlmi_endpoint *ep1, *ep2;
	struct cxlmi_ctx *ctx;
	int rc = 0;

	ctx = cxlmi_new_ctx(stdout, DEFAULT_LOGLEVEL);
	if (!ctx) {
		fprintf(stderr, "cannot create new context object\n");
		return -1;
	}

	ep1 = cxlmi_open(ctx, devname);
	if (!ep1) {
		fprintf(stderr, "cannot open '%s' endpoint\n", devname);
		goto free_ctx;
	}

	ep2 = cxlmi_open(ctx, devname);
	if (ep2) {
		fprintf(stderr,
			"[FAIL] no duplicate endpoints should be allowed\n");
		cxlmi_close(ep2);
		rc = -1;
	}

	cxlmi_close(ep1);
free_ctx:
	rc = verify_num_endpoints(ctx, 0);
	cxlmi_free_ctx(ctx);
	return rc;
}

/* ensure mctp and ioctl endpoints can co-exist */
static int test_mixed_ep(unsigned int nid, int8_t eid, char *devname)
{

	struct cxlmi_endpoint *ep1, *ep2;
	struct cxlmi_ctx *ctx;
	int rc = -1;

	ctx = cxlmi_new_ctx(stdout, DEFAULT_LOGLEVEL);
	if (!ctx) {
		fprintf(stderr, "cannot create new context object\n");
		return -1;
	}

	ep1 = cxlmi_open_mctp(ctx, nid, eid);
	if (!ep1) {
		fprintf(stderr,
			"[FAIL] cannot open '%d:%d' endpoint\n", nid, eid);
		goto free_ctx;
	}

	ep2 = cxlmi_open(ctx, devname);
	if (!ep2) {
		fprintf(stderr,
			"[FAIL] mixed endpoints should be allowed\n");
		goto free_ctx;
	}

	rc = verify_num_endpoints(ctx, 2);
	cxlmi_close(ep2);
	cxlmi_close(ep1);
	rc = verify_num_endpoints(ctx, 0);
free_ctx:
	cxlmi_free_ctx(ctx);
	return rc;
}

/*
 * Ways to run these tests are determined by the passed arguments:
 *
 * api-simple-tests 13 5        <--- mctp tests
 * api-simple-tests switch0     <--- ioctl tests
 * api-simple-tests 23 8 mem2   <--- mctp + ioctl tests
 */
int main(int argc, char **argv)
{
	int rc = 0, errs = 0;
	unsigned int nid;
	uint8_t eid;

	if (argc == 1 || argc > 4) {
		fprintf(stderr,
		"Must provide mctp-endpoint and/or a Linux device (ie: mem0)\n");
		fprintf(stderr, "Usage: api-simple-tests <nid> <eid>\n");
		fprintf(stderr, "Usage: api-simple-tests <device>\n");
		fprintf(stderr, "Usage: api-simple-tests <nid> <eid> <device>\n");
		return EXIT_FAILURE;
	}

	if (argc == 2) { /* ioctl */
		rc = test_ep_duplicates_ioctl(argv[1]);
	} else if (argc == 3) { /* mctp */
		nid = atoi(argv[1]);
		eid = atoi(argv[2]);

		rc = test_ep_duplicates_mctp(nid, eid);
	} else if (argc == 4) { /* both */
		nid = atoi(argv[1]);
		eid = atoi(argv[2]);

		rc = test_ep_duplicates_mctp(nid, eid);
		rc = test_ep_duplicates_ioctl(argv[3]);

		rc = test_mixed_ep(nid, eid, argv[3]);
	}

	if (rc)
		errs++;

	if (!errs)
		printf("No errors found\n");

	return EXIT_SUCCESS;;
}
