// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libcxlmi.
 *
 * Do some simple API verifications.
 */
#include <stdio.h>
#include <stdlib.h>

#include <libcxlmi.h>

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

	cxlmi_close(ep1);
free_ctx:
	cxlmi_free_ctx(ctx);
	return rc;
}

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
	cxlmi_free_ctx(ctx);
	return rc;
}

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
		fprintf(stderr, "cannot open endpoint\n");
		goto free_ctx;
	}

	ep2 = cxlmi_open(ctx, devname);
	if (!ep2) {
		fprintf(stderr,
			"[FAIL] mixed endpoints should be allowed\n");
	} else {
		cxlmi_close(ep2);
		rc = 0;
	}

	cxlmi_close(ep1);
free_ctx:
	cxlmi_free_ctx(ctx);
	return rc;
}

/*
 * Ways to run these tests are determined by the passed arguments:
 *
 * api-simple-tests 13 5 <--- mctp tests
 * api-simple-tests switch0 <--- ioctl tests
 * api-simple-tests 23 8 mem2 <--- mctp + ioctl tests
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