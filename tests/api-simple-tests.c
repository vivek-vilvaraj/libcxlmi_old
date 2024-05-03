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

static int test_ep_duplicates_ioctl(const char *devname)
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


/*
 * Ways to run these tests are determined by the passed arguments:
 * 
 * api-simple-tests 11 9 <--- mctp tests
 * api-simple-tests switch0 <--- ioctl tests
 * api-simple-tests 11 8 mem2 <--- mctp + ioctl tests
 */
int main(int argc, char **argv)
{
	int rc, errs = 0;
	unsigned int nid;
	uint8_t eid;

	if (argc == 2) { /* ioctl */
		rc = test_ep_duplicates_ioctl(argv[1]);
	}

	else if (argc == 3) { /* mctp */
		nid = atoi(argv[1]);
		eid = atoi(argv[2]);

		rc = test_ep_duplicates_mctp(nid, eid);
	}

	else if (argc == 4) {
		
	}
	

	rc = test_ep_duplicates(nid, eid);
	if (rc)
		errs++;

	if (!errs)
		printf("No errors found\n");

	return EXIT_SUCCESS;;
}
