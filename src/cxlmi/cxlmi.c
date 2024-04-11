#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <unistd.h>
#include <assert.h>

#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/types.h>

/* #if HAVE_LINUX_MCTP_H */
#include <linux/mctp.h>
/* #endif */

#include <ccan/list/list.h>

#include <libcxlmi.h>

#include "private.h"

#define CXL_MCTP_CATEGORY_REQ 0
#define CXL_MCTP_CATEGORY_RSP 1

struct cxlmi_transport_mctp {
	int	net;
	uint8_t	eid;
	int	sd;
	void	*resp_buf;
	size_t	resp_buf_size;
	struct sockaddr_mctp addr;
	int tag;
};

static const int default_timeout_ms = 1000;

/* CXL r3.1 Figure 7-19: CCI Message Format */
struct cxlmi_cci_msg {
	uint8_t category;
	uint8_t tag;
	uint8_t rsv1;
	uint8_t command;
	uint8_t command_set;
	uint8_t pl_length[3]; /* 20 bit little endian, BO bit at bit 23 */
	uint16_t return_code;
	uint16_t vendor_ext_status;
	uint8_t payload[];
} __attribute__ ((packed));

static bool cxlmi_probe_enabled_default(void)
{
	char *val;

	val = getenv("LIBCXLMI_PROBE_ENABLED");
	if (!val)
		return true;

	return strcmp(val, "0") &&
		strcasecmp(val, "false") &&
		strncasecmp(val, "disable", 7);
}

struct cxlmi_ctx * cxlmi_new_ctx(FILE *fp, int loglvl)
{
	struct cxlmi_ctx *ctx;

	ctx = calloc(1, sizeof(struct cxlmi_ctx));
	if (!ctx)
		return NULL;

	ctx->probe_enabled = cxlmi_probe_enabled_default();
	list_head_init(&ctx->endpoints);

	return ctx;
}

void cxlmi_free_ctx(struct cxlmi_ctx *ctx)
{
	free(ctx);
}

static struct cxlmi_endpoint *init_endpoint(struct cxlmi_ctx *ctx)
{
	struct cxlmi_endpoint *ep;

	ep = calloc(1, sizeof(*ep));
	if (!ep)
		return NULL;

	list_node_init(&ep->entry);
	ep->ctx = ctx;
	ep->timeout_ms = default_timeout_ms;
	list_add(&ctx->endpoints, &ep->entry);

	return ep;
}

static void mctp_close(struct cxlmi_endpoint *ep)
{
	struct cxlmi_transport_mctp *mctp;

	mctp = ep->transport_data;
	close(mctp->sd);
	free(mctp->resp_buf);
	free(ep->transport_data);
}

void cxlmi_close(struct cxlmi_endpoint *ep)
{
	if (ep->transport_data)
		mctp_close(ep);

	list_del(&ep->entry);
	free(ep);
}

static int sanity_check_rsp(struct cxlmi_cci_msg *req, struct cxlmi_cci_msg *rsp,
			    size_t len, bool fixed_length, size_t min_length)
{
	uint32_t pl_length;

	if (len < sizeof(rsp)) {
		return -1;
	}

	if (rsp->category != CXL_MCTP_CATEGORY_RSP) {
		return -1;
	}
	if (rsp->tag != req->tag) {
		return -1;
	}
	if ((rsp->command != req->command) ||
		(rsp->command_set != req->command_set)) {
		return -1;
	}

	if (rsp->return_code != 0) {
		return -1;
	}

	if (fixed_length) {
		if (len != min_length) {
			return -1;
		}
	} else {
		if (len < min_length) {
			return -1;
		}
	}
	pl_length = rsp->pl_length[0] | (rsp->pl_length[1] << 8) |
		((rsp->pl_length[2] & 0xf) << 16);
	if (len - sizeof(*rsp) != pl_length) {
		return -1;
	}

	return 0;
}

static int send_mctp_direct(struct cxlmi_endpoint *ep,
			    struct cxlmi_cci_msg *req_msg, size_t req_msg_sz,
			    struct cxlmi_cci_msg *rsp_msg, size_t rsp_msg_sz,
			    size_t rsp_msg_sz_min)
{
	int len;
	socklen_t addrlen;
	struct sockaddr_mctp addrrx;
	struct cxlmi_transport_mctp *mctp = ep->transport_data;

	assert(mctp->sd >= 0);
	len = sendto(mctp->sd, req_msg, req_msg_sz, 0,
		     (struct sockaddr *)&mctp->addr, sizeof(mctp->addr));

	len = recvfrom(mctp->sd, rsp_msg, rsp_msg_sz, 0,
		       (struct sockaddr *)&addrrx, &addrlen);
	return sanity_check_rsp(req_msg, rsp_msg, len,
				rsp_msg_sz == rsp_msg_sz_min, rsp_msg_sz_min);
}

/* CXL r3.0 Section 8.2.9.1.1: Identify (Opcode 0001h) */
int cxlmi_query_cci_identify(struct cxlmi_endpoint *ep,
			     struct cxlmi_cci_infostat_identify *ret)
{
	int rc;
	struct cxlmi_transport_mctp *mctp = ep->transport_data;
	ssize_t rsp_sz;
	struct cxlmi_cci_infostat_identify *pl;
	struct cxlmi_cci_msg *rsp;
	struct cxlmi_cci_msg req = {
		.category = CXL_MCTP_CATEGORY_REQ,
		.tag = mctp->tag++,
		.command = 1,
		.command_set = 0,
		.vendor_ext_status = 0xabcd,
	};

	rsp_sz = sizeof(*rsp) + sizeof(*pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_mctp_direct(ep, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc) {
		goto free_rsp;
	}

	if (rsp->return_code) {
		rc = rsp->return_code;
		goto free_rsp;
	}
	pl = (struct cxlmi_cci_infostat_identify *)rsp->payload;

	*ret = *pl;

free_rsp:
	free(rsp);
	return rc;
}

void cxlmi_set_probe_enabled(struct cxlmi_ctx *ctx, bool enabled)
{
	ctx->probe_enabled = enabled;
}

/* probe cxl component for basic device info */
static void endpoint_probe(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cci_infostat_identify id;

	if (!ep->ctx->probe_enabled)
		return;

	if (cxlmi_query_cci_identify(ep, &id))
		return;

	switch (id.component_type) {
	case 0x00:
		/* TODO: tunneling from an OoB switch mailbox CCI */
		ep->type = CXLMI_SWITCH;
		break;
	case 0x03:
		/*
		 * potential scenarios:
		 *   - type3 SLD
		 *   - type3 MLD - FM owned LD (TODO)
		 */
		ep->type = CXLMI_TYPE3;
		break;
	default:
		break;
	}
}

struct cxlmi_endpoint *cxlmi_open_mctp(struct cxlmi_ctx *ctx,
				       unsigned int netid, uint8_t eid)
{
	struct cxlmi_endpoint *ep;
	struct cxlmi_transport_mctp *mctp;
	int errno_save;
	struct sockaddr_mctp cci_addr = {
		.smctp_family = AF_MCTP,
		.smctp_network = netid,
		.smctp_addr.s_addr = eid,
		.smctp_type = 0x8, /* CXL CCI */
		.smctp_tag = MCTP_TAG_OWNER,
	};

	ep = init_endpoint(ctx);
	if (!ep)
		return NULL;

	mctp = calloc(1, sizeof(*mctp));
	if (!mctp) {
		errno_save = errno;
		goto err_close_ep;
	}

	mctp->sd = -1;

	mctp->resp_buf_size = 4096;
	mctp->resp_buf = calloc(1, mctp->resp_buf_size);
	if (!mctp->resp_buf) {
		errno_save = errno;
		goto err_free_mctp;
	}

	mctp->net = netid;
	mctp->eid = eid;
	mctp->addr = cci_addr;

	mctp->sd = socket(AF_MCTP, SOCK_DGRAM, 0);
	if (mctp->sd < 0) {
		assert(false);
		errno_save = errno;
		goto err_free_rspbuf;
	}
	if (bind(mctp->sd,
		 (struct sockaddr *)&cci_addr, sizeof(cci_addr))) {
		assert(false);
		errno_save = errno;
		goto err_free_rspbuf;
	}

	ep->transport_data = mctp;

	endpoint_probe(ep);

	return ep;

err_free_rspbuf:
	free(mctp->resp_buf);
err_free_mctp:
	free(mctp);
err_close_ep:
	cxlmi_close(ep);
	errno = errno_save;
	return NULL;
}

/* CXL r3.0 Section 8.2.9.4.1: Get Timestamp (Opcode 0300h) */
int cxlmi_query_cci_timestamp(struct cxlmi_endpoint *ep,
			      struct cxlmi_cci_get_timestamp *ret)
{

	struct cxlmi_cci_get_timestamp *pl;
	struct cxlmi_transport_mctp *mctp = ep->transport_data;
	int rc;
	ssize_t rsp_sz;
	struct cxlmi_cci_msg *rsp;
	struct cxlmi_cci_msg req = {
		.category = CXL_MCTP_CATEGORY_REQ,
		.tag = mctp->tag++,
		.command = 0,
		.command_set = 3,
		.vendor_ext_status = 0xabcd,
	};

	rsp_sz = sizeof(*rsp) + sizeof(*pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_mctp_direct(ep, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		goto free_rsp;

	pl = (struct cxlmi_cci_get_timestamp *)(rsp->payload);
	*ret = *pl;

free_rsp:
	free(rsp);
	return rc;
}

struct cxlmi_endpoint *cxlmi_first_endpoint(struct cxlmi_ctx *m)
{
	return list_top(&m->endpoints, struct cxlmi_endpoint, entry);
}

struct cxlmi_endpoint *cxlmi_next_endpoint(struct cxlmi_ctx *m, struct cxlmi_endpoint * ep)
{
	return ep ? list_next(&m->endpoints, ep, entry) : NULL;
}
