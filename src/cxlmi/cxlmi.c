#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <unistd.h>

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

/* 2 secs, see CXL r3.1 Section 9.20.2 */
#define MAX_TIMEOUT_MCTP 2000

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

CXLMI_EXPORT struct cxlmi_ctx *cxlmi_new_ctx(FILE *fp, int loglvl)
{
	struct cxlmi_ctx *ctx;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->fp = fp ? fp : stderr;
	ctx->probe_enabled = cxlmi_probe_enabled_default();
	list_head_init(&ctx->endpoints);

	return ctx;
}

CXLMI_EXPORT void cxlmi_free_ctx(struct cxlmi_ctx *ctx)
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
	ep->timeout_ms = 5000;
	list_add(&ctx->endpoints, &ep->entry);

	return ep;
}

static int mctp_check_timeout(struct cxlmi_endpoint *ep,
			      unsigned int timeout_ms)
{
	return timeout_ms > MAX_TIMEOUT_MCTP;
}

CXLMI_EXPORT int cxlmi_endpoint_set_timeout(struct cxlmi_endpoint *ep,
					    unsigned int timeout_ms)
{
	if (ep->transport_data) {
		int rc;

		rc = mctp_check_timeout(ep, timeout_ms);
		if (rc)
			return rc;
	}
	ep->timeout_ms = timeout_ms;
	return 0;
}

CXLMI_EXPORT unsigned int cxlmi_endpoint_get_timeout(struct cxlmi_endpoint *ep)
{
	return ep->timeout_ms;
}

static void mctp_close(struct cxlmi_endpoint *ep)
{
	struct cxlmi_transport_mctp *mctp = ep->transport_data;

	close(mctp->sd);
	free(mctp->resp_buf);
}

CXLMI_EXPORT void cxlmi_close(struct cxlmi_endpoint *ep)
{
	if (ep->transport_data) {
		mctp_close(ep);
		free(ep->transport_data);
	}
	list_del(&ep->entry);
	free(ep);
}

static int sanity_check_rsp(struct cxlmi_ctx *ctx,
			    struct cxlmi_cci_msg *req, struct cxlmi_cci_msg *rsp,
			    size_t len, bool fixed_length, size_t min_length)
{
	uint32_t pl_length;

	if (len < sizeof(rsp)) {
		cxlmi_msg(ctx, LOG_ERR, "Too short to read error code\n");
		return -1;
	}

	if (rsp->category != CXL_MCTP_CATEGORY_RSP) {
		cxlmi_msg(ctx, LOG_ERR, "Message not a response\n");
		return -1;
	}
	if (rsp->tag != req->tag) {
		cxlmi_msg(ctx, LOG_ERR, "Reply has wrong tag %d %d\n",
			  rsp->tag, req->tag);
		return -1;
	}
	if ((rsp->command != req->command) ||
	    (rsp->command_set != req->command_set)) {
		cxlmi_msg(ctx, LOG_ERR, "Response to wrong command\n");
		return -1;
	}

	if (rsp->return_code != 0) {
		cxlmi_msg(ctx, LOG_ERR, "Error code in response %d\n",
			  rsp->return_code);
		return -1;
	}

	if (fixed_length) {
		if (len != min_length) {
			cxlmi_msg(ctx, LOG_ERR,
				  "Not expected fixed length of response. %ld %ld\n",
				  len, min_length);
			return -1;
		}
	} else {
		if (len < min_length) {
			cxlmi_msg(ctx, LOG_ERR,
				  "Not expected minimum length of response\n");
			return -1;
		}
	}
	pl_length = rsp->pl_length[0] | (rsp->pl_length[1] << 8) |
		((rsp->pl_length[2] & 0xf) << 16);
	if (len - sizeof(*rsp) != pl_length) {
		cxlmi_msg(ctx, LOG_ERR,
			  "Payload length not matching expected part of full message %ld %d\n",
			  len - sizeof(*rsp), pl_length);
		return -1;
	}

	return 0;
}

static int send_mctp_direct(struct cxlmi_endpoint *ep,
			    struct cxlmi_cci_msg *req_msg, size_t req_msg_sz,
			    struct cxlmi_cci_msg *rsp_msg, size_t rsp_msg_sz,
			    size_t rsp_msg_sz_min)
{
	int rc, errno_save, len;
	socklen_t addrlen;
	struct sockaddr_mctp addrrx;
	struct cxlmi_transport_mctp *mctp = ep->transport_data;
	struct pollfd pollfds[1];
	int timeout = ep->timeout_ms ?: -1;

	memset(rsp_msg, 0, rsp_msg_sz);

	len = sendto(mctp->sd, req_msg, req_msg_sz, 0,
		     (struct sockaddr *)&mctp->addr, sizeof(mctp->addr));

	pollfds[0].fd = mctp->sd;
	pollfds[0].events = POLLIN;
	while (1) {
		rc = poll(pollfds, 1, timeout);
		if (rc > 0)
			break;
		else if (rc == 0) {
			cxlmi_msg(ep->ctx, LOG_DEBUG, "Timeout on MCTP socket");
			errno = ETIMEDOUT;
			return -1;
		} else if (errno != EINTR) {
			errno_save = errno;
			cxlmi_msg(ep->ctx, LOG_ERR,
				  "Failed polling on MCTP socket");
			errno = errno_save;
			return -1;
		}
	}

	len = recvfrom(mctp->sd, rsp_msg, rsp_msg_sz, 0,
		       (struct sockaddr *)&addrrx, &addrlen);

	return sanity_check_rsp(ep->ctx, req_msg, rsp_msg, len,
				rsp_msg_sz == rsp_msg_sz_min, rsp_msg_sz_min);
}

static int send_cmd_cci(struct cxlmi_endpoint *ep,
			struct cxlmi_cci_msg *req_msg, size_t req_msg_sz,
			struct cxlmi_cci_msg *rsp_msg, size_t rsp_msg_sz,
			size_t rsp_msg_sz_min)
{
	int rc;

	/* TODO: rc = ep->transport->submit(ep, ...); ? */
	rc = send_mctp_direct(ep, req_msg, req_msg_sz,
			      rsp_msg, rsp_msg_sz, rsp_msg_sz);

	return rc;
}

CXLMI_EXPORT void cxlmi_set_probe_enabled(struct cxlmi_ctx *ctx, bool enabled)
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

CXLMI_EXPORT struct cxlmi_endpoint *cxlmi_open_mctp(struct cxlmi_ctx *ctx,
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
		cxlmi_msg(ctx, LOG_ERR,
			  "cannot open socket for mctp endpoint %d:%d\n",
			  netid, eid);
		errno_save = errno;
		goto err_free_rspbuf;
	}
	if (bind(mctp->sd,
		 (struct sockaddr *)&cci_addr, sizeof(cci_addr))) {
		cxlmi_msg(ctx, LOG_ERR,
			  "cannot bind for mctp endpoint %d:%d\n", netid, eid);
		errno_save = errno;
		goto err_free_rspbuf;
	}

	ep->transport_data = mctp;
	ep->timeout_ms = MAX_TIMEOUT_MCTP;
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

CXLMI_EXPORT struct cxlmi_endpoint *cxlmi_first_endpoint(struct cxlmi_ctx *m)
{
	return list_top(&m->endpoints, struct cxlmi_endpoint, entry);
}

CXLMI_EXPORT struct cxlmi_endpoint *cxlmi_next_endpoint(struct cxlmi_ctx *m,
						struct cxlmi_endpoint * ep)
{
	return ep ? list_next(&m->endpoints, ep, entry) : NULL;
}

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
		.command = IS_IDENTIFY,
		.command_set = INFOSTAT,
		.vendor_ext_status = 0xabcd,
	};

	rsp_sz = sizeof(*rsp) + sizeof(*pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
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

int cxlmi_request_bg_operation_abort(struct cxlmi_endpoint *ep)
{
	struct cxlmi_transport_mctp *mctp = ep->transport_data;
	int rc;
	ssize_t rsp_sz;
	struct cxlmi_cci_msg *rsp;
	struct cxlmi_cci_msg req = {
		.category = CXL_MCTP_CATEGORY_REQ,
		.tag = mctp->tag++,
		.command = BACKGROUND_OPERATION_ABORT,
		.command_set = INFOSTAT,
		.vendor_ext_status = 0xabcd,
	};

	rsp_sz = sizeof(*rsp);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, &req, sizeof(req), rsp, rsp_sz, rsp_sz);

	free(rsp);
	return rc;
}

int cxlmi_query_cci_timestamp(struct cxlmi_endpoint *ep,
			      struct cxlmi_cci_get_timestamp *ret)
{
	struct cxlmi_cci_get_timestamp *rsp_pl;
	struct cxlmi_transport_mctp *mctp = ep->transport_data;
	int rc;
	ssize_t rsp_sz;
	struct cxlmi_cci_msg *rsp;
	struct cxlmi_cci_msg req = {
		.category = CXL_MCTP_CATEGORY_REQ,
		.tag = mctp->tag++,
		.command = GET,
		.command_set = TIMESTAMP,
		.vendor_ext_status = 0xabcd,
	};

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		goto free_rsp;

	rsp_pl = (struct cxlmi_cci_get_timestamp *)(rsp->payload);
	*ret = *rsp_pl;

free_rsp:
	free(rsp);
	return rc;
}

int cxlmi_cmd_set_timestamp(struct cxlmi_endpoint *ep,
			    struct cxlmi_cci_set_timestamp *in)
{
	struct cxlmi_transport_mctp *mctp = ep->transport_data;
	struct cxlmi_cci_set_timestamp *req_pl;
	struct cxlmi_cci_msg *req, *rsp;
	size_t req_sz, rsp_sz;
	int rc = 0;

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	*req = (struct cxlmi_cci_msg) {
		.category = CXL_MCTP_CATEGORY_REQ,
		.tag = mctp->tag++,
		.command = SET,
		.command_set = TIMESTAMP,
		.vendor_ext_status = 0xabcd,
		.pl_length = {
			[0] = sizeof(*req_pl) & 0xff,
			[1] = (sizeof(*req_pl) >> 8) & 0xff,
			[2] = (sizeof(*req_pl) >> 16) & 0xff,
		},
	};
	req_pl = (struct cxlmi_cci_set_timestamp *)req->payload;
	*req_pl = *in;

	printf("%ld\n", req_pl->timestamp);

	rsp_sz = sizeof(*rsp);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		goto free_req;

	rc = send_cmd_cci(ep, req, req_sz, rsp, rsp_sz, rsp_sz);

	free(rsp);
free_req:
	free(req);
	return rc;
}
