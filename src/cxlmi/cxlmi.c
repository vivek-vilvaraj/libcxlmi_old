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

#include <ccan/array_size/array_size.h>
/* #include <ccan/minmax/minmax.h> */
#include <ccan/list/list.h>

#include <libcxlmi.h>

#include "private.h"

#define CXL_MCTP_CATEGORY_REQ 0
#define CXL_MCTP_CATEGORY_RSP 1

struct cxlmi_transport_mctp {
	int	net;
	uint8_t	eid;
	int	sd;
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

CXLMI_EXPORT struct cxlmi_ctx *cxlmi_new_ctx(FILE *fp, int log_level)
{
	struct cxlmi_ctx *ctx;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->fp = fp ? fp : stderr;
	ctx->log_level = log_level;
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

static int sanity_check_rsp(struct cxlmi_endpoint *ep,
			    struct cxlmi_cci_msg *req, struct cxlmi_cci_msg *rsp,
			    size_t len, bool fixed_length, size_t min_length)
{
	uint32_t pl_length;

	if (len < sizeof(rsp)) {
		printf( "Too short to read error code\n");
		return -1;
	}

	if (rsp->category != CXL_MCTP_CATEGORY_RSP) {
		printf( "Message not a response\n");
		return -1;
	}
	if (rsp->tag != req->tag) {
		printf( "Reply has wrong tag %d %d\n",
			  rsp->tag, req->tag);
		return -1;
	}
	if ((rsp->command != req->command) ||
	    (rsp->command_set != req->command_set)) {
		printf( "Response to wrong command\n");
		return -1;
	}

	if (rsp->return_code != 0) {
		printf( "Error code in response %d\n",
			  rsp->return_code);
		return rsp->return_code;
	}

	if (fixed_length) {
		if (len != min_length) {
			printf(
				  "Not expected fixed length of response. %ld %ld\n",
				  len, min_length);
			return -1;
		}
	} else {
		if (len < min_length) {
			printf(
				  "Not expected minimum length of response\n");
			return -1;
		}
	}
	pl_length = rsp->pl_length[0] | (rsp->pl_length[1] << 8) |
		((rsp->pl_length[2] & 0xf) << 16);
	if (len - sizeof(*rsp) != pl_length) {
		printf(
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
	int timeout = ep->timeout_ms ? ep->timeout_ms : -1;

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

	return sanity_check_rsp(ep, req_msg, rsp_msg, len,
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
			      rsp_msg, rsp_msg_sz, rsp_msg_sz_min);

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

	if (cxlmi_cmd_infostat_identify(ep, &id))
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

	mctp->net = netid;
	mctp->eid = eid;
	mctp->addr = cci_addr;

	mctp->sd = socket(AF_MCTP, SOCK_DGRAM, 0);
	if (mctp->sd < 0) {
		cxlmi_msg(ctx, LOG_ERR,
			  "cannot open socket for mctp endpoint %d:%d\n",
			  netid, eid);
		errno_save = errno;
		goto err_free_mctp;
	}
	if (bind(mctp->sd,
		 (struct sockaddr *)&cci_addr, sizeof(cci_addr))) {
		cxlmi_msg(ctx, LOG_ERR,
			  "cannot bind for mctp endpoint %d:%d\n", netid, eid);
		errno_save = errno;
		goto err_free_mctp;
	}

	ep->transport_data = mctp;
	ep->timeout_ms = MAX_TIMEOUT_MCTP;
	endpoint_probe(ep);

	return ep;

err_free_mctp:
	free(mctp);
err_close_ep:
	cxlmi_close(ep);
	errno = errno_save;
	return NULL;
}

static const char *const cxlmi_retcode_status[] = {
	[CXLMI_RET_SUCCESS] = "success",
	[CXLMI_RET_BACKGROUND] = "background cmd started successfully",
	[CXLMI_RET_INPUT] = "cmd input was invalid",
	[CXLMI_RET_UNSUPPORTED] = "cmd is not supported",
	[CXLMI_RET_INTERNAL] = "internal device error",
	[CXLMI_RET_RETRY] = "temporary error, retry once",
	[CXLMI_RET_BUSY] = "ongoing background operation",
	[CXLMI_RET_MEDIADISABLED] = "media access is disabled",
	[CXLMI_RET_FWINPROGRESS] = "one FW package can be transferred at a time",
	[CXLMI_RET_FWOOO] = "FW package content was transferred out of order",
	[CXLMI_RET_FWAUTH] = "FW package authentication failed",
	[CXLMI_RET_FWSLOT] = "FW slot is not supported for requested operation",
	[CXLMI_RET_FWROLLBACK] = "rolled back to the previous active FW",
	[CXLMI_RET_FWRESET] = "FW failed to activate, needs cold reset",
	[CXLMI_RET_HANDLE] = "one or more Event Record Handles were invalid",
	[CXLMI_RET_PADDR] = "physical address specified is invalid",
	[CXLMI_RET_POISONLMT] = "poison injection limit has been reached",
	[CXLMI_RET_MEDIAFAILURE] = "permanent issue with the media",
	[CXLMI_RET_ABORT] = "background cmd was aborted by device",
	[CXLMI_RET_SECURITY] = "not valid in the current security state",
	[CXLMI_RET_PASSPHRASE] = "phrase doesn't match current set passphrase",
	[CXLMI_RET_MBUNSUPPORTED] = "unsupported on the mailbox it was issued on",
	[CXLMI_RET_PAYLOADLEN] = "invalid payload length",
	[CXLMI_RET_LOG] = "nvalid or unsupported log page",
	[CXLMI_RET_INTERRUPTED] = "asynchronous event occured",
	[CXLMI_RET_FEATUREVERSION] = "unsupported feature version",
	[CXLMI_RET_FEATURESELVALUE] = "unsupported feature selection value",
	[CXLMI_RET_FEATURETRANSFERIP] = "feature transfer in progress",
	[CXLMI_RET_FEATURETRANSFEROOO] = "feature transfer out of order",
	[CXLMI_RET_RESOURCEEXHAUSTED] = "resources are exhausted",
	[CXLMI_RET_EXTLIST] = "invalid Extent List",
};

CXLMI_EXPORT const char *cxlmi_cmd_retcode_tostr(uint16_t code)
{
	if (code > ARRAY_SIZE(cxlmi_retcode_status))
		return NULL;
	return cxlmi_retcode_status[code];
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

/* #define DECLARE_CMD_PLOUT(cmdset, cmd, outtype)				\ */
/* CXLMI_EXPORT								\ */
/* int cxlmi_cmd_##cmdset_##cmd(struct cxlmi_endpoint *ep,			\ */
/*			     typeof(outtype *) ret)			\ */
/* {									\ */
/*	int rc;                                                         \ */
/*	struct cxlmi_transport_mctp *mctp = ep->transport_data;         \ */
/*	ssize_t rsp_sz;							\ */
/*	typeof(ret) rsp_pl;						\ */
/*	struct cxlmi_cci_msg *rsp;					\ */
/*	struct cxlmi_cci_msg req = {					\ */
/*		.category = CXL_MCTP_CATEGORY_REQ,                      \ */
/*		.tag = mctp->tag++,                                     \ */
/*		.command = (cmd),					\ */
/*		.command_set = (cmdset),				\ */
/*		.vendor_ext_status = 0xabcd,                            \ */
/*	};                                                              \ */
/*									\ */
/*	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);			\ */
/*	rsp = calloc(1, rsp_sz);					\ */
/*	if (!rsp)							\ */
/*		return -1;						\ */
/*									\ */
/*	rc = send_cmd_cci(ep, &req, sizeof(req), rsp, rsp_sz, rsp_sz);	\ */
/*	if (rc) {							\ */
/*		if (rsp->return_code)					\ */
/*			rc = rsp->return_code;				\ */
/*		goto free_rsp;						\ */
/*	}								\ */
/*									\ */
/*	rsp_pl = (typeof(ret))rsp->payload;				\ */
/*	*ret = *rsp_pl;							\ */
/* free_rsp:								\ */
/*	free(rsp);							\ */
/*	return rc;							\ */
/* } */

/* DECLARE_CMD_PLOUT(infostat, is_identify, struct cxlmi_cci_infostat_identify); */
/* DECLARE_CMD_PLOUT(timestamp, get, struct cxlmi_cci_get_timestamp); */

/* #define DECLARE_CMD_PLIN(cmdset, cmd) */
/* #define DECLARE_CMD_PLIN_PLOUT(cmdset, cmd) */
/* #define DECLARE_CMD_PLNONE(cmdset, cmd) */

CXLMI_EXPORT int cxlmi_cmd_infostat_identify(struct cxlmi_endpoint *ep,
				     struct cxlmi_cci_infostat_identify *ret)
{
	int rc;
	ssize_t rsp_sz;
	struct cxlmi_transport_mctp *mctp = ep->transport_data;
	struct cxlmi_cci_infostat_identify *rsp_pl;
	struct cxlmi_cci_msg *rsp;
	struct cxlmi_cci_msg req = (struct cxlmi_cci_msg) {
		.category = CXL_MCTP_CATEGORY_REQ,
		.tag = mctp->tag++,
		.command = IS_IDENTIFY,
		.command_set = INFOSTAT,
		.vendor_ext_status = 0xabcd,
	};

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc) {
		goto free_rsp;
	}

	rsp_pl = (void *)rsp->payload;
	*ret = *rsp_pl;
free_rsp:
	free(rsp);
	return rc;
}

int cxlmi_cmd_get_timestamp(struct cxlmi_endpoint *ep,
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

	rsp_pl = (void  *)(rsp->payload);
	*ret = *rsp_pl;
free_rsp:
	free(rsp);
	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_set_timestamp(struct cxlmi_endpoint *ep,
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

CXLMI_EXPORT int cxlmi_cmd_infostat_bg_op_status(struct cxlmi_endpoint *ep,
				struct cxlmi_cci_infostat_bg_op_status *ret)
{
	struct cxlmi_cci_infostat_bg_op_status *rsp_pl;
	struct cxlmi_transport_mctp *mctp = ep->transport_data;
	int rc;
	ssize_t rsp_sz;
	struct cxlmi_cci_msg *rsp;
	struct cxlmi_cci_msg req = {
		.category = CXL_MCTP_CATEGORY_REQ,
		.tag = mctp->tag++,
		.command = BACKGROUND_OPERATION_STATUS,
		.command_set = INFOSTAT,
		.vendor_ext_status = 0xabcd,
	};

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		goto free_rsp;

	rsp_pl = (void  *)(rsp->payload);
	*ret = *rsp_pl;
free_rsp:
	free(rsp);
	return rc;
}


CXLMI_EXPORT int
cxlmi_cmd_infostat_request_bg_op_abort(struct cxlmi_endpoint *ep)
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

static const int maxlogs = 10; /* Only 3 in CXL r3.0 but let us leave room */
CXLMI_EXPORT int cxlmi_cmd_get_supported_logs(struct cxlmi_endpoint *ep,
				      struct cxlmi_cci_get_supported_logs *ret)
{
	struct cxlmi_transport_mctp *mctp = ep->transport_data;
	struct cxlmi_cci_get_supported_logs *pl;
	struct cxlmi_cci_msg *rsp;
	struct cxlmi_cci_msg req = {
		.category = CXL_MCTP_CATEGORY_REQ,
		.tag = mctp->tag++,
		.command = GET_SUPPORTED,
		.command_set = LOGS,
		.vendor_ext_status = 0xabcd,
	};
	int rc, i, j;
	ssize_t rsp_sz;

	rsp_sz = sizeof(*rsp) + sizeof(*pl) + maxlogs * sizeof(*pl->entries);

	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, &req, sizeof(req), rsp, rsp_sz,
			  sizeof(*rsp) + sizeof(*pl));
	if (rc)
		goto free_rsp;

	pl = (void *)(rsp->payload);
//	memcpy(ret, pl, min(maxlogs, pl->num_supported_log_entries) * sizeof(*pl->entries));
	*ret = *pl;
	for (i = 0; i < pl->num_supported_log_entries; i++) {
		for (j = 0; j < sizeof(pl->entries[i].uuid); j++) {
			ret->entries[i].uuid[j] = pl->entries[i].uuid[j];
		}
	}
free_rsp:
	free(rsp);
	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_identify_memdev(struct cxlmi_endpoint *ep,
				   struct cxlmi_cci_identify_memdev *ret)
{
	struct cxlmi_transport_mctp *mctp = ep->transport_data;
	struct cxlmi_cci_identify_memdev *pl;
	struct cxlmi_cci_msg *rsp;
	struct cxlmi_cci_msg req = {
		.category = CXL_MCTP_CATEGORY_REQ,
		.tag = mctp->tag++,
		.command = MEMORY_DEVICE,
		.command_set = IDENTIFY,
		.vendor_ext_status = 0xabcd,
	};
	int rc;
	ssize_t rsp_sz;

	rsp_sz = sizeof(*rsp) + sizeof(*pl);

	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		goto free_rsp;

	pl = (struct cxlmi_cci_identify_memdev *)(rsp->payload);
	*ret = *pl;
free_rsp:
	free(rsp);
	return rc;
}
