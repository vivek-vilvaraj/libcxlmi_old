// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libcxlmi.
 */
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/types.h>
#if HAVE_LINUX_MCTP_H
#include <linux/mctp.h>
#endif
#if HAVE_LINUX_CXL_MEM_H
#include <linux/cxl_mem.h>
#endif

#ifdef CONFIG_DBUS
#include <dbus/dbus.h>
#endif

#include <ccan/array_size/array_size.h>
#include <ccan/minmax/minmax.h>
#include <ccan/endian/endian.h>
#include <ccan/list/list.h>

#include <libcxlmi.h>

#include "private.h"

#if !defined(AF_MCTP)
#define AF_MCTP 45
#endif /* !AF_MCTP */

#if !HAVE_LINUX_MCTP_H
/* As of kernel v5.15, these AF_MCTP-related definitions are provided by
 * linux/mctp.h. Keep this fallback to fail gracefully upon older standard
 * includes.
 * These were all introduced in the same version as AF_MCTP was defined,
 * so we can key off the presence of that.
 */

typedef __u8			mctp_eid_t;

struct mctp_addr {
	mctp_eid_t		s_addr;
};

struct sockaddr_mctp {
	unsigned short int	smctp_family;
	__u16			__smctp_pad0;
	unsigned int		smctp_network;
	struct mctp_addr	smctp_addr;
	__u8			smctp_type;
	__u8			smctp_tag;
	__u8			__smctp_pad1;
};

#define MCTP_NET_ANY		0x0

#define MCTP_ADDR_NULL		0x00
#define MCTP_ADDR_ANY		0xff

#define MCTP_TAG_MASK		0x07
#define MCTP_TAG_OWNER		0x08

#endif /* HAVE_LINUX_MCTP_H */

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
#define MCTP_MAX_TIMEOUT 2000
#define MCTP_TYPE_CXL_CCI 0x8

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
	ep->type = -1;
	list_add(&ctx->endpoints, &ep->entry);

	return ep;
}

static int mctp_check_timeout(struct cxlmi_endpoint *ep,
			      unsigned int timeout_ms)
{
	return timeout_ms > MCTP_MAX_TIMEOUT;
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
	} else {
		close(ep->fd);
		if (ep->devname)
			free(ep->devname);
	}

	list_del(&ep->entry);
	free(ep);
}

static int sanity_check_mctp_rsp(struct cxlmi_endpoint *ep,
			 struct cxlmi_cci_msg *req, struct cxlmi_cci_msg *rsp,
			 size_t len, bool fixed_length, size_t min_length)
{
	uint32_t pl_length;
	struct cxlmi_ctx *ctx = ep->ctx;

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
		if (rsp->return_code != CXLMI_RET_BACKGROUND)
			cxlmi_msg(ctx, LOG_ERR, "Error code in response: %d\n",
				  rsp->return_code);
		return rsp->return_code;
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

	return sanity_check_mctp_rsp(ep, req_msg, rsp_msg, len,
				rsp_msg_sz == rsp_msg_sz_min, rsp_msg_sz_min);
}

static int send_ioctl_direct(struct cxlmi_endpoint *ep,
		      struct cxlmi_cci_msg *req_msg, size_t req_msg_sz,
		      struct cxlmi_cci_msg *rsp_msg, size_t rsp_msg_sz,
		      size_t rsp_msg_sz_min)
{
	int rc, errno_save;
	struct cxlmi_ctx *ctx = ep->ctx;
	struct cxl_send_command cmd = {
		.id = CXL_MEM_COMMAND_ID_RAW,
		.raw.opcode = req_msg->command | (req_msg->command_set << 8),
		/* The payload is the same, but take off the CCI message header */
		.in.size = req_msg_sz - sizeof(*req_msg),
		.in.payload = (__u64)req_msg->payload,
		.out.size = rsp_msg_sz - sizeof(*rsp_msg),
		.out.payload = (__u64)rsp_msg->payload,
	};

	rc = ioctl(ep->fd, CXL_MEM_SEND_COMMAND, &cmd);
	if (rc < 0) {
		errno_save = errno;
		cxlmi_msg(ctx, LOG_ERR, "ioctl failed %d\n", rc);
		goto err;
	}

	if (cmd.retval != 0) {
		if (cmd.retval != CXLMI_RET_BACKGROUND)
			cxlmi_msg(ctx, LOG_ERR,
				  "ioctl returned non zero retval %d\n",
				  cmd.retval);
		return cmd.retval;
	}
	if (cmd.out.size < rsp_msg_sz_min - sizeof(*rsp_msg)) {
		errno_save = errno;
		cxlmi_msg(ctx, LOG_ERR, "ioctl returned too little data\n");
		goto err;

	}

	return 0;
err:
	errno = errno_save;
	return -1;
}

static int send_cmd_cci(struct cxlmi_endpoint *ep,
			struct cxlmi_cci_msg *req_msg, size_t req_msg_sz,
			struct cxlmi_cci_msg *rsp_msg, size_t rsp_msg_sz,
			size_t rsp_msg_sz_min)
{
	int rc;

	if (ep->transport_data) {
		rc = send_mctp_direct(ep, req_msg, req_msg_sz,
				      rsp_msg, rsp_msg_sz, rsp_msg_sz_min);
	} else {
		rc = send_ioctl_direct(ep, req_msg, req_msg_sz,
				       rsp_msg, rsp_msg_sz, rsp_msg_sz_min);
	}

	return rc;
}

CXLMI_EXPORT void cxlmi_set_probe_enabled(struct cxlmi_ctx *ctx, bool enabled)
{
	ctx->probe_enabled = enabled;
}

/* probe cxl component for basic device info */
static void endpoint_probe(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_identify id;

	if (!ep->ctx->probe_enabled)
		return;

	if (cxlmi_cmd_identify(ep, &id))
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
		ep->type = -1;
		break;
	}
}

CXLMI_EXPORT struct cxlmi_endpoint *cxlmi_open_mctp(struct cxlmi_ctx *ctx,
					    unsigned int netid, uint8_t eid)
{
	struct cxlmi_endpoint *ep, *tmp;
	struct cxlmi_transport_mctp *mctp;
	int errno_save;
	struct sockaddr_mctp cci_addr = {
		.smctp_family = AF_MCTP,
		.smctp_network = netid,
		.smctp_addr.s_addr = eid,
		.smctp_type = MCTP_TYPE_CXL_CCI,
		.smctp_tag = MCTP_TAG_OWNER,
	};

	/* ensure no duplicates */
	cxlmi_for_each_endpoint(ctx, tmp) {
		if (tmp->transport_data) {
			struct cxlmi_transport_mctp *mctp = tmp->transport_data;

			if (mctp->net == netid && mctp->eid == eid) {
				cxlmi_msg(ctx, LOG_ERR,
					  "mctp endpoint %d:%d already open\n",
					  netid, eid);
				return NULL;
			}
		}
	}

	ep = init_endpoint(ctx);
	if (!ep)
		return NULL;

	mctp = calloc(1, sizeof(*mctp));
	if (!mctp) {
		errno_save = errno;
		goto err_close_ep;
	}

	mctp->net = netid;
	mctp->eid = eid;
	mctp->addr = cci_addr;

	mctp->sd = socket(AF_MCTP, SOCK_DGRAM, 0);
	if (mctp->sd < 0) {
		errno_save = errno;
		cxlmi_msg(ctx, LOG_ERR,
			  "cannot open socket for mctp endpoint %d:%d\n",
			  netid, eid);
		goto err_free_mctp;
	}
	if (bind(mctp->sd,
		 (struct sockaddr *)&cci_addr, sizeof(cci_addr))) {
		errno_save = errno;
		cxlmi_msg(ctx, LOG_ERR,
			  "cannot bind for mctp endpoint %d:%d\n", netid, eid);
		goto err_free_mctp;
	}

	ep->transport_data = mctp;
	ep->timeout_ms = MCTP_MAX_TIMEOUT;
	endpoint_probe(ep);

	return ep;

err_free_mctp:
	free(mctp);
err_close_ep:
	cxlmi_close(ep);
	errno = errno_save;
	return NULL;
}

#ifdef CONFIG_DBUS

#define MCTP_DBUS_PATH "/xyz/openbmc_project/mctp"
#define MCTP_DBUS_IFACE "xyz.openbmc_project.MCTP"
#define MCTP_DBUS_IFACE_ENDPOINT "xyz.openbmc_project.MCTP.Endpoint"

static int cxlmi_mctp_add(struct cxlmi_ctx *ctx, unsigned int netid, __u8 eid)
{
	struct cxlmi_endpoint *ep = NULL;

	ep = cxlmi_open_mctp(ctx, netid, eid);
	if (!ep)
		return -1;

	return 0;
}

static bool dbus_object_is_type(DBusMessageIter *obj, int type)
{
	return dbus_message_iter_get_arg_type(obj) == type;
}

static bool dbus_object_is_dict(DBusMessageIter *obj)
{
	return dbus_object_is_type(obj, DBUS_TYPE_ARRAY) &&
		dbus_message_iter_get_element_type(obj) == DBUS_TYPE_DICT_ENTRY;
}

static int read_variant_basic(DBusMessageIter *var, int type, void *val)
{
	if (!dbus_object_is_type(var, type))
		return -1;

	dbus_message_iter_get_basic(var, val);

	return 0;
}

static bool has_message_type(DBusMessageIter *prop, uint8_t type)
{
	DBusMessageIter inner;
	uint8_t *types;
	int i, n;

	if (!dbus_object_is_type(prop, DBUS_TYPE_ARRAY) ||
	    dbus_message_iter_get_element_type(prop) != DBUS_TYPE_BYTE)
		return false;

	dbus_message_iter_recurse(prop, &inner);

	dbus_message_iter_get_fixed_array(&inner, &types, &n);

	for (i = 0; i < n; i++) {
		if (types[i] == type)
			return true;
	}

	return false;
}

static int handle_mctp_endpoint(struct cxlmi_ctx *ctx, const char* objpath,
				DBusMessageIter *props, int *opened)
{
	bool have_eid = false, have_net = false, have_cxlmi = false;
	mctp_eid_t eid;
	int net, rc;

	/* for each property */
	for (;;) {
		DBusMessageIter prop, val;
		const char *propname;

		dbus_message_iter_recurse(props, &prop);

		if (!dbus_object_is_type(&prop, DBUS_TYPE_STRING)) {
			cxlmi_msg(ctx, LOG_ERR,
				 "error unmashalling object (propname)\n");
			return -1;
		}

		dbus_message_iter_get_basic(&prop, &propname);

		dbus_message_iter_next(&prop);

		if (!dbus_object_is_type(&prop, DBUS_TYPE_VARIANT)) {
			cxlmi_msg(ctx, LOG_ERR,
				 "error unmashalling object (propval)\n");
			return -1;
		}

		dbus_message_iter_recurse(&prop, &val);

		printf("propname::: %s\n\n", propname);

		if (!strcmp(propname, "EID")) {
			rc = read_variant_basic(&val, DBUS_TYPE_BYTE, &eid);
			have_eid = true;

		} else if (!strcmp(propname, "NetworkId")) {
			rc = read_variant_basic(&val, DBUS_TYPE_INT32, &net);
			have_net = true;

		} else if (!strcmp(propname, "SupportedMessageTypes")) {
			have_cxlmi = has_message_type(&val, MCTP_TYPE_CXL_CCI);
		}

		if (rc)
			return rc;

		if (!dbus_message_iter_next(props))
			break;
	}

	if (have_cxlmi) {
		if (!(have_eid && have_net)) {
			cxlmi_msg(ctx, LOG_ERR,
				 "Missing property for %s\n", objpath);
			errno = ENOENT;
			return -1;
		}
		rc = cxlmi_mctp_add(ctx, net, eid);
		if (rc < 0) {
			int errno_save = errno;
			cxlmi_msg(ctx, LOG_ERR,
				 "Error adding net %d eid %d: %m\n", net, eid);
			errno = errno_save;
		} else
			*opened = 1;
	} else {
		/* Ignore other endpoints */
		rc = 0;
	}
	return rc;
}

/* obj is an array of (object path, interfaces) dict entries - ie., dbus type
 *   a{oa{sa{sv}}}
 */
static int handle_mctp_obj(struct cxlmi_ctx *ctx, DBusMessageIter *obj,
			   int *opened)
{
	const char *objpath = NULL;
	DBusMessageIter intfs;

	*opened = 0;

	if (!dbus_object_is_type(obj, DBUS_TYPE_OBJECT_PATH)) {
		cxlmi_msg(ctx, LOG_ERR, "error unmashalling object (path)\n");
		return -1;
	}

	dbus_message_iter_get_basic(obj, &objpath);

	dbus_message_iter_next(obj);

	if (!dbus_object_is_dict(obj)) {
		cxlmi_msg(ctx, LOG_ERR, "error unmashalling object (intfs)\n");
		return -1;
	}

	dbus_message_iter_recurse(obj, &intfs);

	/* for each interface */
	for (;;) {
		DBusMessageIter props, intf;
		const char *intfname;

		dbus_message_iter_recurse(&intfs, &intf);

		if (!dbus_object_is_type(&intf, DBUS_TYPE_STRING)) {
			cxlmi_msg(ctx, LOG_ERR,
				 "error unmashalling object (intf)\n");
			return -1;
		}

		dbus_message_iter_get_basic(&intf, &intfname);

		if (strcmp(intfname, MCTP_DBUS_IFACE_ENDPOINT)) {
			if (!dbus_message_iter_next(&intfs))
				break;
			continue;
		}

		dbus_message_iter_next(&intf);

		if (!dbus_object_is_dict(&intf)) {
			cxlmi_msg(ctx, LOG_ERR,
				 "error unmarshalling object (props)\n");
			return -1;
		}

		dbus_message_iter_recurse(&intf, &props);
		return handle_mctp_endpoint(ctx, objpath, &props, opened);
	}

	return 0;
}

int cxlmi_scan_mctp(struct cxlmi_ctx *ctx)
{
	DBusMessage *msg, *resp = NULL;
	DBusConnection *bus = NULL;
	DBusMessageIter args, objs;
	dbus_bool_t drc;
	DBusError berr;
	int errno_save, nopen = 0, rc = -1;

	dbus_error_init(&berr);

	bus = dbus_bus_get(DBUS_BUS_SYSTEM, &berr);
	if (!bus) {
		cxlmi_msg(ctx, LOG_ERR, "Failed connecting to D-Bus: %s (%s)\n",
			  berr.message, berr.name);
		return -1;
	}

	msg = dbus_message_new_method_call(MCTP_DBUS_IFACE,
					   MCTP_DBUS_PATH,
					   "org.freedesktop.DBus.ObjectManager",
					   "GetManagedObjects");
	if (!msg) {
		cxlmi_msg(ctx, LOG_ERR, "Failed creating call message\n");
		return -1;
	}

	resp = dbus_connection_send_with_reply_and_block(bus, msg,
							 DBUS_TIMEOUT_USE_DEFAULT,
							 &berr);
	dbus_message_unref(msg);
	if (!resp) {
		cxlmi_msg(ctx, LOG_ERR, "Failed querying MCTP D-Bus: %s (%s)\n",
			  berr.message, berr.name);
		goto out;
	}

	/* argument container */
	drc = dbus_message_iter_init(resp, &args);
	if (!drc) {
		cxlmi_msg(ctx, LOG_ERR, "can't read dbus reply args\n");
		goto out;
	}

	if (!dbus_object_is_dict(&args)) {
		cxlmi_msg(ctx, LOG_ERR, "error unmashalling args\n");
		goto out;
	}

	/* objects container */
	dbus_message_iter_recurse(&args, &objs);

	rc = 0;

	do {
		DBusMessageIter ent;
		int opened;

		dbus_message_iter_recurse(&objs, &ent);

		rc = handle_mctp_obj(ctx, &ent, &opened);
		if (rc)
			break;

		nopen += opened;
	} while (dbus_message_iter_next(&objs));

out:
	errno_save = errno;
	if (resp)
		dbus_message_unref(resp);
	if (bus)
		dbus_connection_unref(bus);
	dbus_error_free(&berr);

	if (rc < 0)
		errno = errno_save;

	return nopen;
}

#else /* CONFIG_DBUS */

int cxlmi_scan_mctp(struct cxlmi_ctx *ctx)
{
	return 0;
}

#endif /* CONFIG_DBUS */

CXLMI_EXPORT struct cxlmi_endpoint *cxlmi_open(struct cxlmi_ctx *ctx,
					       const char *devname)
{
	struct cxlmi_endpoint *ep, *tmp;
	int errno_save;
	char filename[40];

	/* ensure no duplicates */
	cxlmi_for_each_endpoint(ctx, tmp) {
		if (!strcmp(tmp->devname, devname)) {
			cxlmi_msg(ctx, LOG_ERR,
				  "endpoint '%s' already open\n",
				  devname);
			return NULL;
		}
	}

	ep = init_endpoint(ctx);
	if (!ep)
		return NULL;

	if (!strncmp(devname, "switch", strlen("switch")))
		ep->type = CXLMI_SWITCH;
	else if (!strncmp(devname, "mem", strlen("mem")))
		ep->type = CXLMI_TYPE3;
	else
		ep->type = -1;

	snprintf(filename, sizeof(filename), "/dev/cxl/%s", devname);

	ep->fd = open(filename, O_RDWR);
	if (ep->fd < 0) {
		errno_save = errno;
		cxlmi_msg(ctx, LOG_ERR, "could not open %s\n", devname);
		goto err_close_ep;
	}

	ep->devname = strdup(devname);
	if (!ep->devname) {
		errno_save = errno;
		goto err_close_ep;
	}

	return ep;
err_close_ep:
	cxlmi_close(ep);
	errno = errno_save;
	return NULL;
}

static const char *const cxlmi_cmd_retcode_tbl[] = {
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
	[CXLMI_RET_LOG] = "invalid or unsupported log page",
	[CXLMI_RET_INTERRUPTED] = "asynchronous event occured",
	[CXLMI_RET_FEATUREVERSION] = "unsupported feature version",
	[CXLMI_RET_FEATURESELVALUE] = "unsupported feature selection value",
	[CXLMI_RET_FEATURETRANSFERIP] = "feature transfer in progress",
	[CXLMI_RET_FEATURETRANSFEROOO] = "feature transfer out of order",
	[CXLMI_RET_RESOURCEEXHAUSTED] = "resources are exhausted",
	[CXLMI_RET_EXTLIST] = "invalid Extent List",
	[CXLMI_RET_TRANSFEROOO] = "transfer out of order",
	[CXLMI_RET_NO_BGABORT] = "on-going background cmd is not abortable",
};

CXLMI_EXPORT const char *cxlmi_cmd_retcode_tostr(enum cxlmi_cmd_retcode code)
{
	if (code > ARRAY_SIZE(cxlmi_cmd_retcode_tbl) - 1)
		return NULL;

	return cxlmi_cmd_retcode_tbl[code];
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

static void arm_cci_request(struct cxlmi_endpoint *ep, struct cxlmi_cci_msg *req,
			   size_t req_pl_sz, uint8_t cmdset, uint8_t cmd)
{
	if (ep->transport_data) {
		struct cxlmi_transport_mctp *mctp = ep->transport_data;

		*req = (struct cxlmi_cci_msg) {
			.category = CXL_MCTP_CATEGORY_REQ,
			.tag = mctp->tag++,
			.command = cmd,
			.command_set = cmdset,
			.vendor_ext_status = 0xabcd,
		};

		if (req_pl_sz) {
			req->pl_length[0] = req_pl_sz & 0xff;
			req->pl_length[1] = (req_pl_sz >> 8) & 0xff;
			req->pl_length[2] = (req_pl_sz >> 16) & 0xff;
		}
	} else {
		/* while CCIs arent sent directly over ioctl, add general info */
		*req = (struct cxlmi_cci_msg) {
			.command = cmd,
			.command_set = cmdset,
			.vendor_ext_status = 0xabcd,
		};
	}
}

CXLMI_EXPORT int cxlmi_cmd_identify(struct cxlmi_endpoint *ep,
				    struct cxlmi_cmd_identify *ret)
{
	int rc;
	ssize_t rsp_sz;
	struct cxlmi_cmd_identify *rsp_pl;
	struct cxlmi_cci_msg req, *rsp;

	arm_cci_request(ep, &req, 0, INFOSTAT, IS_IDENTIFY);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		goto done;

	rsp_pl = (struct cxlmi_cmd_identify *)rsp->payload;

	ret->vendor_id = le16_to_cpu(rsp_pl->vendor_id);
	ret->device_id = le16_to_cpu(rsp_pl->device_id);
	ret->subsys_vendor_id = le16_to_cpu(rsp_pl->subsys_vendor_id);
	ret->subsys_id = le16_to_cpu(rsp_pl->subsys_id);
	ret->serial_num = le64_to_cpu(rsp_pl->serial_num);
	ret->max_msg_size = rsp_pl->max_msg_size;
	ret->component_type = rsp_pl->component_type;
done:
	free(rsp);
	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_bg_op_status(struct cxlmi_endpoint *ep,
				struct cxlmi_cmd_bg_op_status *ret)
{
	struct cxlmi_cmd_bg_op_status *rsp_pl;
	struct cxlmi_cci_msg req, *rsp;
	ssize_t rsp_sz;
	int rc;

	arm_cci_request(ep, &req, 0, INFOSTAT, BACKGROUND_OPERATION_STATUS);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		goto done;

	rsp_pl = (struct cxlmi_cmd_bg_op_status *)rsp->payload;
	ret->status = rsp_pl->status;
	ret->opcode = le16_to_cpu(rsp_pl->opcode);
	ret->returncode = le16_to_cpu(rsp_pl->returncode);
	ret->vendor_ext_status = le16_to_cpu(rsp_pl->vendor_ext_status);
done:
	free(rsp);
	return rc;
}


CXLMI_EXPORT int cxlmi_cmd_request_bg_op_abort(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cci_msg req, rsp;

	arm_cci_request(ep, &req, 0, INFOSTAT, BACKGROUND_OPERATION_ABORT);

	return send_cmd_cci(ep, &req, sizeof(req),
			    &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int cxlmi_cmd_get_timestamp(struct cxlmi_endpoint *ep,
					 struct cxlmi_cmd_get_timestamp *ret)
{
	struct cxlmi_cmd_get_timestamp *rsp_pl;
	struct cxlmi_cci_msg req, *rsp;
	ssize_t rsp_sz;
	int rc;

	arm_cci_request(ep, &req, 0, TIMESTAMP, GET);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		goto done;

	rsp_pl = (struct cxlmi_cmd_get_timestamp *)rsp->payload;
	ret->timestamp = le64_to_cpu(rsp_pl->timestamp);
done:
	free(rsp);
	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_set_timestamp(struct cxlmi_endpoint *ep,
					 struct cxlmi_cmd_set_timestamp *in)
{
	struct cxlmi_cmd_set_timestamp *req_pl;
	struct cxlmi_cci_msg *req, rsp;
	size_t req_sz;
	int rc = 0;

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*in), TIMESTAMP, SET);

	req_pl = (struct cxlmi_cmd_set_timestamp *)req->payload;
	req_pl->timestamp = cpu_to_le64(in->timestamp);

	rc = send_cmd_cci(ep, req, req_sz,
			  &rsp, sizeof(rsp), sizeof(rsp));
	free(req);
	return rc;
}

static const int maxlogs = 10; /* Only 7 in CXL r3.1 but let us leave room */
CXLMI_EXPORT int cxlmi_cmd_get_supported_logs(struct cxlmi_endpoint *ep,
				      struct cxlmi_cmd_get_supported_logs *ret)
{
	struct cxlmi_cmd_get_supported_logs *rsp_pl;
	struct cxlmi_cci_msg req, *rsp;
	int rc, i;
	ssize_t rsp_sz;

	arm_cci_request(ep, &req, 0, LOGS, GET_SUPPORTED);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl) + maxlogs * sizeof(*rsp_pl->entries);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, &req, sizeof(req), rsp, rsp_sz,
			  sizeof(*rsp) + sizeof(*rsp_pl));
	if (rc)
		goto done;

	rsp_pl = (struct cxlmi_cmd_get_supported_logs *)rsp->payload;
	memset(ret, 0, sizeof(*ret));

	ret->num_supported_log_entries =
		le16_to_cpu(rsp_pl->num_supported_log_entries);

	for (i = 0; i < rsp_pl->num_supported_log_entries; i++) {
		memcpy(ret->entries[i].uuid, rsp_pl->entries[i].uuid,
		       sizeof(rsp_pl->entries[i].uuid));
		ret->entries[i].log_size =
			le32_to_cpu(rsp_pl->entries[i].log_size);
	}
done:
	free(rsp);
	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_get_log_cel(struct cxlmi_endpoint *ep,
				       struct cxlmi_cmd_get_log *in,
				       struct cxlmi_cmd_get_log_cel_rsp *ret)
{
	struct cxlmi_cmd_get_log *req_pl;
	struct cxlmi_cmd_get_log_cel_rsp *rsp_pl;
	struct cxlmi_cci_msg *req, *rsp;
	ssize_t req_sz, rsp_sz;
	int i, rc = -1;

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*req_pl), LOGS, GET_LOG);
	req_pl = (struct cxlmi_cmd_get_log *)req->payload;

	req_pl->offset = cpu_to_le32(in->offset);
	req_pl->length = cpu_to_le32(in->length);
	memcpy(req_pl->uuid, in->uuid, sizeof(in->uuid));

	rsp_sz = sizeof(*rsp) + in->length;
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		goto done_free_req;

	rc = send_cmd_cci(ep, req, req_sz, rsp, rsp_sz, rsp_sz);
	if (rc)
		goto done_free;

	rsp_pl = (struct cxlmi_cmd_get_log_cel_rsp *)rsp->payload;
	memset(ret, 0, sizeof(*ret));

	for (i = 0; i < in->length / sizeof(*rsp_pl); i++) {
		ret[i].opcode = le16_to_cpu(rsp_pl[i].opcode);
		ret[i].command_effect =
			le16_to_cpu(rsp_pl[i].command_effect);
	}
done_free:
	free(rsp);
done_free_req:
	free(req);
	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_memdev_identify(struct cxlmi_endpoint *ep,
				   struct cxlmi_cmd_memdev_identify *ret)
{
	struct cxlmi_cmd_memdev_identify *rsp_pl;
	struct cxlmi_cci_msg req, *rsp;
	int rc;
	ssize_t rsp_sz;

	arm_cci_request(ep, &req, 0, IDENTIFY, MEMORY_DEVICE);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);

	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		goto done;

	rsp_pl = (struct cxlmi_cmd_memdev_identify *)rsp->payload;
	memset(ret, 0, sizeof(*ret));

	memcpy(ret->fw_revision, rsp_pl->fw_revision,
	       sizeof(rsp_pl->fw_revision));
	ret->total_capacity = le64_to_cpu(rsp_pl->total_capacity);
	ret->volatile_capacity = le64_to_cpu(rsp_pl->volatile_capacity);
	ret->persistent_capacity = le64_to_cpu(rsp_pl->persistent_capacity);
	ret->partition_align = le64_to_cpu(rsp_pl->partition_align);
	ret->info_event_log_size = le16_to_cpu(rsp_pl->info_event_log_size);
	ret->warning_event_log_size = le16_to_cpu(rsp_pl->warning_event_log_size);
	ret->failure_event_log_size = le16_to_cpu(rsp_pl->failure_event_log_size);
	ret->fatal_event_log_size = le16_to_cpu(rsp_pl->fatal_event_log_size);
	ret->lsa_size = le32_to_cpu(rsp_pl->lsa_size);
	/* TODO unaligned ie: get_unaligned_le24(rsp_pl->poison_list_max_mer); */
	memcpy(ret->poison_list_max_mer, rsp_pl->poison_list_max_mer,
	       sizeof(rsp_pl->poison_list_max_mer));
	ret->inject_poison_limit = le16_to_cpu(rsp_pl->inject_poison_limit);
	ret->poison_caps = rsp_pl->poison_caps;
	ret->qos_telemetry_caps = rsp_pl->qos_telemetry_caps;
	ret->dc_event_log_size = le16_to_cpu(rsp_pl->dc_event_log_size);
done:
	free(rsp);
	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_memdev_sanitize(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cci_msg req, rsp;

	arm_cci_request(ep, &req, 0, SANITIZE, SANITIZE);

	return send_cmd_cci(ep, &req, sizeof(req),
			    &rsp, sizeof(rsp), sizeof(rsp));
}
