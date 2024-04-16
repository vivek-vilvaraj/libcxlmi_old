#ifndef __LIBCXLMI_H__
#define __LIBCXLMI_H__

#include "cxlmi/api-types.h"
#include "cxlmi/log.h"

#ifdef __cplusplus
extern "C" {
#endif

struct cxlmi_ctx;
struct cxlmi_endpoint;

/**
 * cxlmi_new_ctx() - Create top-level MI context handle.
 * @fp:		File descriptor for logging messages
 * @log_level:	Logging level to use (standard syslog)
 *
 * Create the top-level library handle for creating subsequent
 * endpointobjects.
 *
 * Return: new context object, or NULL on failure.
 *
 * See &cxlmi_free_ctx.
 */
struct cxlmi_ctx * cxlmi_new_ctx(FILE *fp, int log_level);

/**
 * cxlmi_free_ctx() - Free context object.
 * @ctx: context to free
 *
 * See &cxlmi_new_ctx.
 */
void cxlmi_free_ctx(struct cxlmi_ctx *ctx);

/**
 * cxlmi_open_mctp() - Create an endpoint using a MCTP connection.
 * @ctx: library context object to create under
 * @netid: MCTP network ID on this system
 * @eid: MCTP endpoint ID
 *
 * Transport-specific endpoint initialization for MI-connected endpoints.
 *
 * Return: New endpoint object for @netid & @eid, or NULL on failure.
 *
 * See &cxlmi_close
 */
struct cxlmi_endpoint *cxlmi_open_mctp(struct cxlmi_ctx *ctx,
				       unsigned int net, uint8_t eid);

/**
 * cxlmi_close() - Close an endpoint connection and release resources
 *
 * @ep: Endpoint object to close
 */
void cxlmi_close(struct cxlmi_endpoint *ep);

/**
 * cxlmi_set_probe_enabled() - enable/disable the probe for new endpoints
 * @ctx: &cxlmi_ctx object
 * @enabled: whether to probe new endpoints
 *
 * Controls whether newly-created endpoints are probed upon creation.
 * Defaults to enabled, which results in some initial messaging with the
 * endpoint to determine model-specific details, such as CXL component type.
 */
void cxlmi_set_probe_enabled(struct cxlmi_ctx *ctx, bool enabled);

/**
 * cxlmi_endpoint_get_timeout - get the current timeout value for CXL-MI
 * responses
 * @ep: MI endpoint object
 *
 * Returns the current timeout value, in milliseconds, for this endpoint.
 */
unsigned int cxlmi_endpoint_get_timeout(struct cxlmi_endpoint *ep);

/**
 * cxlmi_endpoint_set_timeout - set a timeout for CXL-MI responses
 * @ep: MI endpoint object
 * @timeout_ms: Timeout for MI responses, given in milliseconds
 */
int cxlmi_endpoint_set_timeout(struct cxlmi_endpoint *ep,
			       unsigned int timeout_ms);

/**
 * cxlmi_first_endpoint - Start endpoint iterator
 * @m: &cxlmi_ctx object
 *
 * Return: first MI endpoint object under this context, or NULL if no endpoints
 *         are present.
 *
 * See: &cxlmi_next_endpoint, &cxlmi_for_each_endpoint
 */
struct cxlmi_endpoint *cxlmi_first_endpoint(struct cxlmi_ctx *m);

/**
 * cxlmi_next_endpoint - Continue endpoint iterator
 * @m: &cxlmi_ctx object
 * @e: &cxlmi_endpoint current position of iterator
 *
 * Return: next endpoint MI endpoint object after @e under this root, or NULL
 *         if no further endpoints are present.
 *
 * See: &cxlmi_first_endpoint, &cxlmi_for_each_endpoint
 */
 struct cxlmi_endpoint *cxlmi_next_endpoint(struct cxlmi_ctx *m,
					    struct cxlmi_endpoint * ep);
/**
 * cxlmi_for_each_endpoint - Iterator for CXL-MI endpoints.
 * @m: &cxlmi_ctx containing endpoints
 * @e: &cxlmi_endpoint object, set on each iteration
 */
#define cxlmi_for_each_endpoint(m, e)			\
	for (e = cxlmi_first_endpoint(m); e != NULL;	\
	     e = cxlmi_next_endpoint(m, e))

/**
 * cxlmi_for_each_endpoint_safe - Iterator for CXL-MI endpoints, allowing
 * deletion during traversal
 * @m: &cxlmi_ctx containing endpoints
 * @e: &cxlmi_endpoint object, set on each iteration
 * @_e: &cxlmi_endpoint object used as temporary storage
 */
#define cxlmi_for_each_endpoint_safe(m, e, _e)				\
	for (e = cxlmi_first_endpoint(m), _e = cxlmi_next_endpoint(m, e); \
	     e != NULL;							\
	     e = _e, _e = cxlmi_next_endpoint(m, e))


enum cxlmi_cmd_retcode {
	CXLMI_RET_SUCCESS = 0x0,
	CXLMI_RET_BACKGROUND,
	CXLMI_RET_INPUT,
	CXLMI_RET_UNSUPPORTED,
	CXLMI_RET_INTERNAL,
	CXLMI_RET_RETRY,
	CXLMI_RET_BUSY,
	CXLMI_RET_MEDIADISABLED,
	CXLMI_RET_FWINPROGRESS,
	CXLMI_RET_FWOOO,
	CXLMI_RET_FWAUTH,
	CXLMI_RET_FWSLOT,
	CXLMI_RET_FWROLLBACK,
	CXLMI_RET_FWRESET,
	CXLMI_RET_HANDLE,
	CXLMI_RET_PADDR,
	CXLMI_RET_POISONLMT,
	CXLMI_RET_MEDIAFAILURE,
	CXLMI_RET_ABORT,
	CXLMI_RET_SECURITY,
	CXLMI_RET_PASSPHRASE,
	CXLMI_RET_MBUNSUPPORTED,
	CXLMI_RET_PAYLOADLEN,
	CXLMI_RET_LOG,
	CXLMI_RET_INTERRUPTED,
	CXLMI_RET_FEATUREVERSION,
	CXLMI_RET_FEATURESELVALUE,
	CXLMI_RET_FEATURETRANSFERIP,
	CXLMI_RET_FEATURETRANSFEROOO,
	CXLMI_RET_RESOURCEEXHAUSTED,
	CXLMI_RET_EXTLIST,
};

/**
 * cxlmi_cmd_retcode_tostr - Convert a CXL-defined return code to a string
 * @code: &cxlmi_cmd_retcode return code.
 *
 * Return: a string describing the return code, otherwise NULL if undefined.
 */
 const char *cxlmi_cmd_retcode_tostr(uint16_t code);

/*
 * Definitions for Generic Component Commands, per CXL r3.1 Table 8-37.
 */
int cxlmi_cmd_infostat_identify(struct cxlmi_endpoint *ep,
				struct cxlmi_cci_infostat_identify *ret);

int cxlmi_cmd_request_bg_operation_abort(struct cxlmi_endpoint *ep);

int cxlmi_cmd_get_timestamp(struct cxlmi_endpoint *ep,
			    struct cxlmi_cci_get_timestamp *ret);
int cxlmi_cmd_set_timestamp(struct cxlmi_endpoint *ep,
			    struct cxlmi_cci_set_timestamp *in);

int cxlmi_cmd_get_supported_logs(struct cxlmi_endpoint *ep,
				 struct cxlmi_cci_get_supported_logs *ret);

/*
 * Definitions for Memory Device Commands, per CXL 3.1 Table 8-126
 */
int cxlmi_cmd_identify_memdev(struct cxlmi_endpoint *ep,
			      struct cxlmi_cci_identify_memdev *ret);

#ifdef __cplusplus
}
#endif
#endif
