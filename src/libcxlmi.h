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
struct cxlmi_ctx * cxlmi_new_ctx(FILE *fp, int loglvl);

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

/*
 * Definitions for Generic Component Commands, per CXL r3.1 Table 8-37.
 */
int cxlmi_query_cci_identify(struct cxlmi_endpoint *ep,
			     struct cxlmi_cci_infostat_identify *ret);
int cxlmi_request_bg_operation_abort(struct cxlmi_endpoint *ep);

int cxlmi_query_cci_timestamp(struct cxlmi_endpoint *ep,
			      struct cxlmi_cci_get_timestamp *ret);

#ifdef __cplusplus
}
#endif
#endif
