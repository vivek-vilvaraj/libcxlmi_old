#ifndef _LIBCXLMI_PRIVATE_H
#define _LIBCXLMI_PRIVATE_H

#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <sys/types.h>

#include <ccan/list/list.h>

enum cxlmi_component_type {
	CXLMI_SWITCH,
	CXLMI_TYPE3,
};

struct cxlmi_ctx {
	FILE *fp;
	int log_level;
	bool log_pid;
	bool log_timestamp;
	struct list_head endpoints; /* all opened mctp-endpoints */
	bool probe_enabled; /* probe upon open, default yes */
};

struct cxlmi_endpoint {
	struct cxlmi_ctx *ctx;
	void *transport_data;
	struct list_node entry;
	unsigned int timeout_ms;
	enum cxlmi_component_type type;
};

#if (LOG_FUNCNAME == 1)
#define __cxlmi_log_func __func__
#else
#define __cxlmi_log_func NULL
#endif

void __attribute__((format(printf, 4, 5)))
__cxlmi_msg(struct cxlmi_ctx *c, int lvl, const char *func, const char *format, ...);

#define cxlmi_msg(c, lvl, format, ...)					\
	do {								\
		if ((lvl) <= MAX_LOGLEVEL)				\
			__cxlmi_msg(c, lvl, __cxlmi_log_func,		\
				   format, ##__VA_ARGS__);		\
	} while (0)

#endif
