#ifndef _LIBCXLMI_PRIVATE_H
#define _LIBCXLMI_PRIVATE_H

#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/types.h>

#include <linux/mctp.h>

#include <ccan/list/list.h>

#define CXLMI_EXPORT __attribute__ ((visibility("default")))

/* define cmd-set and cmds, ala qemu */
enum {
    INFOSTAT    = 0x00,
	#define IS_IDENTIFY   0x1
	#define BACKGROUND_OPERATION_STATUS    0x2
	#define GET_RESP_MSG_LIMIT             003
	#define SET_RSP_MSG_LIMIT              0x4
	#define BACKGROUND_OPERATION_ABORT     0x5
    EVENTS      = 0x01,
	#define GET_RECORDS     0x0
	#define CLEAR_RECORDS   0x1
	#define GET_INTERRUPT_POLICY   0x2
	#define SET_INTERRUPT_POLICY   0x3
    FIRMWARE_UPDATE = 0x02,
	#define GET_INFO      0x0
    TIMESTAMP   = 0x03,
	#define GET           0x0
	#define SET           0x1
    LOGS        = 0x04,
	#define GET_SUPPORTED 0x0
	#define GET_LOG       0x1
	#define GET_LOG_CAPS  0x2
	#define CLEAR_LOG     0x3
	#define POPULATE_LOG  0x4
	#define GET_SUPPORTED_SUBULIST 0x5
    IDENTIFY    = 0x40,
	#define MEMORY_DEVICE 0x0
    CCLS        = 0x41,
	#define GET_PARTITION_INFO     0x0
	#define GET_LSA       0x2
	#define SET_LSA       0x3
    SANITIZE    = 0x44,
	#define SANITIZE      0x0
	#define SECURE_ERASE  0x1
    PERSISTENT_MEM = 0x45,
	#define GET_SECURITY_STATE     0x0
    MEDIA_AND_POISON = 0x43,
	#define GET_POISON_LIST        0x0
	#define INJECT_POISON          0x1
	#define CLEAR_POISON           0x2
	#define GET_SCAN_MEDIA_CAPABILITIES 0x3
	#define SCAN_MEDIA             0x4
	#define GET_SCAN_MEDIA_RESULTS 0x5
    DCD_CONFIG  = 0x48,
	#define GET_DC_CONFIG          0x0
	#define GET_DYN_CAP_EXT_LIST   0x1
	#define ADD_DYN_CAP_RSP        0x2
	#define RELEASE_DYN_CAP        0x3
    PHYSICAL_SWITCH = 0x51,
	#define IDENTIFY_SWITCH_DEVICE      0x0
	#define GET_PHYSICAL_PORT_STATE     0x1
    TUNNEL = 0x53,
	#define MANAGEMENT_COMMAND     0x0
    MHD = 0x55,
	#define GET_MHD_INFO 0x0
    DCD_MANAGEMENT = 0x56
	#define GET_DCD_INFO 0x0
	#define GET_HOST_DC_REGION_CONFIG 0x1
	#define SET_DC_REGION_CONFIG 0x2
	#define GET_DC_REGION_EXTENT_LIST 0x3
	#define INITIATE_DC_ADD 0x4
	#define INITIATE_DC_RELEASE 0x5
};

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

enum cxlmi_component_type {
	CXLMI_SWITCH,
	CXLMI_TYPE3,
};

struct cxlmi_ctx {
	FILE *fp;
	int log_level;
	bool log_pid;
	bool log_timestamp;
	struct list_head endpoints; /* all opened endpoints */
	bool probe_enabled; /* probe upon open, default yes */
};

struct cxlmi_endpoint {
	struct cxlmi_ctx *ctx;

	/* mctp */
	void *transport_data;

	/* ioctl (primary mbox) */
	int fd;
	char *devname;

	struct list_node entry;
	unsigned int timeout_ms;
	int type;
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

#endif /* _LIBCXLMI_PRIVATE_H */
