// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libcxlmi.
 */
#include <stdlib.h>

#include <ccan/endian/endian.h>

#include <libcxlmi.h>

#include "private.h"

CXLMI_EXPORT int cxlmi_cmd_identify(struct cxlmi_endpoint *ep,
				    struct cxlmi_tunnel_info *ti,
				    struct cxlmi_cmd_identify *ret)
{
	int rc;
	ssize_t rsp_sz;
	struct cxlmi_cmd_identify *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;

	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 18);

	arm_cci_request(ep, &req, 0, INFOSTAT, IS_IDENTIFY);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_identify *)rsp->payload;

	ret->vendor_id = le16_to_cpu(rsp_pl->vendor_id);
	ret->device_id = le16_to_cpu(rsp_pl->device_id);
	ret->subsys_vendor_id = le16_to_cpu(rsp_pl->subsys_vendor_id);
	ret->subsys_id = le16_to_cpu(rsp_pl->subsys_id);
	ret->serial_num = le64_to_cpu(rsp_pl->serial_num);
	ret->max_msg_size = rsp_pl->max_msg_size;
	ret->component_type = rsp_pl->component_type;

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_bg_op_status(struct cxlmi_endpoint *ep,
				struct cxlmi_tunnel_info *ti,
				struct cxlmi_cmd_bg_op_status *ret)
{
	struct cxlmi_cmd_bg_op_status *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t rsp_sz;
	int rc;

	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 8);

	arm_cci_request(ep, &req, 0, INFOSTAT, BACKGROUND_OPERATION_STATUS);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_bg_op_status *)rsp->payload;
	ret->status = rsp_pl->status;
	ret->opcode = le16_to_cpu(rsp_pl->opcode);
	ret->returncode = le16_to_cpu(rsp_pl->returncode);
	ret->vendor_ext_status = le16_to_cpu(rsp_pl->vendor_ext_status);

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_get_response_msg_limit(struct cxlmi_endpoint *ep,
				  struct cxlmi_tunnel_info *ti,
				  struct cxlmi_cmd_get_response_msg_limit *ret)
{
	struct cxlmi_cmd_get_response_msg_limit *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t rsp_sz;
	int rc;

	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 1);

	arm_cci_request(ep, &req, 0, INFOSTAT, GET_RESP_MSG_LIMIT);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_get_response_msg_limit *)rsp->payload;
	ret->limit = rsp_pl->limit;

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_set_response_msg_limit(struct cxlmi_endpoint *ep,
					  struct cxlmi_tunnel_info *ti,
					  struct cxlmi_cmd_set_response_msg_limit *in)
{
	struct cxlmi_cmd_get_response_msg_limit *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	size_t req_sz;
	int rc = 0;

	CXLMI_BUILD_BUG_ON(sizeof(*in) != 1);

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*in), INFOSTAT, SET_RESP_MSG_LIMIT);

	req_pl = (struct cxlmi_cmd_get_response_msg_limit *)req->payload;
	req_pl->limit = in->limit;

	rc = send_cmd_cci(ep, ti, req, req_sz, &rsp, sizeof(rsp), sizeof(rsp));
	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_request_bg_op_abort(struct cxlmi_endpoint *ep,
					       struct cxlmi_tunnel_info *ti)
{
	struct cxlmi_cci_msg req, rsp;

	arm_cci_request(ep, &req, 0, INFOSTAT, BACKGROUND_OPERATION_ABORT);

	return send_cmd_cci(ep, ti, &req, sizeof(req),
			    &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int cxlmi_cmd_get_fw_info(struct cxlmi_endpoint *ep,
				       struct cxlmi_tunnel_info *ti,
				       struct cxlmi_cmd_get_fw_info *ret)
{
	struct cxlmi_cmd_get_fw_info *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t rsp_sz;
	int rc;

	arm_cci_request(ep, &req, 0, FIRMWARE_UPDATE, GET_INFO);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_get_fw_info *)rsp->payload;
	ret->slots_supported = rsp_pl->slots_supported;
	ret->slot_info = rsp_pl->slot_info;
	ret->caps = rsp_pl->caps;
	memcpy(ret->fw_rev1, rsp_pl->fw_rev1, sizeof(rsp_pl->fw_rev1));
	memcpy(ret->fw_rev2, rsp_pl->fw_rev2, sizeof(rsp_pl->fw_rev2));
	memcpy(ret->fw_rev3, rsp_pl->fw_rev3, sizeof(rsp_pl->fw_rev3));
	memcpy(ret->fw_rev4, rsp_pl->fw_rev4, sizeof(rsp_pl->fw_rev4));

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_get_timestamp(struct cxlmi_endpoint *ep,
					 struct cxlmi_tunnel_info *ti,
					 struct cxlmi_cmd_get_timestamp *ret)
{
	struct cxlmi_cmd_get_timestamp *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t rsp_sz;
	int rc;

	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 8);

	arm_cci_request(ep, &req, 0, TIMESTAMP, GET);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_get_timestamp *)rsp->payload;
	ret->timestamp = le64_to_cpu(rsp_pl->timestamp);

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_set_timestamp(struct cxlmi_endpoint *ep,
					 struct cxlmi_tunnel_info *ti,
					 struct cxlmi_cmd_set_timestamp *in)
{
	struct cxlmi_cmd_set_timestamp *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	size_t req_sz;
	int rc;

	CXLMI_BUILD_BUG_ON(sizeof(*in) != 8);

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*in), TIMESTAMP, SET);

	req_pl = (struct cxlmi_cmd_set_timestamp *)req->payload;
	req_pl->timestamp = cpu_to_le64(in->timestamp);

	rc = send_cmd_cci(ep, ti, req, req_sz,
			    &rsp, sizeof(rsp), sizeof(rsp));
	return rc;
}

static const int maxlogs = 10; /* Only 7 in CXL r3.1 but let us leave room */
CXLMI_EXPORT int cxlmi_cmd_get_supported_logs(struct cxlmi_endpoint *ep,
				      struct cxlmi_tunnel_info *ti,
				      struct cxlmi_cmd_get_supported_logs *ret)
{
	struct cxlmi_cmd_get_supported_logs *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp;
	int rc, i;
	ssize_t rsp_sz;

	arm_cci_request(ep, &req, 0, LOGS, GET_SUPPORTED);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl) + maxlogs * sizeof(*rsp_pl->entries);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz,
			  sizeof(*rsp) + sizeof(*rsp_pl));
	if (rc)
		return rc;

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

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_get_log_cel(struct cxlmi_endpoint *ep,
				       struct cxlmi_tunnel_info *ti,
				       struct cxlmi_cmd_get_log *in,
				       struct cxlmi_cmd_get_log_cel_rsp *ret)
{
	struct cxlmi_cmd_get_log *req_pl;
	struct cxlmi_cmd_get_log_cel_rsp *rsp_pl;
	_cleanup_free_ struct cxlmi_cci_msg  *req = NULL;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
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
		return rc;

	rc = send_cmd_cci(ep, ti, req, req_sz, rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_get_log_cel_rsp *)rsp->payload;
	memset(ret, 0, sizeof(*ret));

	for (i = 0; i < in->length / sizeof(*rsp_pl); i++) {
		ret[i].opcode = le16_to_cpu(rsp_pl[i].opcode);
		ret[i].command_effect =
			le16_to_cpu(rsp_pl[i].command_effect);
	}

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_clear_log(struct cxlmi_endpoint *ep,
				     struct cxlmi_tunnel_info *ti,
				     struct cxlmi_cmd_clear_log *in)
{
	struct cxlmi_cmd_clear_log *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	size_t req_sz;

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*in), LOGS, CLEAR_LOG);

	req_pl = (struct cxlmi_cmd_clear_log *)req->payload;
	memcpy(req_pl->uuid, in->uuid, sizeof(in->uuid));

	return send_cmd_cci(ep, ti, req, req_sz,
			  &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int cxlmi_cmd_populate_log(struct cxlmi_endpoint *ep,
				struct cxlmi_tunnel_info *ti,
				struct cxlmi_cmd_populate_log *in)
{
	struct cxlmi_cmd_populate_log *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	size_t req_sz;

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*in), LOGS, POPULATE_LOG);

	req_pl = (struct cxlmi_cmd_populate_log *)req->payload;
	memcpy(req_pl->uuid, in->uuid, sizeof(in->uuid));

	return send_cmd_cci(ep, ti, req, req_sz,
			  &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int
cxlmi_cmd_get_supported_logs_sublist(struct cxlmi_endpoint *ep,
		     struct cxlmi_tunnel_info *ti,
		     struct cxlmi_cmd_get_supported_logs_sublist_req *in,
		     struct cxlmi_cmd_get_supported_logs_sublist_rsp *ret)
{
	struct cxlmi_cmd_get_supported_logs_sublist_req *req_pl;
	struct cxlmi_cmd_get_supported_logs_sublist_rsp *rsp_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t req_sz, rsp_sz;
	int i, rc = -1;

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*req_pl), LOGS, GET_SUPPORTED_SUBLIST);
	req_pl = (struct cxlmi_cmd_get_supported_logs_sublist_req *)req->payload;

	req_pl->max_supported_log_entries = in->max_supported_log_entries;
	req_pl->start_log_entry_index = in->start_log_entry_index;

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl) + maxlogs * sizeof(*rsp_pl->entries);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, req, req_sz, rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_get_supported_logs_sublist_rsp *)rsp->payload;
	memset(ret, 0, sizeof(*ret));

	ret->num_supported_log_entries = rsp_pl->num_supported_log_entries;
	ret->total_num_supported_log_entries =
		le16_to_cpu(rsp_pl->total_num_supported_log_entries);
	ret->start_log_entry_index = rsp_pl->start_log_entry_index;

	for (i = 0; i < rsp_pl->num_supported_log_entries; i++) {
		memcpy(ret->entries[i].uuid, rsp_pl->entries[i].uuid,
		       sizeof(rsp_pl->entries[i].uuid));
		ret->entries[i].log_size =
			le32_to_cpu(rsp_pl->entries[i].log_size);
	}

	return rc;
}


CXLMI_EXPORT int cxlmi_cmd_memdev_identify(struct cxlmi_endpoint *ep,
				   struct cxlmi_tunnel_info *ti,
				   struct cxlmi_cmd_memdev_identify *ret)
{
	struct cxlmi_cmd_memdev_identify *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	int rc;
	ssize_t rsp_sz;

	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 0x45);

	arm_cci_request(ep, &req, 0, IDENTIFY, MEMORY_DEVICE);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);

	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

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

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_memdev_get_lsa(struct cxlmi_endpoint *ep,
					  struct cxlmi_tunnel_info *ti,
					  struct cxlmi_cmd_memdev_get_lsa *ret)
{
	struct cxlmi_cmd_memdev_get_lsa *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp;
	ssize_t rsp_sz;
	int rc;

	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 8);

	arm_cci_request(ep, &req, 0, CCLS, GET_LSA);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_memdev_get_lsa *)rsp->payload;
	ret->offset = le32_to_cpu(rsp_pl->offset);
	ret->length = le32_to_cpu(rsp_pl->length);

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_memdev_set_lsa(struct cxlmi_endpoint *ep,
					  struct cxlmi_tunnel_info *ti,
					  struct cxlmi_cmd_memdev_set_lsa *in)
{
	struct cxlmi_cmd_memdev_set_lsa  *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	size_t req_sz;

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*in), CCLS, SET_LSA);

	req_pl = (struct cxlmi_cmd_memdev_set_lsa *)req->payload;
	req_pl->offset = cpu_to_le32(in->offset);

	return send_cmd_cci(ep, ti, req, req_sz,
			    &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int cxlmi_cmd_memdev_get_health_info(struct cxlmi_endpoint *ep,
				  struct cxlmi_tunnel_info *ti,
				  struct cxlmi_cmd_memdev_get_health_info *ret)
{
	struct cxlmi_cmd_memdev_get_health_info *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	int rc;
	ssize_t rsp_sz;

	arm_cci_request(ep, &req, 0, HEALTH_INFO_ALERTS, GET_HEALTH_INFO);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);

	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_memdev_get_health_info *)rsp->payload;
	memset(ret, 0, sizeof(*ret));

	ret->health_status = rsp_pl->health_status;
	ret->media_status = rsp_pl->media_status;
	ret->additional_status = rsp_pl->additional_status;
	ret->life_used = rsp_pl->life_used;
	ret->device_temperature = le16_to_cpu(rsp_pl->device_temperature);
	ret->dirty_shutdown_count = le32_to_cpu(rsp_pl->dirty_shutdown_count);
	ret->corrected_volatile_error_count =
		le32_to_cpu(rsp_pl->corrected_volatile_error_count);
	ret->corrected_persistent_error_count =
		le32_to_cpu(rsp_pl->corrected_persistent_error_count);

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_memdev_get_alert_config(struct cxlmi_endpoint *ep,
				   struct cxlmi_tunnel_info *ti,
				   struct cxlmi_cmd_memdev_get_alert_config *ret)
{
	struct cxlmi_cmd_memdev_get_alert_config *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	int rc;
	ssize_t rsp_sz;

	arm_cci_request(ep, &req, 0, HEALTH_INFO_ALERTS, GET_ALERT_CONFIG);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);

	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_memdev_get_alert_config *)rsp->payload;
	memset(ret, 0, sizeof(*ret));

	ret->valid_alerts = rsp_pl->valid_alerts;
	ret->programmable_alerts = rsp_pl->programmable_alerts;
	ret->life_used_critical_alert_threshold =
		rsp_pl->life_used_critical_alert_threshold;
	ret->life_used_programmable_warning_threshold =
		rsp_pl->life_used_programmable_warning_threshold;
	ret->device_over_temperature_critical_alert_threshold =
		le16_to_cpu(rsp_pl->device_over_temperature_critical_alert_threshold);
	ret->device_under_temperature_critical_alert_threshold =
		le16_to_cpu(rsp_pl->device_under_temperature_critical_alert_threshold);
	ret->device_over_temperature_programmable_warning_threshold =
		le16_to_cpu(rsp_pl->device_over_temperature_programmable_warning_threshold);
	ret->device_under_temperature_programmable_warning_threshold =
		le16_to_cpu(rsp_pl->device_under_temperature_programmable_warning_threshold);
	ret->corrected_volatile_mem_error_programmable_warning_threshold =
		le16_to_cpu(rsp_pl->corrected_volatile_mem_error_programmable_warning_threshold);
	ret->corrected_persistent_mem_error_programmable_warning_threshold =
		le16_to_cpu(rsp_pl->corrected_persistent_mem_error_programmable_warning_threshold);

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_memdev_set_alert_config(struct cxlmi_endpoint *ep,
				   struct cxlmi_tunnel_info *ti,
				   struct cxlmi_cmd_memdev_set_alert_config *in)
{
	struct cxlmi_cmd_memdev_set_alert_config *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	size_t req_sz;

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*in), HEALTH_INFO_ALERTS, SET_ALERT_CONFIG);

	req_pl = (struct cxlmi_cmd_memdev_set_alert_config *)req->payload;

	req_pl->valid_alert_actions = in->valid_alert_actions;
	req_pl->enable_alert_actions = in->enable_alert_actions;
	req_pl->life_used_programmable_warning_threshold =
		in->life_used_programmable_warning_threshold;
	req_pl->device_over_temperature_programmable_warning_threshold =
		cpu_to_le16(in->device_over_temperature_programmable_warning_threshold);
	req_pl->device_under_temperature_programmable_warning_threshold =
		cpu_to_le16(in->device_under_temperature_programmable_warning_threshold);
	req_pl->corrected_volatile_mem_error_programmable_warning_threshold =
		cpu_to_le16(in->corrected_volatile_mem_error_programmable_warning_threshold);
	req_pl->corrected_persistent_mem_error_programmable_warning_threshold =
		cpu_to_le16(in->corrected_persistent_mem_error_programmable_warning_threshold);

	return send_cmd_cci(ep, ti, req, req_sz, &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int cxlmi_cmd_memdev_sanitize(struct cxlmi_endpoint *ep,
					   struct cxlmi_tunnel_info *ti)
{
	struct cxlmi_cci_msg req, rsp;

	arm_cci_request(ep, &req, 0, SANITIZE, SANITIZE);

	return send_cmd_cci(ep, ti, &req, sizeof(req),
			    &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int cxlmi_cmd_memdev_secure_erase(struct cxlmi_endpoint *ep,
					       struct cxlmi_tunnel_info *ti)
{
	struct cxlmi_cci_msg req, rsp;

	arm_cci_request(ep, &req, 0, SANITIZE, SECURE_ERASE);

	return send_cmd_cci(ep, ti, &req, sizeof(req),
			    &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int cxlmi_cmd_fmapi_identify_sw_device(struct cxlmi_endpoint *ep,
			    struct cxlmi_tunnel_info *ti,
			    struct cxlmi_cmd_fmapi_identify_sw_device *ret)
{
	int rc;
	ssize_t rsp_sz;
	struct cxlmi_cmd_fmapi_identify_sw_device *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;

	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 0x49);

	arm_cci_request(ep, &req, 0, PHYSICAL_SWITCH, IDENTIFY_SWITCH_DEVICE);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return -1;

	rsp_pl = (struct cxlmi_cmd_fmapi_identify_sw_device *)rsp->payload;

	ret->ingres_port_id = rsp_pl->ingres_port_id;
	ret->num_physical_ports = rsp_pl->num_physical_ports;
	ret->num_vcs = rsp_pl->num_vcs;
	memcpy(ret->active_port_bitmask, rsp_pl->active_port_bitmask,
	       sizeof(rsp_pl->active_port_bitmask));
	memcpy(ret->active_vcs_bitmask, rsp_pl->active_vcs_bitmask,
	       sizeof(rsp_pl->active_vcs_bitmask));
	ret->num_total_vppb = le16_to_cpu(rsp_pl->num_total_vppb);
	ret->num_active_vppb = le16_to_cpu(rsp_pl->num_active_vppb);
	ret->num_hdm_decoder_per_usp = rsp_pl->num_hdm_decoder_per_usp;

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_fmapi_get_phys_port_state(struct cxlmi_endpoint *ep,
				     struct cxlmi_tunnel_info *ti,
				     struct cxlmi_cmd_fmapi_get_phys_port_state_req *in,
				     struct cxlmi_cmd_fmapi_get_phys_port_state_rsp *ret)
{
	struct cxlmi_cmd_fmapi_get_phys_port_state_req *req_pl;
	struct cxlmi_cmd_fmapi_get_phys_port_state_rsp *rsp_pl;
	struct cxlmi_cci_msg _cleanup_free_ *req = NULL;
	struct cxlmi_cci_msg _cleanup_free_ *rsp = NULL;
	ssize_t req_sz, rsp_sz;
	int i, rc = -1;

	req_sz = sizeof(*req_pl) + in->num_ports + sizeof(*req);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*req_pl),
			PHYSICAL_SWITCH, GET_PHYSICAL_PORT_STATE);
	req_pl = (struct cxlmi_cmd_fmapi_get_phys_port_state_req *)req->payload;

	req_pl->num_ports = in->num_ports;
	for (i = 0; i < in->num_ports; i++)
		req_pl->ports[i] = in->ports[i];

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl) +
		in->num_ports * sizeof(*rsp_pl->ports);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, req, req_sz, rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_fmapi_get_phys_port_state_rsp *)rsp->payload;
	memset(ret, 0, sizeof(*ret));

	ret->num_ports = rsp_pl->num_ports;
	for (i = 0; i < rsp_pl->num_ports; i++) {
		ret->ports[i].port_id = rsp_pl->ports[i].port_id;
		ret->ports[i].config_state = rsp_pl->ports[i].config_state;
		ret->ports[i].conn_dev_cxl_ver = rsp_pl->ports[i].conn_dev_cxl_ver;
		ret->ports[i].conn_dev_type = rsp_pl->ports[i].conn_dev_type;
		ret->ports[i].port_cxl_ver_bitmask =
			rsp_pl->ports[i].port_cxl_ver_bitmask;
		ret->ports[i].max_link_width = rsp_pl->ports[i].max_link_width;
		ret->ports[i].negotiated_link_width =
			rsp_pl->ports[i].negotiated_link_width;
		ret->ports[i].supported_link_speeds_vector =
			rsp_pl->ports[i].supported_link_speeds_vector;
		ret->ports[i].max_link_speed = rsp_pl->ports[i].max_link_speed;
		ret->ports[i].current_link_speed =
			rsp_pl->ports[i].current_link_speed;
		ret->ports[i].ltssm_state = rsp_pl->ports[i].ltssm_state;
		ret->ports[i].first_lane_num = rsp_pl->ports[i].first_lane_num;
		ret->ports[i].link_state = le16_to_cpu(rsp_pl->ports[i].link_state);
		ret->ports[i].supported_ld_count = rsp_pl->ports[i].supported_ld_count;
	}

	return rc;
}
