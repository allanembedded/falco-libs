// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/
//
// k8s_replicationcontroller_handler.cpp
//
#ifndef CYGWING_AGENT

#include "k8s_replicationcontroller_handler.h"
#include "sinsp.h"
#include "sinsp_int.h"

// filters normalize state and event JSONs, so they can be processed generically:
// event is turned into a single-entry array, state is turned into an array of ADDED events

std::string k8s_replicationcontroller_handler::EVENT_FILTER =
	"{"
	" type: .type,"
	" apiVersion: .object.apiVersion,"
	" kind: .object.kind,"
	" items:"
	" ["
	"  .object |"
	"  {"
	"   namespace: .metadata.namespace,"
	"   name: .metadata.name,"
	"   uid: .metadata.uid,"
	"   timestamp: .metadata.creationTimestamp,"
	"   specReplicas: .spec.replicas,"
	"   statReplicas: .status.replicas,"
	"   selector: .spec.selector,"
	"   labels: .metadata.labels"
	"  }"
	" ]"
	"}";

std::string k8s_replicationcontroller_handler::STATE_FILTER =
	"{"
	" type: \"ADDED\","
	" apiVersion: .apiVersion,"
	" kind: \"ReplicationController\", "
	" items:"
	" ["
	"  .items[] | "
	"  {"
	"   namespace: .metadata.namespace,"
	"   name: .metadata.name,"
	"   uid: .metadata.uid,"
	"   timestamp: .metadata.creationTimestamp,"
	"   specReplicas: .spec.replicas,"
	"   statReplicas: .status.replicas,"
	"   selector: .spec.selector,"
	"   labels: .metadata.labels"
	"   }"
	" ]"
	"}";

std::string k8s_replicationcontroller_handler::NULL_FILTER =
	"{"
	" type: \"NONEXISTENT\","
	" apiVersion: .apiVersion,"
	" kind: \"ReplicationController\", "
	" items: [ null ]"
	"}";

k8s_replicationcontroller_handler::k8s_replicationcontroller_handler(k8s_state_t& state
#if defined(HAS_CAPTURE) && !defined(_WIN32)
	,ptr_t dependency_handler
	,collector_ptr_t collector
	,std::string url
	,const std::string& http_version
	,ssl_ptr_t ssl
	,bt_ptr_t bt
	,bool connect
	,bool blocking_socket
#endif // HAS_CAPTURE
	):
		k8s_handler("k8s_replicationcontroller_handler", true,
#if defined(HAS_CAPTURE) && !defined(_WIN32)
					url, 
					"/api/v1/replicationcontrollers" + k8s_component::get_selector(k8s_component::K8S_REPLICATIONCONTROLLERS),
					STATE_FILTER, EVENT_FILTER, NULL_FILTER, collector,
					http_version, 1000L, ssl, bt, true,
					connect, dependency_handler, blocking_socket,
#endif // HAS_CAPTURE
					100, // max msgs
					&state)
{
}

k8s_replicationcontroller_handler::~k8s_replicationcontroller_handler()
{
}

bool k8s_replicationcontroller_handler::handle_component(const Json::Value& json, const msg_data* data)
{
	if(data)
	{
		if(m_state)
		{
			if((data->m_reason == k8s_component::COMPONENT_ADDED) ||
			   (data->m_reason == k8s_component::COMPONENT_MODIFIED))
			{
				k8s_rc_t& rc =
					m_state->get_component<k8s_controllers, k8s_rc_t>(m_state->get_rcs(),
																	  data->m_name, data->m_uid, data->m_namespace);
				k8s_pair_list entries = extract_object(json["labels"]);
				if(entries.size() > 0)
				{
					rc.set_labels(std::move(entries));
				}
				handle_selectors(rc, json["selector"]);
				const Json::Value& spec = json["specReplicas"];
				const Json::Value& stat = json["statReplicas"];
				if(!spec.isNull() && spec.isConvertibleTo(Json::intValue) &&
				   !stat.isNull() && stat.isConvertibleTo(Json::intValue))
				{
					rc.set_replicas(spec.asInt(), stat.asInt());
				}
			}
			else if(data->m_reason == k8s_component::COMPONENT_DELETED)
			{
				if(!m_state->delete_component(m_state->get_rcs(), data->m_uid))
				{
					log_not_found(*data);
					return false;
				}
			}
			else if(data->m_reason != k8s_component::COMPONENT_ERROR)
			{
				g_logger.log(std::string("Unsupported K8S " + name() + " event reason: ") +
							 std::to_string(data->m_reason), sinsp_logger::SEV_ERROR);
				return false;
			}
		}
		else
		{
			throw sinsp_exception("K8s node handler: state is null.");
		}
	}
	else
	{
		throw sinsp_exception("K8s node handler: data is null.");
	}
	return true;
}
#endif // CYGWING_AGENT
