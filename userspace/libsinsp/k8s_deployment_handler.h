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
// k8s_deployment_handler.h
//
#ifndef MINIMAL_BUILD
#pragma once

#include "json/json.h"
#include "sinsp_auth.h"
#include "k8s_handler.h"
#include "k8s_state.h"

class sinsp;

class k8s_deployment_handler : public k8s_handler
{
public:
	k8s_deployment_handler(k8s_state_t& state
#if defined(HAS_CAPTURE) && !defined(_WIN32)
		,ptr_t dependency_handler
		,collector_ptr_t collector = nullptr
		,std::string url = ""
		,const std::string& http_version = "1.1"
		,ssl_ptr_t ssl = 0
		,bt_ptr_t bt = 0
		,bool connect = true
		,bool blocking_socket = false
#endif // HAS_CAPTURE
		);

	~k8s_deployment_handler();

private:
	static std::string EVENT_FILTER;
	static std::string STATE_FILTER;
	static std::string NULL_FILTER;

	virtual bool handle_component(const Json::Value& json, const msg_data* data = 0);
};

#endif // MINIMAL_BUILD
