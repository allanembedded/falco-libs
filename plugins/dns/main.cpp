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

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <iostream>

#include <ppm_events_public.h>

#include <engine/source_plugin/source_plugin_public.h>
//#include "test_plugins.h"

constexpr const char* s_evt_data = "hello world";

/**
 * Example of plugin implementing only the event sourcing capability, which:
 * - Implements a specific event source "sample"
 * - Sources plugin events containing a sample string 
 */
typedef struct plugin_state
{
    std::string lasterr;
} plugin_state;

typedef struct instance_state
{
    uint64_t count;
    uint8_t evt_buf[2048];
    ss_plugin_event* evt;
} instance_state;

extern "C" const char* plugin_get_required_api_version()
{
    return PLUGIN_API_VERSION_STR;
}

extern "C" const char* plugin_get_version()
{
    return "0.1.0";
}

extern "C" const char* plugin_get_name()
{
    return "sample_plugin_source";
}

extern "C" const char* plugin_get_description()
{
    return "some desc";
}

extern "C" const char* plugin_get_contact()
{
    return "some contact";
}

extern "C" uint32_t plugin_get_id()
{
	return 999;
}

extern "C" const char* plugin_get_event_source()
{
	return "sample";
}

extern "C" const char* plugin_get_last_error(ss_plugin_t* s)
{
    return ((plugin_state *) s)->lasterr.c_str();
}

extern "C" ss_plugin_t* plugin_init(const ss_plugin_init_input* in, ss_plugin_rc* rc)
{
    std::cerr << "Called plugin_init" << std::endl;
    *rc = SS_PLUGIN_SUCCESS;
    return new plugin_state();
}

extern "C" void plugin_destroy(ss_plugin_t* s)
{
    delete ((plugin_state *) s);
}
/*
extern "C" ss_instance_t* plugin_open(ss_plugin_t* s, const char* params, ss_plugin_rc* rc)
{
    instance_state *ret = new instance_state();
    ret->evt = (ss_plugin_event*) &ret->evt_buf;
    ret->count = 10000;
    auto count = atoi(params);
    if (count > 0)
    {
        ret->count = (uint64_t) count;
    }

    *rc = SS_PLUGIN_SUCCESS;
    return ret;
}

extern "C" void plugin_close(ss_plugin_t* s, ss_instance_t* i)
{
    delete ((instance_state *) i);
}

extern "C" ss_plugin_rc plugin_next_batch(ss_plugin_t* s, ss_instance_t* i, uint32_t *nevts, ss_plugin_event ***evts)
{
    instance_state *istate = (instance_state *) i;

    if (istate->count == 0)
    {
        *nevts = 0;
        return SS_PLUGIN_EOF;
    }

    *nevts = 1;
    *evts = &istate->evt;
    istate->evt->type = PPME_PLUGINEVENT_E;
    istate->evt->tid = -1;
    istate->evt->ts = UINT64_MAX;
    istate->evt->len = sizeof(ss_plugin_event);
    istate->evt->nparams = 2;

    uint8_t* parambuf = &istate->evt_buf[0] + sizeof(ss_plugin_event);

    // lenghts
    *((uint32_t*) parambuf) = sizeof(uint32_t);
    parambuf += sizeof(uint32_t);
    *((uint32_t*) parambuf) = strlen(s_evt_data) + 1;
    parambuf += sizeof(uint32_t);

    // params
    *((uint32_t*) parambuf) = plugin_get_id();
    parambuf += sizeof(uint32_t);
    strcpy((char*) parambuf, s_evt_data);
    parambuf += strlen(s_evt_data) + 1;

    istate->evt->len += parambuf - (&istate->evt_buf[0] + sizeof(ss_plugin_event));
    istate->count--;
    return SS_PLUGIN_SUCCESS;
}
*/
extern "C" const char* plugin_get_parse_event_sources()
{
    std::cerr << "Called plugin_get_parse_event_sources" << std::endl;
    return "[\"syscall\"]";
}

extern "C" uint16_t* plugin_get_parse_event_types(uint32_t* num_types)
{
    std::cerr << "Called plugin_get_parse_event_types" << std::endl;
    static uint16_t types[] = {
	PPME_SOCKET_RECVFROM_X
    };
    *num_types = sizeof(types) / sizeof(uint16_t);
    return &types[0];
}

extern "C" ss_plugin_rc plugin_parse_event(ss_plugin_t *s, const ss_plugin_event_input *ev, const ss_plugin_event_parse_input* in)
{
    // Hack for DNS parsing
    std::cerr << "Called plugin_parse_event" << std::endl;
    if (ev->evt->type == PPME_SOCKET_RECVFROM_X)
    {
        std::cerr << "Found recvfrom" << std::endl;
        if (ev->evt->nparams != 3)
        {
            return SS_PLUGIN_SUCCESS;
        }        
    }

    return SS_PLUGIN_SUCCESS;
}


extern "C" void get_plugin_api_sample_plugin_source(plugin_api& out)
{
    memset(&out, 0, sizeof(plugin_api));
	out.get_required_api_version = plugin_get_required_api_version;
	out.get_version = plugin_get_version;
	out.get_description = plugin_get_description;
	out.get_contact = plugin_get_contact;
	out.get_name = plugin_get_name;
	out.get_last_error = plugin_get_last_error;
	out.init = plugin_init;
	out.destroy = plugin_destroy;

    out.get_id = plugin_get_id;
    /*out.get_event_source = plugin_get_event_source;
    out.open = plugin_open;
    out.close = plugin_close;
    out.next_batch = plugin_next_batch;*/

    out.get_parse_event_sources = plugin_get_parse_event_sources;
    out.get_parse_event_types = plugin_get_parse_event_types;
    out.parse_event = plugin_parse_event;
}
