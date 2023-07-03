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

#include <arpa/inet.h>

constexpr const char* s_evt_data = "hello world";

struct thread_fdinfo_key_t
{
	uint64_t tid = 0;
	uint64_t fd = 0;
};

/**
 * Example of plugin implementing only the event sourcing capability, which:
 * - Implements a specific event source "sample"
 * - Sources plugin events containing a sample string 
 */
typedef struct plugin_state
{
    std::string lasterr;
    ss_plugin_table_t* thread_table;
    ss_plugin_table_t* thread_fdinfo_table;
    ss_plugin_table_field_t* thread_fdinfo_l4proto;
    
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
    plugin_state* state = new plugin_state();
    std::cerr << "Called plugin_init" << std::endl;
    *rc = SS_PLUGIN_SUCCESS;

    state->thread_table = in->tables->get_table(
        in->owner, "threads", ss_plugin_state_type::SS_PLUGIN_ST_INT64);
    if (!state->thread_table)
    {
        *rc = SS_PLUGIN_FAILURE;
        auto err = in->get_owner_last_error(in->owner);
        state->lasterr = err ? err : "can't access thread table";
        return state;
    }

    // get accessor for thread fdinfo table
    state->thread_fdinfo_table = in->tables->get_table(
        in->owner, "thread_fdinfo", ss_plugin_state_type::SS_PLUGIN_ST_UINT64);

    if (!state->thread_fdinfo_table)
    {
        *rc = SS_PLUGIN_FAILURE;
        auto err = in->get_owner_last_error(in->owner);
        state->lasterr = err ? err : "can't access thread fdinfo table";
        return state;
    }

    // get accessor for proc name in thread table entries
    state->thread_fdinfo_l4proto = in->tables->fields.get_table_field(
        state->thread_fdinfo_table, "l4proto", ss_plugin_state_type::SS_PLUGIN_ST_UINT8);
    if (!state->thread_fdinfo_l4proto)
    {
        *rc = SS_PLUGIN_FAILURE;
        auto err = in->get_owner_last_error(in->owner);
        state->lasterr = err ? err : "can't access l4proto in fdinfo table";
        return state;
    }

    return state;
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
	PPME_SOCKET_RECVFROM_X,
	PPME_SOCKET_RECVMSG_X
    };
    *num_types = sizeof(types) / sizeof(uint16_t);
    return &types[0];
}

struct __attribute__((__packed__)) ip_port {
	uint8_t a;
	uint8_t b;
	uint8_t c;
	uint8_t d;
	uint16_t port;
};

struct __attribute__((__packed__)) socktuple {
	uint8_t type;
	ip_port src;
	ip_port dst;
};

void have_dns_packet(uint8_t* buf, uint32_t len)
{
	std::cerr << "Have DNS packet with length " << len << std::endl;
        unsigned short query_count = ntohs(((unsigned short*)buf)[2]);

        std::cerr << "Query count: " << query_count << std::endl;
        unsigned int index = 12;

	if (query_count > 100)
		return;

        while(query_count)
        {
                std::string domain("");

                while ((index < len) && (buf[index] != 0))
                {
                        if (index + (unsigned int)(buf[index]) > len)
                                break;

                        domain.append((const char*)&buf[index+1], (size_t)buf[index]);

                        domain.append(".");
                        index += buf[index]+1;
                }
                std::cerr << "Domain: " << domain << std::endl;

                index++;
                query_count--;
        }
}

extern "C" ss_plugin_rc plugin_parse_event(ss_plugin_t *s, const ss_plugin_event_input *ev, const ss_plugin_event_parse_input* in)
{
    //ss_plugin_state_data tmp;

    // Hack for DNS parsing
    //std::cerr << "START PLUGIN" << std::endl;
    if (ev->evt->type == PPME_SOCKET_RECVMSG_X)
    {
	std::cerr << ev->evt->tid << " recvmsg " << ev->evt->nparams << std::endl;
        if (ev->evt->nparams == 4)
        {
		uint16_t* buf = (uint16_t*)((uint8_t*)ev->evt + sizeof(*ev->evt));

		if (buf[3] == 0)
		{
			return SS_PLUGIN_SUCCESS;
		}

		socktuple* test = (socktuple*)(((uint8_t*)&buf[4]) + buf[0] + buf[1] + buf[2]);
		if (test->type != 2)
		{
			return SS_PLUGIN_SUCCESS;
		}
		if (test->src.port == 53)
		{
			have_dns_packet(((uint8_t*)&buf[4]) + buf[0] + buf[1], buf[2]);
		}
		//std::cerr << "recvmsg" << std::endl;
		//std::cerr << "Test sport:" << test->src.port << std::endl;
		//std::cerr << "Test dport:" << test->dst.port << std::endl;
	}	
    }

    if (ev->evt->type == PPME_SOCKET_RECVFROM_X)
    {
	std::cerr << ev->evt->tid << " recvfrom " << ev->evt->nparams << std::endl;
        //std::cerr << "Found recvfrom " << ev->evt->nparams << std::endl;
	//std::cerr << "Event pointer inside plugin:"  << ev->evt << std::endl;
        if (ev->evt->nparams == 3)
        {
		uint16_t* buf = (uint16_t*)((uint8_t*)ev->evt + sizeof(*ev->evt));
		//std::cerr << "Type: " << ev->evt->type << std::endl;
		//std::cerr << "Length: " << ev->evt->len << std::endl;
		//std::cerr << "Length param 0: " << buf[0] << std::endl;
		//std::cerr << "Length param 1: " << buf[1] << std::endl;
		//std::cerr << "Length param 2: " << buf[2] << std::endl;
		if (buf[2] == 0)
		{
			return SS_PLUGIN_SUCCESS;
		}

		uint8_t* sockbuf = (uint8_t*)(((uint8_t*)&buf[3]) + buf[0] + buf[1]);
		/*std::cerr << "Payload addr:" << (void*)sockbuf << std::endl;
		std::cerr << "Payload: " << +sockbuf[0] << std::endl;
		std::cerr << "IP: " << +sockbuf[1] << "." << +sockbuf[2] << "." << +sockbuf[3] << "." << +sockbuf[4] << std::endl;
		std::cerr << "Sport: " << *(uint16_t*)(sockbuf+5) << std::endl;
		std::cerr << "Dport: " << *(uint16_t*)(sockbuf+11) << std::endl;*/

		socktuple* test = (socktuple*)(((uint8_t*)&buf[3]) + buf[0] + buf[1]);
		//std::cerr << "recvfrom" << std::endl;
		//std::cerr << "Test sport:" << test->src.port << std::endl;
		//std::cerr << "Test dport:" << test->dst.port << std::endl;
		if (test->src.port == 53)
		{
			have_dns_packet(((uint8_t*)&buf[3]) + buf[0], buf[1]);
		}
		
		//sinsp_evt_param *parinfo = ev->evt->get_param(0);
		//std::cerr << "Param 0 value:" << (uint16_t)parinfo->m_val << std::endl;

		//std::cerr << "Port: " << get_port(ev->evt->get_param(2)) << std::endl;

		//thread_fdinfo_key_t key = { tid, fd };
		//rc = in->table_reader.read_entry_field(ps->thread_fdinfo_table, &key, ps->thread_fdinfo_l4proto, &tmp);

    		//std::cerr << "END PLUGIN" << std::endl;
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
