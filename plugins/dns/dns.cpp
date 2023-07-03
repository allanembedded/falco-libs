#include <string>
#include <cstring>

#include <engine/source_plugin/source_plugin_public.h>
#include <ppm_events_public.h>

typedef struct plugin_state
{
    std::string lasterr;
    
} plugin_state;

extern "C"
{

const char* plugin_get_required_api_version()
{
    return PLUGIN_API_VERSION_STR;
}

const char* plugin_get_version()
{
    return "0.0.1";
}

const char* plugin_get_name()
{
    return "dns_query_source";
}

const char* plugin_get_description()
{
    return "Returns DNS query events";
}

const char* plugin_get_contact()
{
    return "Sysdig Support";
}

uint32_t plugin_get_id()
{
	return 999;
}

ss_plugin_t* plugin_init(const ss_plugin_init_input* in, ss_plugin_rc* rc)
{
    plugin_state* state = new plugin_state();

    *rc = SS_PLUGIN_SUCCESS;

    return state;
}

void plugin_destroy(ss_plugin_t* s)
{
    delete ((plugin_state *) s);
}

const char* plugin_get_last_error(ss_plugin_t* s)
{
    return ((plugin_state *) s)->lasterr.c_str();
}

const char* plugin_get_parse_event_sources()
{
    return "[\"syscall\"]";
}

uint16_t* plugin_get_parse_event_types(uint32_t* num_types)
{
    static uint16_t types[] = {
        PPME_SOCKET_RECVFROM_X,
        PPME_SOCKET_RECVMSG_X
    };
    *num_types = sizeof(types) / sizeof(uint16_t);
    return &types[0];
}

ss_plugin_rc plugin_parse_event(ss_plugin_t *s, const ss_plugin_event_input *ev, const ss_plugin_event_parse_input* in)
{
    if (ev->evt->type == PPME_SOCKET_RECVMSG_X)
    {
        // Process recvmsg
    }
    else if (ev->evt->type == PPME_SOCKET_RECVFROM_X)
    {
        //process recvfrom
    }

    return SS_PLUGIN_SUCCESS;
}

void get_plugin_api_sample_plugin_source(plugin_api& out)
{
    memset(&out, 0, sizeof(plugin_api));

    /* Minimal plugin functions */
    out.get_required_api_version = plugin_get_required_api_version;
    out.get_version = plugin_get_version;
    out.get_description = plugin_get_description;
    out.get_contact = plugin_get_contact;
    out.get_name = plugin_get_name;
    out.get_last_error = plugin_get_last_error;
    out.init = plugin_init;
    out.destroy = plugin_destroy;

    out.get_id = plugin_get_id;

    /* Event parsing implementation */
    out.get_parse_event_sources = plugin_get_parse_event_sources;
    out.get_parse_event_types = plugin_get_parse_event_types;
    out.parse_event = plugin_parse_event;
}

}
