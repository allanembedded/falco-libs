#include <string>
#include <cstring>

#include <engine/source_plugin/source_plugin_public.h>

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
}

}
