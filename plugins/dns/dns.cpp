#include <string>
#include <cstring>
#include <iostream>
#include <arpa/inet.h>

#include <engine/source_plugin/source_plugin_public.h>
#include <ppm_events_public.h>

typedef struct plugin_state
{
    std::string lasterr = "";
    ss_plugin_async_event_handler_t handler = nullptr;
    uint8_t async_evt_buf[2048] = {0};
    ss_plugin_event* async_evt = nullptr;
    ss_plugin_owner_t* owner;
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
    std::cerr << "Called plugin_init" << std::endl;
    plugin_state* state = new plugin_state();

    state->async_evt = (ss_plugin_event*) &state->async_evt_buf;

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

static void encode_async_event(ss_plugin_event* evt, uint64_t tid, const char* name, const char* data)
{
    // set event info
    evt->type = PPME_ASYNCEVENT_E;
    evt->tid = tid;
    evt->len = sizeof(ss_plugin_event);
    evt->nparams = 3;

    // lenghts
    uint8_t* parambuf = (uint8_t*) evt + sizeof(ss_plugin_event);
    *((uint32_t*) parambuf) = sizeof(uint32_t);
    parambuf += sizeof(uint32_t);
    *((uint32_t*) parambuf) = strlen(name) + 1;
    parambuf += sizeof(uint32_t);
    *((uint32_t*) parambuf) = strlen(data) + 1;
    parambuf += sizeof(uint32_t);

    // params
    // skip plugin ID, it will be filled by the framework
    parambuf += sizeof(uint32_t);
    strcpy((char*) parambuf, name);
    parambuf += strlen(name) + 1;
    strcpy((char*) parambuf, data);
    parambuf += strlen(data) + 1;

    // update event's len
    evt->len += parambuf - ((uint8_t*) evt + sizeof(ss_plugin_event));
}

void have_dns_packet(plugin_state *ps, uint64_t tid, uint8_t* buf, uint32_t len)
{
    unsigned short query_count = ntohs(((unsigned short*)buf)[2]);
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

            index += buf[index]+1;

            if (index < len && buf[index] != 0)
            {
                domain.append(".");
            }
        }

        if (domain.size() > 0 && ps->handler)
        {
            char err[PLUGIN_MAX_ERRLEN];
            encode_async_event(ps->async_evt, tid, "dns", domain.c_str());

            if (SS_PLUGIN_SUCCESS != ps->handler(ps->owner, ps->async_evt, err))
            {
                printf("sample_syscall_async: unexpected failure in sending asynchronous event from plugin: %s\n", err);
                exit(1);
            }
        }

        index++;
        query_count--;
    }
}

ss_plugin_rc plugin_parse_event(ss_plugin_t *s, const ss_plugin_event_input *ev, const ss_plugin_event_parse_input* in)
{
    plugin_state *ps = (plugin_state *) s;

    if (ev->evt->type == PPME_SOCKET_RECVMSG_X)
    {
        // Process recvmsg
        if (ev->evt->nparams == 4)
        {
            uint16_t* buf = (uint16_t*)((uint8_t*)ev->evt + sizeof(*ev->evt));

            if (buf[3] < sizeof(socktuple))
            {
                //std::cerr << "Socktuple parameter too small " << buf[3] << std::endl;
                return SS_PLUGIN_SUCCESS;
            }
            if (buf[2] == 0)
            {
                //std::cerr << "Empty buffer" << std::endl;
                return SS_PLUGIN_SUCCESS;
            }

            socktuple* test = (socktuple*)(((uint8_t*)&buf[4]) + buf[0] + buf[1] + buf[2]);

            // Check for ipv4 and port 53
            if (test->type == 2 && test->src.port == 53)
            {
                have_dns_packet(ps, ev->evt->tid, ((uint8_t*)&buf[4]) + buf[0] + buf[1], buf[2]);
            }
        }
        else
        {
            std::cerr << "Unexpected recvmsg length: " << ev->evt->nparams << std::endl;
        }
    }
    else if (ev->evt->type == PPME_SOCKET_RECVFROM_X)
    {
        //process recvfrom
        if (ev->evt->nparams == 3)
        {
            uint16_t* buf = (uint16_t*)((uint8_t*)ev->evt + sizeof(*ev->evt));

            if (buf[2] < sizeof(socktuple))
            {
                //std::cerr << "Socktuple parameter too small " << buf[2] << std::endl;
                return SS_PLUGIN_SUCCESS;
            }
            if (buf[1] == 0)
            {
                //std::cerr << "Empty buffer" << std::endl;
                return SS_PLUGIN_SUCCESS;
            }

            socktuple* test = (socktuple*)(((uint8_t*)&buf[3]) + buf[0] + buf[1]);

            // Check for ipv4 and port 53
            if (test->type == 2 && test->src.port == 53)
            {
                have_dns_packet(ps, ev->evt->tid, ((uint8_t*)&buf[3]) + buf[0], buf[1]);
            }
        }
        else
        {
            std::cerr << "Unexpected recvfrom length: " << ev->evt->nparams << std::endl;
        }
    }

    return SS_PLUGIN_SUCCESS;
}

const char* plugin_get_async_events()
{
    return "[\"dns\"]";
}

ss_plugin_rc plugin_set_async_event_handler(ss_plugin_t* s, ss_plugin_owner_t* owner, const ss_plugin_async_event_handler_t handler)
{
    plugin_state *ps = (plugin_state *) s;
    std::cerr << "Called plugin_set_async_event_handler" << std::endl;

    // Note plugin_set_async_event_handler is called with handler = NULL on close
    if (handler)
    {
        ps->handler = handler;
        ps->owner = owner;
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

    out.get_async_events = plugin_get_async_events;
    out.set_async_event_handler = plugin_set_async_event_handler;
}

}
