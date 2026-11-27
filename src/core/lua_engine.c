#include "apex/lua_engine.h"
#include "internal.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

static __thread lua_State *s_worker_lua_state = NULL;
static __thread apex_pipeline_ctx_t *s_lua_current_ctx = NULL;
static __thread char *s_lua_out_body = NULL;
static __thread size_t s_lua_out_cap = 0;
static __thread size_t s_lua_out_len = 0;
static __thread apex_action_t s_lua_action = APEX_ACTION_CONTINUE;

/* ========================================================================= */
/* Lua C API Callbacks for apex.*                                            */
/* ========================================================================= */

static int lua_apex_req_get_method(lua_State *L) {
    if (s_lua_current_ctx != NULL && s_lua_current_ctx->method != NULL) {
        lua_pushlstring(L, s_lua_current_ctx->method, s_lua_current_ctx->method_len);
    } else {
        lua_pushliteral(L, "GET");
    }
    return 1;
}

static int lua_apex_req_get_uri(lua_State *L) {
    if (s_lua_current_ctx != NULL && s_lua_current_ctx->path != NULL) {
        lua_pushlstring(L, s_lua_current_ctx->path, s_lua_current_ctx->path_len);
    } else {
        lua_pushliteral(L, "/");
    }
    return 1;
}

static int lua_apex_req_get_body(lua_State *L) {
    if (s_lua_current_ctx != NULL && s_lua_current_ctx->body != NULL) {
        lua_pushlstring(L, s_lua_current_ctx->body, s_lua_current_ctx->body_len);
    } else {
        lua_pushliteral(L, "");
    }
    return 1;
}

static int lua_apex_req_get_header(lua_State *L) {
    const char *name = luaL_checkstring(L, 1);
    if (s_lua_current_ctx == NULL || name == NULL) {
        lua_pushnil(L);
        return 1;
    }

    const char *val = NULL;
    size_t val_len = 0;
    if (apex_pipeline_find_header(s_lua_current_ctx, name, &val, &val_len) && val != NULL) {
        lua_pushlstring(L, val, val_len);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

static int lua_apex_req_get_headers(lua_State *L) {
    lua_newtable(L);
    if (s_lua_current_ctx == NULL || s_lua_current_ctx->raw_request == NULL) {
        return 1;
    }

    const char *raw = s_lua_current_ctx->raw_request;
    size_t raw_len = s_lua_current_ctx->raw_request_len;

    const char *line_end = memmem(raw, raw_len, "\r\n", 2);
    if (line_end == NULL) return 1;

    const char *p = line_end + 2;
    while (p < raw + raw_len) {
        const char *next_eol = memmem(p, raw_len - (size_t)(p - raw), "\r\n", 2);
        if (next_eol == NULL || next_eol == p) {
            break;
        }

        const char *colon = memchr(p, ':', (size_t)(next_eol - p));
        if (colon != NULL) {
            size_t name_len = (size_t)(colon - p);
            char hname[128];
            if (name_len < sizeof(hname)) {
                for (size_t i = 0; i < name_len; i++) {
                    hname[i] = (char)tolower((unsigned char)p[i]);
                }
                hname[name_len] = '\0';

                const char *val = colon + 1;
                while (val < next_eol && (*val == ' ' || *val == '\t')) val++;
                size_t val_len = (size_t)(next_eol - val);

                lua_pushlstring(L, val, val_len);
                lua_setfield(L, -2, hname);
            }
        }
        p = next_eol + 2;
    }

    return 1;
}

static int lua_apex_req_set_header(lua_State *L) {
    const char *name = luaL_checkstring(L, 1);
    const char *val = luaL_checkstring(L, 2);
    if (s_lua_current_ctx != NULL && name != NULL && val != NULL) {
        apex_pipeline_add_header(s_lua_current_ctx, name, val);
    }
    return 0;
}

static int lua_apex_resp_set_status(lua_State *L) {
    int status = (int)luaL_checkinteger(L, 1);
    if (s_lua_current_ctx != NULL) {
        s_lua_current_ctx->status_code = status;
    }
    return 0;
}

static int lua_apex_resp_set_header(lua_State *L) {
    const char *name = luaL_checkstring(L, 1);
    const char *val = luaL_checkstring(L, 2);
    if (s_lua_current_ctx != NULL && name != NULL && val != NULL) {
        apex_pipeline_add_header(s_lua_current_ctx, name, val);
    }
    return 0;
}

static int lua_apex_say(lua_State *L) {
    size_t len = 0;
    const char *str = luaL_checklstring(L, 1, &len);
    if (str != NULL && s_lua_out_body != NULL && s_lua_out_len + len < s_lua_out_cap) {
        memcpy(s_lua_out_body + s_lua_out_len, str, len);
        s_lua_out_len += len;
        s_lua_out_body[s_lua_out_len] = '\0';
        s_lua_action = APEX_ACTION_DONE;
        if (s_lua_current_ctx != NULL && s_lua_current_ctx->status_code == 0) {
            s_lua_current_ctx->status_code = 200;
        }
    }
    return 0;
}

static int lua_apex_exit(lua_State *L) {
    int status = (int)luaL_checkinteger(L, 1);
    if (s_lua_current_ctx != NULL) {
        s_lua_current_ctx->status_code = status;
    }
    if (status >= 400) {
        s_lua_action = APEX_ACTION_DENY;
    } else {
        s_lua_action = APEX_ACTION_DONE;
    }
    return luaL_error(L, "__apex_exit__");
}

static int lua_apex_log(lua_State *L) {
    const char *msg = luaL_checkstring(L, 1);
    if (msg != NULL) {
        fprintf(stderr, "apex lua: %s\n", msg);
    }
    return 0;
}

/* ========================================================================= */
/* Engine Initialization & Teardown                                          */
/* ========================================================================= */

bool apex_lua_thread_init(void) {
    if (s_worker_lua_state != NULL) {
        return true;
    }

    lua_State *L = luaL_newstate();
    if (L == NULL) {
        return false;
    }

    luaL_openlibs(L);

    /* Construct apex table:
     * apex = {
     *     req = { get_method, get_uri, get_body, get_header, get_headers, set_header },
     *     resp = { set_status, set_header },
     *     say = say,
     *     exit = exit,
     *     log = log
     * }
     */
    lua_newtable(L); /* apex table */

    /* apex.req */
    lua_newtable(L);
    lua_pushcfunction(L, lua_apex_req_get_method);
    lua_setfield(L, -2, "get_method");
    lua_pushcfunction(L, lua_apex_req_get_uri);
    lua_setfield(L, -2, "get_uri");
    lua_pushcfunction(L, lua_apex_req_get_body);
    lua_setfield(L, -2, "get_body");
    lua_pushcfunction(L, lua_apex_req_get_header);
    lua_setfield(L, -2, "get_header");
    lua_pushcfunction(L, lua_apex_req_get_headers);
    lua_setfield(L, -2, "get_headers");
    lua_pushcfunction(L, lua_apex_req_set_header);
    lua_setfield(L, -2, "set_header");
    lua_setfield(L, -2, "req");

    /* apex.resp */
    lua_newtable(L);
    lua_pushcfunction(L, lua_apex_resp_set_status);
    lua_setfield(L, -2, "set_status");
    lua_pushcfunction(L, lua_apex_resp_set_header);
    lua_setfield(L, -2, "set_header");
    lua_setfield(L, -2, "resp");

    /* apex top-level methods */
    lua_pushcfunction(L, lua_apex_say);
    lua_setfield(L, -2, "say");
    lua_pushcfunction(L, lua_apex_exit);
    lua_setfield(L, -2, "exit");
    lua_pushcfunction(L, lua_apex_log);
    lua_setfield(L, -2, "log");

    lua_setglobal(L, "apex");

    s_worker_lua_state = L;
    return true;
}

void apex_lua_thread_cleanup(void) {
    if (s_worker_lua_state != NULL) {
        lua_close(s_worker_lua_state);
        s_worker_lua_state = NULL;
    }
}

apex_action_t apex_lua_run_phase(apex_pipeline_ctx_t *ctx, const char *script,
                                 apex_phase_t phase, char *out_body,
                                 size_t out_body_cap, size_t *out_body_len) {
    (void)phase;
    if (ctx == NULL || script == NULL || script[0] == '\0') {
        return APEX_ACTION_CONTINUE;
    }

    if (!apex_lua_thread_init()) {
        return APEX_ACTION_CONTINUE;
    }

    lua_State *L = s_worker_lua_state;
    s_lua_current_ctx = ctx;
    s_lua_out_body = out_body;
    s_lua_out_cap = out_body_cap;
    s_lua_out_len = 0;
    s_lua_action = APEX_ACTION_CONTINUE;

    if (out_body != NULL && out_body_cap > 0) {
        out_body[0] = '\0';
    }

    int base_top = lua_gettop(L);

    int load_res = luaL_loadstring(L, script);
    if (load_res != 0) {
        const char *err = lua_tostring(L, -1);
        fprintf(stderr, "apex: lua compile error: %s\n", err ? err : "unknown error");
        lua_settop(L, base_top);
        s_lua_current_ctx = NULL;
        s_lua_out_body = NULL;
        s_lua_out_cap = 0;
        s_lua_out_len = 0;
        return APEX_ACTION_ERROR;
    }

    int pcall_res = lua_pcall(L, 0, 0, 0);
    if (pcall_res != 0) {
        const char *err = lua_tostring(L, -1);
        if (err != NULL && strstr(err, "__apex_exit__") != NULL) {
            /* Handled clean early exit */
        } else {
            fprintf(stderr, "apex: lua runtime error: %s\n", err ? err : "unknown error");
            s_lua_action = APEX_ACTION_ERROR;
        }
    }

    if (out_body_len != NULL) {
        *out_body_len = s_lua_out_len;
    }

    lua_settop(L, base_top);
    s_lua_current_ctx = NULL;
    s_lua_out_body = NULL;
    s_lua_out_cap = 0;
    s_lua_out_len = 0;

    return s_lua_action;
}
