#ifndef APEX_LUA_ENGINE_H
#define APEX_LUA_ENGINE_H

#include "apex/module.h"
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize LuaJIT VM for the current worker thread (lazy on first call) */
bool apex_lua_thread_init(void);

/* Tear down LuaJIT VM for the current worker thread */
void apex_lua_thread_cleanup(void);

/* Execute a Lua hook script within the given pipeline context */
apex_action_t apex_lua_run_phase(apex_pipeline_ctx_t *ctx, const char *script,
                                 apex_phase_t phase, char *out_body,
                                 size_t out_body_cap, size_t *out_body_len);

#ifdef __cplusplus
}
#endif

#endif /* APEX_LUA_ENGINE_H */
