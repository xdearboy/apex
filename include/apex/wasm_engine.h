#ifndef APEX_WASM_ENGINE_H
#define APEX_WASM_ENGINE_H

#include "apex/module.h"
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize WasmEdge runtime for current thread */
bool apex_wasm_thread_init(void);

/* Tear down WasmEdge runtime for current thread */
void apex_wasm_thread_cleanup(void);

/* Execute a WebAssembly filter (.wasm file) on the given pipeline context */
apex_action_t apex_wasm_run_filter(apex_pipeline_ctx_t *ctx, const char *wasm_path,
                                   char *out_body, size_t out_body_cap, size_t *out_body_len);

#ifdef __cplusplus
}
#endif

#endif /* APEX_WASM_ENGINE_H */
