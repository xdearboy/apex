#include "apex/wasm_engine.h"
#include "internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wasmedge/wasmedge.h>

static __thread WasmEdge_ConfigureContext *s_worker_wasm_conf = NULL;
static __thread WasmEdge_VMContext *s_worker_wasm_vm = NULL;
static __thread WasmEdge_ModuleInstanceContext *s_worker_wasm_mod = NULL;
static __thread apex_pipeline_ctx_t *s_wasm_current_ctx = NULL;
static __thread char *s_wasm_out_body = NULL;
static __thread size_t s_wasm_out_cap = 0;
static __thread size_t s_wasm_out_len = 0;
static __thread apex_action_t s_wasm_action = APEX_ACTION_CONTINUE;

/* ========================================================================= */
/* Wasm Host Functions for Proxy ABI (Module: "env")                         */
/* ========================================================================= */

/* int32_t proxy_get_header(int32_t name_ptr, int32_t name_len, int32_t buf_ptr, int32_t buf_cap) */
static WasmEdge_Result host_proxy_get_header(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                            const WasmEdge_Value *Params, WasmEdge_Value *Returns) {
    (void)Data;
    uint32_t name_ptr = (uint32_t)WasmEdge_ValueGetI32(Params[0]);
    uint32_t name_len = (uint32_t)WasmEdge_ValueGetI32(Params[1]);
    uint32_t buf_ptr = (uint32_t)WasmEdge_ValueGetI32(Params[2]);
    uint32_t buf_cap = (uint32_t)WasmEdge_ValueGetI32(Params[3]);

    WasmEdge_MemoryInstanceContext *Mem = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);
    if (Mem == NULL || s_wasm_current_ctx == NULL || name_len >= 256) {
        Returns[0] = WasmEdge_ValueGenI32(-1);
        return WasmEdge_Result_Success;
    }

    char name_buf[256];
    if (!WasmEdge_ResultOK(WasmEdge_MemoryInstanceGetData(Mem, (uint8_t *)name_buf, name_ptr, name_len))) {
        Returns[0] = WasmEdge_ValueGenI32(-1);
        return WasmEdge_Result_Success;
    }
    name_buf[name_len] = '\0';

    const char *val = NULL;
    size_t val_len = 0;
    if (!apex_pipeline_find_header(s_wasm_current_ctx, name_buf, &val, &val_len) || val == NULL) {
        Returns[0] = WasmEdge_ValueGenI32(-1);
        return WasmEdge_Result_Success;
    }

    uint32_t to_write = (uint32_t)(val_len < buf_cap ? val_len : buf_cap);
    if (to_write > 0) {
        uint8_t *dest = WasmEdge_MemoryInstanceGetPointer(Mem, buf_ptr, to_write);
        if (dest == NULL) {
            Returns[0] = WasmEdge_ValueGenI32(-1);
            return WasmEdge_Result_Success;
        }
        memcpy(dest, val, to_write);
    }

    Returns[0] = WasmEdge_ValueGenI32((int32_t)to_write);
    return WasmEdge_Result_Success;
}

/* int32_t proxy_set_header(int32_t name_ptr, int32_t name_len, int32_t val_ptr, int32_t val_len) */
static WasmEdge_Result host_proxy_set_header(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                            const WasmEdge_Value *Params, WasmEdge_Value *Returns) {
    (void)Data;
    uint32_t name_ptr = (uint32_t)WasmEdge_ValueGetI32(Params[0]);
    uint32_t name_len = (uint32_t)WasmEdge_ValueGetI32(Params[1]);
    uint32_t val_ptr = (uint32_t)WasmEdge_ValueGetI32(Params[2]);
    uint32_t val_len = (uint32_t)WasmEdge_ValueGetI32(Params[3]);

    WasmEdge_MemoryInstanceContext *Mem = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);
    if (Mem == NULL || s_wasm_current_ctx == NULL || name_len >= 256 || val_len >= 1024) {
        Returns[0] = WasmEdge_ValueGenI32(-1);
        return WasmEdge_Result_Success;
    }

    char name_buf[256];
    char val_buf[1024];
    if (!WasmEdge_ResultOK(WasmEdge_MemoryInstanceGetData(Mem, (uint8_t *)name_buf, name_ptr, name_len)) ||
        !WasmEdge_ResultOK(WasmEdge_MemoryInstanceGetData(Mem, (uint8_t *)val_buf, val_ptr, val_len))) {
        Returns[0] = WasmEdge_ValueGenI32(-1);
        return WasmEdge_Result_Success;
    }
    name_buf[name_len] = '\0';
    val_buf[val_len] = '\0';

    apex_pipeline_add_header(s_wasm_current_ctx, name_buf, val_buf);
    Returns[0] = WasmEdge_ValueGenI32(0);
    return WasmEdge_Result_Success;
}

/* int32_t proxy_get_uri(int32_t buf_ptr, int32_t buf_cap) */
static WasmEdge_Result host_proxy_get_uri(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                         const WasmEdge_Value *Params, WasmEdge_Value *Returns) {
    (void)Data;
    uint32_t buf_ptr = (uint32_t)WasmEdge_ValueGetI32(Params[0]);
    uint32_t buf_cap = (uint32_t)WasmEdge_ValueGetI32(Params[1]);

    WasmEdge_MemoryInstanceContext *Mem = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);
    if (Mem == NULL || s_wasm_current_ctx == NULL || s_wasm_current_ctx->path == NULL) {
        Returns[0] = WasmEdge_ValueGenI32(0);
        return WasmEdge_Result_Success;
    }

    size_t len = s_wasm_current_ctx->path_len;
    uint32_t to_write = (uint32_t)(len < buf_cap ? len : buf_cap);
    if (to_write > 0) {
        uint8_t *dest = WasmEdge_MemoryInstanceGetPointer(Mem, buf_ptr, to_write);
        if (dest == NULL) {
            Returns[0] = WasmEdge_ValueGenI32(-1);
            return WasmEdge_Result_Success;
        }
        memcpy(dest, s_wasm_current_ctx->path, to_write);
    }

    Returns[0] = WasmEdge_ValueGenI32((int32_t)to_write);
    return WasmEdge_Result_Success;
}

/* int32_t proxy_get_method(int32_t buf_ptr, int32_t buf_cap) */
static WasmEdge_Result host_proxy_get_method(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                            const WasmEdge_Value *Params, WasmEdge_Value *Returns) {
    (void)Data;
    uint32_t buf_ptr = (uint32_t)WasmEdge_ValueGetI32(Params[0]);
    uint32_t buf_cap = (uint32_t)WasmEdge_ValueGetI32(Params[1]);

    WasmEdge_MemoryInstanceContext *Mem = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);
    if (Mem == NULL || s_wasm_current_ctx == NULL || s_wasm_current_ctx->method == NULL) {
        Returns[0] = WasmEdge_ValueGenI32(0);
        return WasmEdge_Result_Success;
    }

    size_t len = s_wasm_current_ctx->method_len;
    uint32_t to_write = (uint32_t)(len < buf_cap ? len : buf_cap);
    if (to_write > 0) {
        uint8_t *dest = WasmEdge_MemoryInstanceGetPointer(Mem, buf_ptr, to_write);
        if (dest == NULL) {
            Returns[0] = WasmEdge_ValueGenI32(-1);
            return WasmEdge_Result_Success;
        }
        memcpy(dest, s_wasm_current_ctx->method, to_write);
    }

    Returns[0] = WasmEdge_ValueGenI32((int32_t)to_write);
    return WasmEdge_Result_Success;
}

/* int32_t proxy_set_status(int32_t code) */
static WasmEdge_Result host_proxy_set_status(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                            const WasmEdge_Value *Params, WasmEdge_Value *Returns) {
    (void)Data;
    (void)CallFrameCxt;
    int32_t code = WasmEdge_ValueGetI32(Params[0]);
    if (s_wasm_current_ctx != NULL) {
        s_wasm_current_ctx->status_code = (int)code;
    }
    Returns[0] = WasmEdge_ValueGenI32(0);
    return WasmEdge_Result_Success;
}

/* int32_t proxy_say(int32_t body_ptr, int32_t body_len) */
static WasmEdge_Result host_proxy_say(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                      const WasmEdge_Value *Params, WasmEdge_Value *Returns) {
    (void)Data;
    uint32_t body_ptr = (uint32_t)WasmEdge_ValueGetI32(Params[0]);
    uint32_t body_len = (uint32_t)WasmEdge_ValueGetI32(Params[1]);

    WasmEdge_MemoryInstanceContext *Mem = WasmEdge_CallingFrameGetMemoryInstance(CallFrameCxt, 0);
    if (Mem != NULL && s_wasm_out_body != NULL && s_wasm_out_len + body_len < s_wasm_out_cap) {
        uint8_t *src = WasmEdge_MemoryInstanceGetPointer(Mem, body_ptr, body_len);
        if (src != NULL) {
            memcpy(s_wasm_out_body + s_wasm_out_len, src, body_len);
            s_wasm_out_len += body_len;
            s_wasm_out_body[s_wasm_out_len] = '\0';
            s_wasm_action = APEX_ACTION_DONE;
            if (s_wasm_current_ctx != NULL && s_wasm_current_ctx->status_code == 0) {
                s_wasm_current_ctx->status_code = 200;
            }
        }
    }

    Returns[0] = WasmEdge_ValueGenI32(0);
    return WasmEdge_Result_Success;
}

/* int32_t proxy_exit(int32_t code) */
static WasmEdge_Result host_proxy_exit(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                       const WasmEdge_Value *Params, WasmEdge_Value *Returns) {
    (void)Data;
    (void)CallFrameCxt;
    int32_t code = WasmEdge_ValueGetI32(Params[0]);
    if (s_wasm_current_ctx != NULL) {
        s_wasm_current_ctx->status_code = (int)code;
    }
    if (code >= 400) {
        s_wasm_action = APEX_ACTION_DENY;
    } else {
        s_wasm_action = APEX_ACTION_DONE;
    }
    Returns[0] = WasmEdge_ValueGenI32(0);
    return WasmEdge_Result_Success;
}

/* ========================================================================= */
/* Engine Lifecycle                                                          */
/* ========================================================================= */

static void register_host_func(WasmEdge_ModuleInstanceContext *Mod, const char *name,
                               WasmEdge_HostFunc_t func, const WasmEdge_ValType *params,
                               uint32_t param_len, const WasmEdge_ValType *rets, uint32_t ret_len) {
    WasmEdge_FunctionTypeContext *FType = WasmEdge_FunctionTypeCreate(params, param_len, rets, ret_len);
    WasmEdge_FunctionInstanceContext *FCxt = WasmEdge_FunctionInstanceCreate(FType, func, NULL, 0);
    WasmEdge_FunctionTypeDelete(FType);

    WasmEdge_String Str = WasmEdge_StringCreateByCString(name);
    WasmEdge_ModuleInstanceAddFunction(Mod, Str, FCxt);
    WasmEdge_StringDelete(Str);
}

bool apex_wasm_thread_init(void) {
    if (s_worker_wasm_vm != NULL) {
        return true;
    }

    s_worker_wasm_conf = WasmEdge_ConfigureCreate();
    if (s_worker_wasm_conf == NULL) {
        return false;
    }

    s_worker_wasm_vm = WasmEdge_VMCreate(s_worker_wasm_conf, NULL);
    if (s_worker_wasm_vm == NULL) {
        WasmEdge_ConfigureDelete(s_worker_wasm_conf);
        s_worker_wasm_conf = NULL;
        return false;
    }

    /* Create and register host module "env" */
    WasmEdge_String ModName = WasmEdge_StringCreateByCString("env");
    s_worker_wasm_mod = WasmEdge_ModuleInstanceCreate(ModName);
    WasmEdge_StringDelete(ModName);

    WasmEdge_ValType p_4i32[] = {
        WasmEdge_ValTypeGenI32(), WasmEdge_ValTypeGenI32(),
        WasmEdge_ValTypeGenI32(), WasmEdge_ValTypeGenI32()
    };
    WasmEdge_ValType p_2i32[] = {
        WasmEdge_ValTypeGenI32(), WasmEdge_ValTypeGenI32()
    };
    WasmEdge_ValType p_1i32[] = {
        WasmEdge_ValTypeGenI32()
    };
    WasmEdge_ValType r_1i32[] = {
        WasmEdge_ValTypeGenI32()
    };

    register_host_func(s_worker_wasm_mod, "proxy_get_header", host_proxy_get_header, p_4i32, 4, r_1i32, 1);
    register_host_func(s_worker_wasm_mod, "proxy_set_header", host_proxy_set_header, p_4i32, 4, r_1i32, 1);
    register_host_func(s_worker_wasm_mod, "proxy_get_uri", host_proxy_get_uri, p_2i32, 2, r_1i32, 1);
    register_host_func(s_worker_wasm_mod, "proxy_get_method", host_proxy_get_method, p_2i32, 2, r_1i32, 1);
    register_host_func(s_worker_wasm_mod, "proxy_set_status", host_proxy_set_status, p_1i32, 1, r_1i32, 1);
    register_host_func(s_worker_wasm_mod, "proxy_say", host_proxy_say, p_2i32, 2, r_1i32, 1);
    register_host_func(s_worker_wasm_mod, "proxy_exit", host_proxy_exit, p_1i32, 1, r_1i32, 1);

    WasmEdge_VMRegisterModuleFromImport(s_worker_wasm_vm, s_worker_wasm_mod);

    return true;
}

void apex_wasm_thread_cleanup(void) {
    if (s_worker_wasm_vm != NULL) {
        WasmEdge_VMDelete(s_worker_wasm_vm);
        s_worker_wasm_vm = NULL;
    }
    if (s_worker_wasm_mod != NULL) {
        WasmEdge_ModuleInstanceDelete(s_worker_wasm_mod);
        s_worker_wasm_mod = NULL;
    }
    if (s_worker_wasm_conf != NULL) {
        WasmEdge_ConfigureDelete(s_worker_wasm_conf);
        s_worker_wasm_conf = NULL;
    }
}

apex_action_t apex_wasm_run_filter(apex_pipeline_ctx_t *ctx, const char *wasm_path,
                                   char *out_body, size_t out_body_cap, size_t *out_body_len) {
    if (ctx == NULL || wasm_path == NULL || wasm_path[0] == '\0') {
        return APEX_ACTION_CONTINUE;
    }

    if (!apex_wasm_thread_init()) {
        return APEX_ACTION_CONTINUE;
    }

    s_wasm_current_ctx = ctx;
    s_wasm_out_body = out_body;
    s_wasm_out_cap = out_body_cap;
    s_wasm_out_len = 0;
    s_wasm_action = APEX_ACTION_CONTINUE;

    if (out_body != NULL && out_body_cap > 0) {
        out_body[0] = '\0';
    }

    /* Try entrypoint names */
    const char *entry_names[] = {"filter_run", "proxy_on_request_headers", "_start"};
    bool executed = false;

    for (size_t i = 0; i < sizeof(entry_names) / sizeof(entry_names[0]); i++) {
        WasmEdge_String Entry = WasmEdge_StringCreateByCString(entry_names[i]);
        WasmEdge_Value Returns[1];
        WasmEdge_Result Res = WasmEdge_VMRunWasmFromFile(s_worker_wasm_vm, wasm_path, Entry, NULL, 0, Returns, 1);
        WasmEdge_StringDelete(Entry);
        if (WasmEdge_ResultOK(Res)) {
            int32_t ret_val = WasmEdge_ValueGetI32(Returns[0]);
            if (ret_val == 0) {
                if (s_wasm_action == APEX_ACTION_CONTINUE) {
                    s_wasm_action = APEX_ACTION_CONTINUE;
                }
            } else if (ret_val == 1) {
                s_wasm_action = APEX_ACTION_DENY;
                if (ctx->status_code == 0) {
                    ctx->status_code = 403;
                }
            } else if (ret_val >= 400) {
                s_wasm_action = APEX_ACTION_DENY;
                ctx->status_code = (int)ret_val;
            } else {
                s_wasm_action = APEX_ACTION_DONE;
            }
            executed = true;
            break;
        }
    }

    if (!executed) {
        /* Run without return value if functions take no returns */
        for (size_t i = 0; i < sizeof(entry_names) / sizeof(entry_names[0]); i++) {
            WasmEdge_String Entry = WasmEdge_StringCreateByCString(entry_names[i]);
            WasmEdge_Result Res = WasmEdge_VMRunWasmFromFile(s_worker_wasm_vm, wasm_path, Entry, NULL, 0, NULL, 0);
            WasmEdge_StringDelete(Entry);
            if (WasmEdge_ResultOK(Res)) {
                executed = true;
                break;
            }
        }
    }

    if (!executed) {
        fprintf(stderr, "apex: failed to execute wasm filter '%s'\n", wasm_path);
    }

    if (out_body_len != NULL) {
        *out_body_len = s_wasm_out_len;
    }

    s_wasm_current_ctx = NULL;
    s_wasm_out_body = NULL;
    s_wasm_out_cap = 0;
    s_wasm_out_len = 0;

    return s_wasm_action;
}
