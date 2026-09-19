#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    void *ptr;
    size_t len;
} cliproxy_buffer;

typedef int (*host_call_fn)(void *, const char *, const uint8_t *, size_t, cliproxy_buffer *);
typedef void (*host_free_fn)(void *, size_t);
typedef struct {
    uint32_t abi_version;
    void *host_ctx;
    host_call_fn call;
    host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*plugin_call_fn)(const char *, const uint8_t *, size_t, cliproxy_buffer *);
typedef void (*plugin_free_fn)(void *, size_t);
typedef void (*plugin_shutdown_fn)(void);
typedef struct {
    uint32_t abi_version;
    plugin_call_fn call;
    plugin_free_fn free_buffer;
    plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

typedef int (*plugin_init_fn)(const cliproxy_host_api *, cliproxy_plugin_api *);

static int unused_host_call(void *ctx, const char *method, const uint8_t *body, size_t len, cliproxy_buffer *out) {
    (void)ctx; (void)method; (void)body; (void)len;
    if (out) { out->ptr = NULL; out->len = 0; }
    return 1;
}

static void unused_host_free(void *ptr, size_t len) {
    (void)ptr; (void)len;
}

static int run_method(cliproxy_plugin_api *api, const char *method) {
    cliproxy_buffer response = {0};
    int rc = api->call(method, NULL, 0, &response);
    printf("method=%s rc=%d response=%.*s\n", method, rc, (int)response.len, (char *)response.ptr);
    if (response.ptr && api->free_buffer) {
        api->free_buffer(response.ptr, response.len);
    }
    return rc;
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "./target/debug/libfixgpt.so";
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 2;
    }

    plugin_init_fn init = (plugin_init_fn)dlsym(handle, "cliproxy_plugin_init");
    if (!init) {
        fprintf(stderr, "missing cliproxy_plugin_init: %s\n", dlerror());
        dlclose(handle);
        return 3;
    }

    cliproxy_host_api host = {1, NULL, unused_host_call, unused_host_free};
    cliproxy_plugin_api plugin = {0};
    if (init(&host, &plugin) != 0) {
        fprintf(stderr, "plugin init failed\n");
        dlclose(handle);
        return 4;
    }
    if (plugin.abi_version != 1 || !plugin.call || !plugin.free_buffer) {
        fprintf(stderr, "invalid plugin ABI\n");
        dlclose(handle);
        return 5;
    }

    int failed = 0;
    failed |= run_method(&plugin, "plugin.register");
    failed |= run_method(&plugin, "management.register");
    if (plugin.shutdown) {
        plugin.shutdown();
    }
    dlclose(handle);
    return failed ? 1 : 0;
}