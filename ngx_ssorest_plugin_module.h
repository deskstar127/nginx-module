#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define SSOZONE_DEFAULT "SM"

typedef struct {
    ngx_flag_t enable;
    ngx_flag_t trace_enable;
    ngx_str_t acoName;
    ngx_str_t gatewayUrl;
    ngx_str_t pluginId;
    ngx_str_t secretKey;
    ngx_str_t gatewayToken;
    ngx_str_t ssoZone;
    ngx_array_t *ignoreExt;
    ngx_array_t *ignoreUrl;
    ngx_pool_t *cf_pool; // TODO saving the cf pool so we can store gatewayTokens in it, is this the right technique?
} ngx_ssorest_plugin_conf_t;

