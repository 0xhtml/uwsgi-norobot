#include <openssl/sha.h>
#include <stdbool.h>
#include <uuid/uuid.h>
#include <uwsgi.h>

typedef unsigned char sha256_t[SHA256_DIGEST_LENGTH];
#define SECRET_STR_LEN (sizeof(uuid_t) * 2 + 1)
#define HASH_STR_LEN (sizeof(sha256_t) * 2 + 1)

static char *status = "200 OK";
static char *content_type = "text/html; charset=utf-8";
static char *content;
static unsigned long content_len;
static unsigned long content_secret_offset;
static unsigned long content_hash_offset;

static char *get_cookie(struct wsgi_request *request, char *key, uint16_t *len) {
    return uwsgi_get_cookie(request, key, strlen(key), len);
}

static char *get_var(struct wsgi_request *request, char *key, uint16_t *len) {
    return uwsgi_get_var(request, key, strlen(key), len);
}

static void gen_hash(uuid_t in, sha256_t raw_out, char *out) {
    SHA256(in, sizeof(uuid_t), raw_out);
    for (uint16_t i = 0; i < sizeof(sha256_t); ++i) {
        sprintf(out + i * 2, "%02x", raw_out[i]);
    }
}

static void gen_shared_secret(struct wsgi_request *request, struct uwsgi_route *route, uuid_t raw_out, char *out) {
    uint16_t ip_len;
    char *ip = get_var(request, "REMOTE_ADDR", &ip_len);

    uuid_generate_sha1(raw_out, route->data, ip, ip_len);

    for (uint16_t i = 0; i < sizeof(uuid_t); ++i) {
        sprintf(out + i * 2, "%02x", raw_out[i]);
    }
}

static bool check_cookie(struct wsgi_request *request, char *shared_secret) {
    uint16_t cookie_len;
    char *cookie = get_cookie(request, "secret", &cookie_len);

    if (cookie == NULL) return false;
    if (cookie_len != SECRET_STR_LEN - 1) return false; // w/o terminating null-byte
    if (memcmp(cookie, shared_secret, cookie_len)) return false;

    return true;
}

static int norobot_router_func(struct wsgi_request *request, struct uwsgi_route *route) {
    uuid_t raw_shared_secret;
    char shared_secret[SECRET_STR_LEN];
    gen_shared_secret(request, route, raw_shared_secret, shared_secret);

    if (check_cookie(request, shared_secret)) {
        return UWSGI_ROUTE_NEXT;
    }

    sha256_t raw_hash;
    char hash[HASH_STR_LEN];
    gen_hash(raw_shared_secret, raw_hash, hash);

    char cpy_content[content_len + 1];
    memcpy(cpy_content, content, content_len + 1);
    memcpy(cpy_content + content_secret_offset, shared_secret, strlen(shared_secret) - 4);
    memcpy(cpy_content + content_hash_offset, hash, strlen(hash));

    if (uwsgi_response_prepare_headers(request, status, strlen(status))) {
        return UWSGI_ROUTE_BREAK;
    }
    if (uwsgi_response_add_content_length(request, content_len)) {
        return UWSGI_ROUTE_BREAK;
    }
    if (uwsgi_response_add_content_type(request, content_type, strlen(content_type))) {
        return UWSGI_ROUTE_BREAK;
    }

    uwsgi_response_write_body_do(request, cpy_content, content_len);
    return UWSGI_ROUTE_BREAK;
}

static int norobot_router(struct uwsgi_route *route, char *args) {
    if (strlen(args) == 0) {
        char uuid[SECRET_STR_LEN];
        uwsgi_uuid(uuid);
        uwsgi_log("invalid route syntax: norobot missing uuid, replace with norobot:%s\n", uuid);
        exit(1);
    }

    route->data = uwsgi_malloc(sizeof(uuid_t));
    if (uuid_parse(args, route->data)) {
        uwsgi_log("invalid route syntax: error parsing uuid %s\n", args);
        exit(1);
    }

    route->func = norobot_router_func;

    return 0;
}

static void norobot_on_load() {
    FILE *f = fopen("check.html", "r");

    fseek(f, 0, SEEK_END);
    content_len = ftell(f);
    rewind(f);

    content = uwsgi_malloc(content_len + 1);
    fread(content, content_len, 1, f);
    content[content_len] = '\0';

    fclose(f);

    content_secret_offset = strstr(content, "secret = ") - content + 33;
    content_hash_offset = strstr(content, "hash = ") - content + 31;

    uwsgi_register_router("norobot", norobot_router);
}

struct uwsgi_plugin norobot_plugin = {
    .name = "norobot",
    .on_load = norobot_on_load,
};
