#include <openssl/sha.h>
#include <stdbool.h>
#include <uuid/uuid.h>
#include <uwsgi.h>

static char *get_cookie(struct wsgi_request *request, char *key, uint16_t *len) {
    return uwsgi_get_cookie(request, key, strlen(key), len);
}

static char *get_var(struct wsgi_request *request, char *key, uint16_t *len) {
    return uwsgi_get_var(request, key, strlen(key), len);
}

static void get_ip(struct wsgi_request *request, unsigned char *out) {
    uint16_t len;
    char *ip = get_var(request, "REMOTE_ADDR", &len);
    int j = 0;

    for (int i = 0; i < 4; ++i) {
        out[i] = 0;

        while (j < len && ip[j] != '.') {
            out[i] = (out[i] * 10) + (ip[j++] - '0');
        }

        ++j; // skip '.'
    }
}

#define RAW_HASH_LEN SHA256_DIGEST_LENGTH
#define HASH_LEN (RAW_HASH_LEN * 2 + 1)

static void gen_hash(unsigned char *in, uint16_t in_len, unsigned char *raw_out, char *out) {
    SHA256(in, in_len, raw_out);
    for (uint16_t i = 0; i < RAW_HASH_LEN; ++i) {
        sprintf(out + i * 2, "%02x", raw_out[i]);
    }
}

static void gen_shared_secret(struct wsgi_request *request, struct uwsgi_route *route, unsigned char *raw_out, char *out) {
    struct {
        uuid_t uuid;
        unsigned char ip[4];
    } data;

    memcpy(data.uuid, route->data, sizeof(uuid_t));
    get_ip(request, data.ip);

    gen_hash((unsigned char *) &data, sizeof(data), raw_out, out);
}

static bool check_cookie(struct wsgi_request *request, char *shared_secret) {
    uint16_t cookie_len;
    char *cookie = get_cookie(request, "secret", &cookie_len);

    if (cookie == NULL) return false;
    if (cookie_len != HASH_LEN - 1) return false; // w/o terminating null-byte
    if (memcmp(cookie, shared_secret, cookie_len)) return false;

    return true;
}

static char *status = "200 OK";
static char *content_type = "text/html; charset=utf-8";
#define CALC_DIGITS 5
#define ENTER_DIGITS 3

static int norobot_router_func(struct wsgi_request *request, struct uwsgi_route *route) {
    unsigned char raw_shared_secret[RAW_HASH_LEN];
    char shared_secret[HASH_LEN];
    gen_shared_secret(request, route, raw_shared_secret, shared_secret);

    if (check_cookie(request, shared_secret)) {
        return UWSGI_ROUTE_NEXT;
    }

    unsigned char raw_hash[RAW_HASH_LEN];
    char hash[HASH_LEN];
    gen_hash(raw_shared_secret, sizeof(raw_shared_secret), raw_hash, hash);

    char content[2048] = {};
    int offset = HASH_LEN - 1 - CALC_DIGITS - ENTER_DIGITS;
    uint16_t content_len = snprintf(
        content,
        sizeof(content),
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        "    <title>Checking connection</title>\n"
        "</head>\n"
        "<body>\n"
        "    <h1>Checking connection...</h1>\n"
        "    <p>Diese Zeichen: %.*s</p>\n"
        "    <input id='digits' type='text' placeholder='Zeichen eingeben'>\n"
        "    <button onclick='calc()'>Verify</button>\n"
        "    <script src='https://unpkg.com/crypto-js@4.1.1/crypto-js.js'></script>\n"
        "    <script>\n"
        "        function calc() {\n"
        "            const el = document.getElementById('digits');\n"
        "            if (el.value.length != %i) {\n"
        "                el.value = '';\n"
        "                return;\n"
        "            }\n"
        "            const secret = CryptoJS.enc.Hex.parse('%.*s' + el.value + '%0*i');\n"
        "            const hash = CryptoJS.enc.Hex.parse('%s');\n"
        "            for (let i = 0; i < 16 ** %i; i++) {\n"
        "                let testHash = CryptoJS.SHA256(secret);\n"
        "                if (\n"
        "                    hash.words[0] == testHash.words[0] &&\n"
        "                    hash.words[1] == testHash.words[1] &&\n"
        "                    hash.words[2] == testHash.words[2] &&\n"
        "                    hash.words[3] == testHash.words[3] &&\n"
        "                    hash.words[4] == testHash.words[4] &&\n"
        "                    hash.words[5] == testHash.words[5] &&\n"
        "                    hash.words[6] == testHash.words[6] &&\n"
        "                    hash.words[7] == testHash.words[7]\n"
        "                ) {\n"
        "                    document.cookie = 'secret=' + CryptoJS.enc.Hex.stringify(secret) + '; Max-Age=' + (60*60*24*31) + '; Secure; SameSite=Strict'\n"
        "                    location.reload();\n"
        "                    return;\n"
        "                }\n"
        "                secret.words[7]++;\n"
        "            }\n"
        "            el.value = '';\n"
        "        }\n"
        "    </script>\n"
        "</body>\n"
        "</html>",
        ENTER_DIGITS, shared_secret + offset,
        ENTER_DIGITS,
        offset, shared_secret,
        CALC_DIGITS, 0,
        hash,
        CALC_DIGITS
    );

    if (uwsgi_response_prepare_headers(request, status, strlen(status))) {
        return UWSGI_ROUTE_BREAK;
    }

    if (uwsgi_response_add_content_length(request, content_len)) {
        return UWSGI_ROUTE_BREAK;
    }

    if (uwsgi_response_add_content_type(request, content_type, strlen(content_type))) {
        return UWSGI_ROUTE_BREAK;
    }

    uwsgi_response_write_body_do(request, content, content_len);
    return UWSGI_ROUTE_BREAK;
}

static int norobot_router(struct uwsgi_route *route, char *args) {
    if (strlen(args) == 0) {
        char uuid[37];
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

static void register_norobot_router() {
    uwsgi_register_router("norobot", norobot_router);
}

struct uwsgi_plugin norobot_plugin = {
    .name = "norobot",
    .on_load = register_norobot_router,
};
