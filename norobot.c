#include <uwsgi.h>
#include <uuid/uuid.h>
#include <openssl/sha.h>

static char *get_cookie(struct wsgi_request *request, char *key, uint16_t *len) {
    return uwsgi_get_cookie(request, key, strlen(key), len);
}

static char *get_var(struct wsgi_request *request, char *key, uint16_t *len) {
    return uwsgi_get_var(request, key, strlen(key), len);
}

static void get_ip(unsigned char *out, struct wsgi_request *request) {
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

static void gen_secret(struct wsgi_request *request, struct uwsgi_route *route, unsigned char *out) {
    unsigned char data[4 + sizeof(uuid_t)] = {};
    get_ip(data, request);
    memcpy(data + 4, route->data, sizeof(uuid_t));
    SHA256(data, sizeof(data), out);
}

static void to_str(unsigned char *in, uint16_t len, char *out) {
    for (uint16_t i = 0; i < len; ++i) {
        sprintf(out + i * 2, "%02x", in[i]);
    }
}

static char *status = "200 OK";
static char *content_type = "text/html; charset=utf-8";
#define CALC_DIGITS 5
#define ENTER_DIGITS 3

static int norobot_router_func(struct wsgi_request *request, struct uwsgi_route *route) {
    unsigned char secret[SHA256_DIGEST_LENGTH];
    gen_secret(request, route, secret);

    char secret_str[sizeof(secret) * 2 + 1] = {};
    to_str(secret, sizeof(secret), secret_str);

    uint16_t cookie_len;
    char *cookie = get_cookie(request, "secret", &cookie_len);

    if (cookie != NULL && cookie_len == sizeof(secret) * 2 && !memcmp(cookie, secret_str, cookie_len)) {
        return UWSGI_ROUTE_NEXT;
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(secret, sizeof(secret), hash);

    char hash_str[sizeof(hash) * 2 + 1] = {};
    to_str(hash, sizeof(hash), hash_str);

    char content[2048] = {};
    int offset = (int) sizeof(secret) * 2 - CALC_DIGITS - ENTER_DIGITS;
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
        ENTER_DIGITS, secret_str + offset,
        ENTER_DIGITS,
        offset, secret_str,
        CALC_DIGITS, 0,
        hash_str,
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
    route->func = norobot_router_func;

    route->data = uwsgi_malloc(sizeof(uuid_t));

    if (strlen(args) > 0) {
        if (uuid_parse(args, route->data)) {
            uwsgi_log("error parsing uuid %s\n", args);
            exit(1);
        }
    } else {
        uuid_generate(route->data);
    }

    return 0;
}

static void register_norobot_router() {
    uwsgi_register_router("norobot", norobot_router);
}

struct uwsgi_plugin norobot_plugin = {
    .name = "norobot",
    .on_load = register_norobot_router,
};
