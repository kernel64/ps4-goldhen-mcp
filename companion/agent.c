// ps4-dev-agent: a small TCP command server running as a thread inside a system daemon.
// Freestanding: ps4_goldhen_mcp/agent.py copies the flat binary into the host process, fills
// struct agent_table with the system functions and starts agent_main(table). No imports, no
// relocations, no globals (companion/build.py checks).
//
// One command per line, one reply per line ("OK ..." or "ERR <code hex> <text>"):
//   PING                      -> OK ps4-dev-agent <version> <base hex> <size hex> <host pid>
//   FGUSER                    -> OK <user id hex>
//   BIGAPP                    -> OK <app id hex>         (bit 31 set: no big app, it is the SCE error)
//   LAUNCH <TITLEID> [args]   -> OK <app id hex>         sceLncUtilLaunchApp from this process
//   KILL <app id hex>         -> OK                      sceSystemServiceKillApp(id, -1, 0, 0)
//   KILLBIG                   -> OK <app id hex>         kill the running big app
//   PKGINFO <path>            -> OK <TITLEID> <is_app>   sceAppInstUtilGetTitleIdFromPkg
//   INSTALL <path>            -> OK [<CONTENTID>]        sceAppInstUtilAppInstallPkg (pkg on the console)
//   EXISTS <TITLEID>          -> OK <0|1>
//   UNINSTALL <TITLEID>       -> OK                      sceAppInstUtilAppUnInstall
//   QUIT                      -> OK bye  (the thread exits; the host process keeps running)

#include "agent_table.h"

// sceLncUtilLaunchApp's parameter on 5.05: 0x18 bytes, not the 0x20 of OpenOrbis' header.
// Don't use sceSystemServiceLaunchApp instead: it drops the user and SceShellUI crashes (see README).
struct lnc_app_param {
    u32 size;
    u32 user_id;
    u32 app_attr;
    u32 crash_report;
    u64 check_flag;
};

#define LINE_MAX 1024
#define MAX_ARGS 8

static int streq(const char *a, const char *b) {
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

static char *put_s(char *p, char *end, const char *s) {
    while (*s && p < end)
        *p++ = *s++;
    return p;
}

static char *put_hex(char *p, char *end, u64 v) {
    int shift = 60;
    while (shift > 0 && ((v >> shift) & 0xf) == 0)
        shift -= 4;
    for (; shift >= 0 && p < end; shift -= 4) {
        u32 d = (u32)((v >> shift) & 0xf);
        *p++ = (char)(d < 10 ? '0' + d : 'a' + d - 10);
    }
    return p;
}

static char *put_dec(char *p, char *end, u32 v) {
    char tmp[10];
    int n = 0;
    do {
        tmp[n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    while (n > 0 && p < end)
        *p++ = tmp[--n];
    return p;
}

static int parse_hex(const char *s, u32 *out) {
    u64 v = 0;
    int n = 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        s += 2;
    for (; *s; s++, n++) {
        char c = *s;
        u32 d;
        if (c >= '0' && c <= '9')
            d = (u32)(c - '0');
        else if (c >= 'a' && c <= 'f')
            d = (u32)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            d = (u32)(c - 'A' + 10);
        else
            return 0;
        v = (v << 4) | d;
        if (v > 0xffffffffULL)
            return 0;
    }
    if (n == 0)
        return 0;
    *out = (u32)v;
    return 1;
}

static int is_title_id(const char *s) {
    int i;
    for (i = 0; i < 4; i++)
        if (s[i] < 'A' || s[i] > 'Z')
            return 0;
    for (i = 4; i < 9; i++)
        if (s[i] < '0' || s[i] > '9')
            return 0;
    return s[9] == 0;
}

// Cuts the next space-separated word out of *cur (in place). Returns 0 when there is none.
static char *next_word(char **cur) {
    char *p = *cur;
    char *w;
    while (*p == ' ')
        p++;
    if (!*p) {
        *cur = p;
        return 0;
    }
    w = p;
    while (*p && *p != ' ')
        p++;
    if (*p)
        *p++ = 0;
    *cur = p;
    return w;
}

static void send_all(struct agent_table *t, int fd, const char *buf, u64 len) {
    while (len) {
        int n = t->net_send(fd, buf, len, 0);
        if (n <= 0)
            return;
        buf += n;
        len -= (u64)n;
    }
}

static void reply_err(struct agent_table *t, int fd, int code, const char *text) {
    char out[160];
    char *end = out + sizeof(out) - 1;
    char *p = put_s(out, end, "ERR ");
    p = put_hex(p, end, (u32)code);
    p = put_s(p, end, " ");
    p = put_s(p, end, text);
    *p++ = '\n';
    send_all(t, fd, out, (u64)(p - out));
}

static void reply_ok_hex(struct agent_table *t, int fd, u32 v) {
    char out[32];
    char *end = out + sizeof(out) - 1;
    char *p = put_s(out, end, "OK ");
    p = put_hex(p, end, v);
    *p++ = '\n';
    send_all(t, fd, out, (u64)(p - out));
}

static void reply_ok(struct agent_table *t, int fd, const char *text) {
    char out[64];
    char *end = out + sizeof(out) - 1;
    char *p = put_s(out, end, "OK");
    if (text) {
        p = put_s(p, end, " ");
        p = put_s(p, end, text);
    }
    *p++ = '\n';
    send_all(t, fd, out, (u64)(p - out));
}

// Returns 1 when the agent has to stop.
static int handle_line(struct agent_table *t, int fd, char *line) {
    char *cur = line;
    char *cmd = next_word(&cur);
    int rc;

    if (!cmd) {
        reply_err(t, fd, 0, "empty command");
        return 0;
    }

    if (streq(cmd, "PING")) {
        char out[96];
        char *end = out + sizeof(out) - 1;
        char *p = put_s(out, end, "OK ps4-dev-agent ");
        p = put_dec(p, end, AGENT_VERSION);
        p = put_s(p, end, " ");
        p = put_hex(p, end, t->base);
        p = put_s(p, end, " ");
        p = put_hex(p, end, t->size);
        p = put_s(p, end, " ");
        p = put_dec(p, end, t->host_pid);
        *p++ = '\n';
        send_all(t, fd, out, (u64)(p - out));
        return 0;
    }

    if (streq(cmd, "QUIT")) {
        reply_ok(t, fd, "bye");
        return 1;
    }

    if (streq(cmd, "FGUSER")) {
        int user = -1;
        rc = t->get_foreground_user(&user);
        if (rc < 0)
            reply_err(t, fd, rc, "sceUserServiceGetForegroundUser");
        else
            reply_ok_hex(t, fd, (u32)user);
        return 0;
    }

    if (streq(cmd, "BIGAPP")) {
        reply_ok_hex(t, fd, (u32)t->big_app_id());
        return 0;
    }

    if (streq(cmd, "LAUNCH")) {
        const char *argv[MAX_ARGS + 1];
        struct lnc_app_param param;
        char *title = next_word(&cur);
        char *arg;
        int argc = 0;
        int user = -1;

        if (!title || !is_title_id(title)) {
            reply_err(t, fd, 0, "bad title id");
            return 0;
        }
        while ((arg = next_word(&cur)) != 0) {
            if (argc == MAX_ARGS) {
                reply_err(t, fd, 0, "too many arguments");
                return 0;
            }
            argv[argc++] = arg;
        }
        argv[argc] = 0;
        rc = t->get_foreground_user(&user);
        if (rc < 0) {
            reply_err(t, fd, rc, "sceUserServiceGetForegroundUser");
            return 0;
        }
        param.size = sizeof(param);
        param.user_id = (u32)user;
        param.app_attr = 0;
        param.crash_report = 0;
        param.check_flag = 0;
        rc = t->launch_app(title, argc ? argv : 0, &param);
        if (rc < 0)
            reply_err(t, fd, rc, "sceLncUtilLaunchApp");
        else
            reply_ok_hex(t, fd, (u32)rc);
        return 0;
    }

    if (streq(cmd, "KILL")) {
        char *word = next_word(&cur);
        u32 app_id;
        if (!word || !parse_hex(word, &app_id) || (app_id & 0x80000000u)) {
            reply_err(t, fd, 0, "bad app id");
            return 0;
        }
        rc = t->kill_app((int)app_id, -1, 0, 0);
        if (rc < 0)
            reply_err(t, fd, rc, "sceSystemServiceKillApp");
        else
            reply_ok(t, fd, 0);
        return 0;
    }

    if (streq(cmd, "KILLBIG")) {
        int app_id = t->big_app_id();
        if (app_id < 0) {
            reply_err(t, fd, app_id, "no big app");
            return 0;
        }
        rc = t->kill_app(app_id, -1, 0, 0);
        if (rc < 0)
            reply_err(t, fd, rc, "sceSystemServiceKillApp");
        else
            reply_ok_hex(t, fd, (u32)app_id);
        return 0;
    }

    if (streq(cmd, "PKGINFO") || streq(cmd, "INSTALL") || streq(cmd, "EXISTS") || streq(cmd, "UNINSTALL")) {
        char *word = next_word(&cur);
        int by_path = streq(cmd, "PKGINFO") || streq(cmd, "INSTALL");

        if (!t->inst_initialize || !t->inst_install_pkg || !t->inst_title_id_from_pkg || !t->inst_uninstall ||
            !t->inst_exists) {
            reply_err(t, fd, 0, "libSceAppInstUtil is not available in the host process");
            return 0;
        }
        if (!word || (by_path ? word[0] != '/' : !is_title_id(word))) {
            reply_err(t, fd, 0, by_path ? "expected an absolute path" : "bad title id");
            return 0;
        }
        // once: calling it again resets the link to the install service
        if (!t->inst_ready) {
            t->inst_initialize();
            t->inst_ready = 1;
        }

        if (streq(cmd, "PKGINFO")) {
            char title[32];
            char out[64];
            char *end = out + sizeof(out) - 1;
            char *p;
            int is_app = 0;
            int i;
            for (i = 0; i < (int)sizeof(title); i++)
                title[i] = 0;
            rc = t->inst_title_id_from_pkg(word, title, &is_app);
            if (rc < 0) {
                reply_err(t, fd, rc, "sceAppInstUtilGetTitleIdFromPkg");
                return 0;
            }
            title[sizeof(title) - 1] = 0;
            p = put_s(out, end, "OK ");
            p = put_s(p, end, title);
            p = put_s(p, end, " ");
            p = put_dec(p, end, is_app ? 1 : 0);
            *p++ = '\n';
            send_all(t, fd, out, (u64)(p - out));
        } else if (streq(cmd, "INSTALL")) {
            // filled by the system: content id (0x30 bytes), content type, platform
            char info[0x40];
            int i;
            for (i = 0; i < (int)sizeof(info); i++)
                info[i] = 0;
            rc = t->inst_install_pkg(word, info);
            info[0x2f] = 0;
            if (rc < 0)
                reply_err(t, fd, rc, "sceAppInstUtilAppInstallPkg");
            else
                reply_ok(t, fd, info[0] > ' ' && info[0] < 0x7f ? info : 0);
        } else if (streq(cmd, "EXISTS")) {
            int exists = 0;
            rc = t->inst_exists(word, &exists);
            if (rc < 0)
                reply_err(t, fd, rc, "sceAppInstUtilAppExists");
            else
                reply_ok_hex(t, fd, exists ? 1 : 0);
        } else {
            rc = t->inst_uninstall(word);
            if (rc < 0)
                reply_err(t, fd, rc, "sceAppInstUtilAppUnInstall");
            else
                reply_ok(t, fd, 0);
        }
        return 0;
    }

    reply_err(t, fd, 0, "unknown command");
    return 0;
}

// Serves one client until it closes, goes silent or sends QUIT. Returns 1 on QUIT.
static int serve_client(struct agent_table *t, int fd) {
    char line[LINE_MAX];
    u32 len = 0;
    int too_long = 0;

    for (;;) {
        char c;
        int n = t->net_recv(fd, &c, 1, 0);
        if (n <= 0)
            return 0;
        if (c == '\r')
            continue;
        if (c != '\n') {
            if (len < LINE_MAX - 1)
                line[len++] = c;
            else
                too_long = 1;
            continue;
        }
        line[len] = 0;
        if (too_long)
            reply_err(t, fd, 0, "line too long");
        else if (handle_line(t, fd, line))
            return 1;
        len = 0;
        too_long = 0;
    }
}

__attribute__((section(".text.entry"), used)) void *agent_main(struct agent_table *t) {
    // BSD-style sockaddr_in: len, family, port (big endian), address, padding
    u8 addr[16];
    int one = 1;
    int timeout_us = 15 * 1000 * 1000;
    int listener, rc, i;
    int failures = 0;

    if (!t || t->magic != AGENT_MAGIC)
        return 0;
    t->version = AGENT_VERSION;

    listener = t->net_socket("ps4-dev-agent", 2 /* AF_INET */, 1 /* SOCK_STREAM */, 0);
    if (listener < 0) {
        t->last_error = listener;
        t->state = ST_FAILED | 1;
        return 0;
    }
    t->net_setsockopt(listener, 0xffff /* SOL_SOCKET */, 0x0004 /* SO_REUSEADDR */, &one, sizeof(one));
    for (i = 0; i < 16; i++)
        addr[i] = 0;
    addr[0] = 16;
    addr[1] = 2;
    addr[2] = (u8)(t->port >> 8);
    addr[3] = (u8)t->port;
    rc = t->net_bind(listener, addr, 16);
    if (rc >= 0)
        rc = t->net_listen(listener, 2);
    if (rc < 0) {
        t->last_error = rc;
        t->state = ST_FAILED | 2;
        t->net_close(listener);
        return 0;
    }
    t->state = ST_LISTENING;

    // One client at a time: the PC opens a connection per command.
    while (failures < 100) {
        int quit;
        int fd = t->net_accept(listener, 0, 0);
        if (fd < 0) {
            t->last_error = fd;
            failures++;
            continue;
        }
        failures = 0;
        // a client that goes silent must not block the next one forever
        t->net_setsockopt(fd, 0xffff, 0x1006 /* SO_RCVTIMEO, microseconds */, &timeout_us, sizeof(timeout_us));
        quit = serve_client(t, fd);
        t->net_close(fd);
        if (quit)
            break;
    }

    t->net_close(listener);
    t->state = ST_STOPPED;
    return 0;
}
