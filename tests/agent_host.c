// Host test for the agent blob: loads companion/build/agent.bin exactly as the console would get it
// (flat, at an arbitrary address), gives it a table of fake system functions built on POSIX sockets,
// and runs agent_main. Linux x86-64 only (same calling convention as the PS4); the test runs it in WSL.
//
//   gcc -O1 -o agent_host tests/agent_host.c && ./agent_host companion/build/agent.bin 9226
//
// Every fake system call prints one line on stdout so the test can check what the agent did.

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "../companion/agent_table.h"

static int big_app = -1;
static char installed[8][16] = {"HRSA00064"};

static int f_socket(const char *name, int family, int type, int proto) {
    printf("socket %s %d %d\n", name, family, type);
    (void)proto;
    return socket(AF_INET, SOCK_STREAM, 0);
}

static int f_bind(int s, const void *addr, u32 len) {
    const u8 *a = addr;
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    printf("bind len=%u sa_len=%u family=%u port=%u\n", len, a[0], a[1], (a[2] << 8) | a[3]);
    sin.sin_family = AF_INET;
    memcpy(&sin.sin_port, a + 2, 2);
    memcpy(&sin.sin_addr, a + 4, 4);
    return bind(s, (struct sockaddr *)&sin, sizeof(sin)) ? -1 : 0;
}

static int f_listen(int s, int backlog) { return listen(s, backlog) ? -1 : 0; }
static int f_accept(int s, void *addr, u32 *len) {
    (void)addr;
    (void)len;
    return accept(s, 0, 0);
}
static int f_recv(int s, void *buf, u64 len, int flags) { return (int)recv(s, buf, len, flags); }
static int f_send(int s, const void *buf, u64 len, int flags) { return (int)send(s, buf, len, flags | MSG_NOSIGNAL); }
static int f_close(int s) { return close(s); }

static int f_setsockopt(int s, int level, int name, const void *val, u32 len) {
    int v = *(const int *)val;
    printf("setsockopt level=%#x name=%#x val=%d len=%u\n", level, name, v, len);
    if (name == 0x0004)
        return setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
    if (name == 0x1006) {
        // the test shortens the timeout so the silent-client case does not take 15 s
        const char *o = getenv("AGENT_HOST_TIMEOUT_MS");
        int ms = o ? atoi(o) : v / 1000;
        struct timeval tv = {ms / 1000, (ms % 1000) * 1000};
        return setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    return -1;
}

static int f_fguser(int *user) {
    *user = 0x10000000;
    return 0;
}

static int f_launch(const char *title, const char **argv, void *param) {
    const u32 *p = param;
    int argc = 0;
    printf("launch %s size=%#x user=%#x attr=%u crash=%u check=%llu args=", title, p[0], p[1], p[2], p[3],
           *(const unsigned long long *)(p + 4));
    if (argv)
        for (; argv[argc]; argc++)
            printf("[%s]", argv[argc]);
    printf(" argc=%d\n", argc);
    if (big_app >= 0)
        return (int)0x8094000c; // something is already running
    if (strcmp(title, "HRSA00064") && strcmp(title, "CUSA00001"))
        return (int)0x80940031; // not installed
    big_app = 0x60000f0b;
    return big_app;
}

static int f_kill(int app_id, int a, int b, int c) {
    printf("kill %#x %d %d %d\n", app_id, a, b, c);
    if (app_id != big_app)
        return (int)0x80940010;
    big_app = -1;
    return 0;
}

static int f_big(void) { return big_app >= 0 ? big_app : (int)0x80aa000a; }

static int f_inst_init(void) {
    printf("appinst init\n");
    return 0;
}

static int f_inst_pkg(const char *path, void *info) {
    printf("install %s info=%s\n", path, info ? "buffer" : "null");
    if (strcmp(path, "/data/pkg/new.pkg"))
        return (int)0x80990015;
    strcpy(installed[1], "HRSA00099");
    if (info)
        strcpy(info, "IV0000-HRSA00099_00-NEWPKG0000000000");
    return 0;
}

static int f_inst_title(const char *path, char *title, int *is_app) {
    printf("pkginfo %s\n", path);
    if (strcmp(path, "/data/pkg/new.pkg"))
        return (int)0x80990015;
    strcpy(title, "HRSA00099");
    *is_app = 1;
    return 0;
}

static int f_inst_exists(const char *title, int *exists) {
    int i;
    *exists = 0;
    for (i = 0; i < 8; i++)
        if (!strcmp(installed[i], title))
            *exists = 1;
    return 0;
}

static int f_inst_uninstall(const char *title) {
    int i;
    printf("uninstall %s\n", title);
    for (i = 0; i < 8; i++)
        if (!strcmp(installed[i], title)) {
            installed[i][0] = 0;
            return 0;
        }
    return (int)0x80990088;
}

int main(int argc, char **argv) {
    struct agent_table t;
    FILE *f;
    long n;
    u8 *code;
    void *(*entry)(struct agent_table *);

    if (argc < 3)
        return 2;
    setvbuf(stdout, 0, _IOLBF, 0);
    f = fopen(argv[1], "rb");
    if (!f)
        return 3;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    // an odd address on purpose: the blob must not care where it lands
    code = mmap((void *)0x7a1234000UL, 0x8000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED || fread(code, 1, (size_t)n, f) != (size_t)n)
        return 4;
    fclose(f);

    memset(&t, 0, sizeof(t));
    t.magic = AGENT_MAGIC;
    t.port = (u32)atoi(argv[2]);
    t.base = (u64)code;
    t.size = 0x8000;
    t.host_pid = 45;
    if (argc > 3 && !strcmp(argv[3], "badmagic"))
        t.magic = 1;
    t.net_socket = f_socket;
    t.net_bind = f_bind;
    t.net_listen = f_listen;
    t.net_accept = f_accept;
    t.net_recv = f_recv;
    t.net_send = f_send;
    t.net_close = f_close;
    t.net_setsockopt = f_setsockopt;
    t.get_foreground_user = f_fguser;
    t.launch_app = f_launch;
    t.kill_app = f_kill;
    t.big_app_id = f_big;
    if (!(argc > 3 && !strcmp(argv[3], "noinst"))) {
        t.inst_initialize = f_inst_init;
        t.inst_install_pkg = f_inst_pkg;
        t.inst_title_id_from_pkg = f_inst_title;
        t.inst_uninstall = f_inst_uninstall;
        t.inst_exists = f_inst_exists;
    }

    entry = (void *(*)(struct agent_table *))code;
    printf("start size=%ld table=%zu\n", n, sizeof(t));
    entry(&t);
    printf("stopped state=%#x version=%u last_error=%#x\n", t.state, t.version, (u32)t.last_error);
    return 0;
}
