#pragma once

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

#define AGENT_MAGIC 0x50533441474e5431ULL // "PS4AGNT1"
#define AGENT_VERSION 3

#define ST_LISTENING 1u
#define ST_STOPPED 2u
#define ST_FAILED 0x80000000u

// Keep in sync with agent.py (TABLE_*, FUNCTIONS).
struct agent_table {
    u64 magic;          // 0x00
    u32 version;        // 0x08
    u32 port;           // 0x0c
    u64 base;           // 0x10
    u64 size;           // 0x18
    u32 host_pid;       // 0x20
    volatile u32 state; // 0x24
    int last_error;     // 0x28
    u32 reserved;       // 0x2c
    // 0x30: the sceAppInstUtil ones may be 0
    int (*net_socket)(const char *name, int family, int type, int proto);
    int (*net_bind)(int s, const void *addr, u32 len);
    int (*net_listen)(int s, int backlog);
    int (*net_accept)(int s, void *addr, u32 *len);
    int (*net_recv)(int s, void *buf, u64 len, int flags);
    int (*net_send)(int s, const void *buf, u64 len, int flags);
    int (*net_close)(int s);
    int (*net_setsockopt)(int s, int level, int name, const void *val, u32 len);
    int (*get_foreground_user)(int *user_id);
    // sceLncUtilLaunchApp
    int (*launch_app)(const char *title_id, const char **argv, void *param);
    int (*kill_app)(int app_id, int a, int b, int c);
    int (*big_app_id)(void);
    int (*inst_initialize)(void);
    int (*inst_install_pkg)(const char *path, void *reserved);
    int (*inst_title_id_from_pkg)(const char *path, char *title_id, int *is_app);
    int (*inst_uninstall)(const char *title_id);
    int (*inst_exists)(const char *title_id, int *exists);
};
