// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2021-2022, Dell Inc. or its subsidiaries.  All Rights Reserved.
 *
 * Authors: Stuart Hayes <Stuart_Hayes@Dell.com>
 *
 */
#ifndef _NBFT_H
#define _NBFT_H

#include <uuid/uuid.h>
#include <ccan/list/list.h>

enum primary_admin_host_flag {
	not_indicated,
	unselected,
	selected,
	reserved,
};

struct nbft_host {
	uuid_t *id;
	char *nqn;
	bool host_id_configured;
	bool host_nqn_configured;
	enum primary_admin_host_flag primary;
};

struct nbft_hfi_info_tcp {
	__u32 pci_sbdf;
	__u8 *mac_addr;
	__u16 vlan;
	__u8 ip_origin;
	char ipaddr[40];
	__u8 subnet_mask_prefix;
	char gateway_ipaddr[40];
	__u16 route_metric;
	char primary_dns_ipaddr[40];
	char secondary_dns_ipaddr[40];
	char dhcp_server_ipaddr[40];
	char *host_name;
	bool this_hfi_is_default_route;
	bool dhcp_override;
};

struct nbft_hfi {
	int index;
	char transport[8];
	//uuid_t *host_id;
	//char *host_nqn;
	struct nbft_hfi_info_tcp tcp_info;
	struct list_node node;
};

struct nbft_discovery {
	int index;
	struct list_node node;
	struct nbft_security *security;
	struct nbft_hfi *hfi;
	char *uri;
	char *nqn;
};

struct nbft_security {
	int index;
	struct list_node node;
	/* TODO add fields */
};

enum nid_type_type {
	none = 0,
	ieee_eui_64 = 1,
	nguid = 2,
	ns_uuid = 3
};

struct nbft_subsystem_ns {
	int index;
	struct list_node node;
	struct nbft_discovery *discovery;
	struct nbft_security *security;
	int num_hfis;
	struct nbft_hfi **hfis;
	char transport[8];
	char transport_address[40];
	char *transport_svcid;
	__u16 subsys_port_id;
	__u32 nsid;
	enum nid_type_type nid_type;
	__u8 *nid;
	char *subsys_nqn;
	/*
	 * tcp specific
	 */
	bool pdu_header_digest_required;
	bool data_digest_required;
	/*
	 * from extended information sub-structure, if present:
	 */
	int controller_id;
	int asqsz;
	char *dhcp_root_path_string;
};

struct nbft_info {
	struct list_node node;
	const char *filename;
	__u8 *raw_nbft;
	ssize_t raw_nbft_size;
	/* host info... should match other NBFTs */
	struct nbft_host host;
	/* adapters */
	struct list_head hfi_list;
	/* security profiles */
	struct list_head security_list;
	/* discovery controllers */
	struct list_head discovery_list;
	/* subsystem/namespace */
	struct list_head subsystem_ns_list;
};

/*
 * nbft_read() - Read and return contents of an ACPI NBFT table
 *
 * @nbft:		NBFT table data
 * @filename:		Filename of NBFT table to read
 *
 * Read and parse the specified NBFT file into a struct nbft_info,
 * which can be freed with nbft_free
 *
 * Return: NBFT table data
 */
int nbft_read(struct nbft_info **nbft, const char *filename);

/**
 * nbft_free() - Free nbft_info and contents
 * @nbft:	NBFT table data
 */
void nbft_free(struct nbft_info *nbft);
#endif
