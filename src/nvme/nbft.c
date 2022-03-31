// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2021-2022, Dell Inc. or its subsidiaries.  All Rights Reserved.
 *
 * Authors: Stuart Hayes <Stuart_Hayes@Dell.com>
 *
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>

#include "private.h"
#include "nbft.h"
#include "log.h"

/*
 *  ACPI NBFT table structures (spec v0.65)
 */

#define NBFT_ACPI_SIG		"NBFT"

enum nbft_raw_descriptor_type {
	NBFT_HEADER,
	NBFT_CONTROL,
	NBFT_HOST,
	NBFT_HFI,
	NBFT_SSNS,
	NBFT_SECURITY,
	NBFT_DISCOVERY,
	NBFT_HFI_TRANSPORT,
	RESERVED_8,
	NBFT_SSNS_EXTENDED_INFO,
};

typedef struct __attribute__((__packed__)) heap_obj_s {
	__u32 offset;
	__u16 length;
} heap_obj;

/*
 * HEADER (Figure 8)
 */
struct __attribute__((__packed__)) raw_nbft_header {
	char signature[4];
	__u32 length;
	__u8 major_revision;
	__u8 checksum;
	char oem_id[6];
	char oem_table_id[8];
	__u32 oem_revision;
	__u32 creator_id;
	__u32 creator_revision;
	__u32 heap_offset;
	__u32 heap_length;
	heap_obj driver_dev_path_sig;
	__u8 minor_revision;
	__u8 reserved[13];
};

/*
 * CONTROL (Figure 8)
 */
struct __attribute__((__packed__)) raw_nbft_control {
	__u8 structure_id;
	__u8 major_revision;
	__u8 minor_revision;
	__u8 reserved1;
	__u16 length;
	__u8 flags;
	__u8 reserved2;

	heap_obj host_descriptor;
	__u8 host_descriptor_version;
	__u8 reserved3;

	__u32 hfi_descriptor_list_offset;
	__u16 hfi_descriptor_length;
	__u8 hfi_descriptor_version;
	__u8 num_hfi;

	__u32 ssns_descriptor_list_offset;
	__u16 ssns_descriptor_length;
	__u8 ssns_descriptor_version;
	__u8 num_ssns;

	__u32 security_profile_descriptor_list_offset;
	__u16 security_profile_descriptor_length;
	__u8 security_descriptor_version;
	__u8 num_sec;

	__u32 discovery_profile_descriptor_list_offset;
	__u16 discovery_profile_descriptor_length;
	__u8 descovery_descriptor_version;
	__u8 num_disc;

	__u8 reserved4[16];
};

#define CONTROLFLAG_VALID		0x01

/*
 * HOST DESCRIPTOR (Figure 9)
 */
struct __attribute__((__packed__)) raw_nbft_host {
	__u8 structure_id;
	__u8 flags;
	uuid_t host_identifier;
	heap_obj host_nqn;
	__u8 reserved[8];
};

#define HOSTFLAG_VALID			0x01
#define HOSTFLAG_HOSTID_CONFIGURED	0x02
#define HOSTFLAG_HOSTNQN_CONFIGURED	0x04
#define HOSTFLAG_PRIMARY_ADMIN_HOST	0x18

enum nbft_transport_types {
	nbft_trtype_tcp = 3,
};

/*
 * HFI DESCRIPTOR (Figure 11)
 */
struct __attribute__((__packed__)) raw_nbft_hfi {
	__u8 structure_id;
	__u8 index;
	__u8 hfi_flags;
	__u8 hfi_transport_type;
	__u8 reserved1[12];
	heap_obj hfi_transport_descriptor;
	__u8 reserved2[10];
};

#define HFIFLAG_VALID		0x01

/*
 * HFI TRANSPORT INFO DESCRIPTOR (Figure 13)
 */
struct __attribute__((__packed__)) raw_nbft_hfi_info_tcp {
	__u8 structure_id;
	__u8 version;
	__u8 hfi_transport_type;
	__u8 transport_info_version;
	__u16 hfi_index;
	__u8 transport_flags;
	__u32 pci_sbdf;
	__u8 mac_addr[6];
	__u16 vlan;
	__u8 ip_origin;
	__u8 ip_address[16];
	__u8 subnet_mask_prefix;
	__u8 ip_gateway[16];
	__u8 reserved1;
	__u16 route_metric;
	__u8 primary_dns[16];
	__u8 secondary_dns[16];
	__u8 dhcp_server[16];
	heap_obj host_name;
	__u8 reserved2[18];
};

#define HFIINFOTCPFLAG_VALID		0x01
#define HFIINFOTCPFLAG_GLOBAL_ROUTE	0x02
#define HFIINFOTCPFLAG_DHCP_OVERRIDE	0x04

/*
 * SUBSYSTEM NAMESPACE DESCRIPTOR (Figure 15)
 */
struct __attribute__((__packed__)) raw_nbft_ssns {
	__u8 structure_id;
	__u16 index;
	__u16 flags;
	__u8 transport_type;
	__u16 transport_specific_flags;
	__u8 primary_discovery_ctrl_index;
	__u8 reserved1;
	heap_obj subsystem_transport_address;
	heap_obj subsystem_transport_svcid;
	__u16 subsystem_port_id;
	__u32 nsid;
	__u8 nid_type;
	__u8 nid[16];
	__u8 security_descriptor_index;
	__u8 primary_hfi_descriptor_index;
	__u8 reserved2;
	heap_obj secondary_hfi_associations;
	heap_obj subsystem_namespace_nqn;
	heap_obj ssns_extended_info_descriptor;
	__u8 reserved3[62];
};

#define SSNSFLAG_VALID				0x0001
#define SSNSFLAG_NON_BOOTABLE_ENTRY		0x0002
#define SSNSFLAG_USE_SECURITY_FIELD		0x0004
#define SSNSFLAG_DHCP_ROOT_PATH_OVERRIDE	0x0008
#define SSNSFLAG_EXTENDED_INFO_IN_USE		0x0010
#define SSNSFLAG_SEPARATE_DISCOVERY_CONTROLLER	0x0020
#define SSNSFLAG_DISCOVERED_NAMESPACE		0x0040
#define SSNSFLAG_UNAVAILABLE_NAMESPACE		0x0180
#define SSNSFLAG_UNAVAILABLE_NAMESPACE_NOTIND	 0x0000
#define SSNSFLAG_UNAVAILABLE_NAMESPACE_AVAIL	 0x0080
#define SSNSFLAG_UNAVAILABLE_NAMESPACE_UNAVAIL	 0x0100
#define SSNSFLAG_UNAVAILABLE_NAMESPACE_RESV	 0x0180

#define SSNS_TCP_FLAG_VALID		0x01
#define SSNS_TCP_FLAG_PDU_HEADER_DIGEST	0x02
#define SSNS_TCP_FLAG_DATA_DIGEST	0x04

/*
 * SUBSYSTEM AND NAMESPACE EXTENDED INFORMATION DESCRIPTOR (Figure 19)
 */
struct __attribute__((__packed__)) raw_nbft_ssns_extended_info {
	__u8 structure_id;
	__u8 version;
	__u16 ssns_index;
	__u32 flags;
	__u16 controller_id;
	__u16 asqsz;
	heap_obj dhcp_root_path_string;
};

#define SSNS_EXTINFO_FLAG_VALID		0x01
#define SSNS_EXTINFO_FLAG_ADMIN_ASQSZ	0x02

/*
 * SECURITY DESCRIPTOR (Figure 21)
 */
struct __attribute__((__packed__)) raw_nbft_security {
	__u8 structure_id;
	__u8 index;
	__u16 security_descriptor_flags;
	__u8 secret_type;
	__u8 reserved1;
	heap_obj secure_channel_algorithm;
	heap_obj authentication_protocols;
	heap_obj cipher_suite;
	heap_obj dh_groups;
	heap_obj secure_hash_functions;
	heap_obj secret_keypath;
	__u8 reserved2[22];
};

#define SECFLAG_VALID(x)					0x0001 
#define SECFLAG_IN_BAND_AUTHENTICATION_REQUIRED			0x0006
#define SECFLAG_AUTHENTICATION_POLICY_LIST			0x0018
#define SECFLAG_AUTHENTICATION_POLICY_LIST_NOT_SUP		 0x0000
#define SECFLAG_AUTHENTICATION_POLICY_LIST_SUP			 0x0008
#define SECFLAG_AUTHENTICATION_POLICY_LIST_REQ			 0x0010
#define SECFLAG_AUTHENTICATION_POLICY_LIST_RSVD			 0x0018
#define SECFLAG_SECURE_CHANNEL_NEGOTIATION			0x0060
#define SECFLAG_SECURE_CHANNEL_NEGOTIATION_NOT_SUP		 0x0000
#define SECFLAG_SECURE_CHANNEL_NEGOTIATION_SUP			 0x0020
#define SECFLAG_SECURE_CHANNEL_NEGOTIATION_REQ			 0x0040
#define SECFLAG_SECURE_CHANNEL_NEGOTIATION_RSVD			 0x0060
#define SECFLAG_SECURITY_POLICY_LIST				0x0180
#define SECFLAG_SECURITY_POLICY_LIST_NOT_PRES			 0x0000
#define SECFLAG_SECURITY_POLICY_LIST_PRES			 0x0080
#define SECFLAG_SECURITY_POLICY_LIST_PRES_ADMINSET		 0x0100
#define SECFLAG_SECURITY_POLICY_LIST_RSVD			 0x0180
#define SECFLAG_CIPHER_SUITES_RESTRICTED_BY_POLICY		0x0200
#define SECFLAG_AUTH_DH_GROUPS_RESTRICTED_BY_POLICY_LIST	0x0400
#define SECFLAG_SECURE_HASH_FUNCTIONS_POLICY_LIST		0x0800

enum secret_type {
	SECRET_TYPE_RESERVED,
	SECRET_TYPE_REDFISH_HOST_INTERFACE_URI,
};

/*
 * DISCOVERY DESCRIPTOR (Figure 24)
 */
struct __attribute__((__packed__)) raw_nbft_discovery {
	__u8 structure_id;
	__u8 flags;
	__u8 index;
	__u8 hfi_index;
	__u8 security_index;
	__u8 reserved1;
	heap_obj discovery_ctrl_addr;
	heap_obj discovery_controller_nqn;
	__u8 reserved2[14];
};

#define DISCOVERYFLAG_VALID	0x01

/*
 *  End of NBFT ACPI table definitions
 */
#define MIN(a,b) (((a)<(b))?(a):(b))

static __u8 csum(void *buffer, int length)
{
	int n;
	__u8 sum = 0;

	for (n = 0; n < length; n++) {
		sum = (__u8)(sum + ((__u8 *)buffer)[n]);
	}
	return sum;
}

static void format_ip_addr(char *buf, size_t buflen, __u8 *addr) {
	struct in6_addr *addr_ipv6;

	addr_ipv6 = (struct in6_addr *)addr;
	if (   addr_ipv6->s6_addr32[0] == 0
	    && addr_ipv6->s6_addr32[1] == 0
	    && (ntohl(addr_ipv6->s6_addr32[2]) == 0xffff) )
		/* ipv4 */
		inet_ntop(AF_INET, &(addr_ipv6->s6_addr32[3]), buf, buflen);
	else
		/* ipv6 */
		inet_ntop(AF_INET6, addr_ipv6, buf, buflen);
}

static int in_heap(struct raw_nbft_header *header, heap_obj obj)
{
	if (obj.length == 0)
		return 1;
	if (obj.offset < header->heap_offset)
		goto bad;
	if (obj.offset > header->heap_offset + header->heap_length)
		goto bad;
	if (obj.offset + obj.length > header->heap_offset + header->heap_length)
		goto bad;
	return 1;
bad:
	return 0;
}

/*
 *  Return transport_type string (NBFT Table 2)
 */
static char *trtype_to_string(__u8 transport_type)
{
	switch (transport_type) {
		case 3:
			return "tcp";
			break;
		default:
			return "invalid";
			break;
	}
}

#define verify(condition, message)							\
	if (!(condition)) {								\
		nvme_msg(NULL, LOG_DEBUG, "file %s: " message "\n", nbft->filename);	\
		return -EINVAL;								\
	}

static int __get_heap_obj(struct raw_nbft_header *header, const char *filename,
			  const char *descriptorname, const char *fieldname,
			  heap_obj obj, bool is_string,
			  char **output)
{
	if (obj.length == 0) {
		*output = NULL;
		return -ENOENT;
	}

	if (!in_heap(header, obj)) {
		nvme_msg(NULL, LOG_DEBUG, "file %s: field '%s' in descriptor '%s' has invalid offset or length\n",
			 filename, fieldname, descriptorname);
		return -EINVAL;
	}

	/* check that string is zero terminated correctly */
	*output = (char *)header + obj.offset;

	if (is_string) {
		if (strnlen(*output, obj.length + 1) < obj.length)
			nvme_msg(NULL, LOG_DEBUG, "file %s: string '%s' in descriptor '%s' is shorter (%ld) than specified length (%d)\n",
				filename, fieldname, descriptorname, strnlen(*output, obj.length + 1), obj.length);
		else if (strnlen(*output, obj.length + 1) > obj.length) {
			nvme_msg(NULL, LOG_DEBUG, "file %s: string '%s' in descriptor '%s' is not zero terminated\n",
				 filename, fieldname, descriptorname);
			return -EINVAL;
		}
	}

	return 0;
}

#define get_heap_obj(descriptor, obj, is_string, output)		\
	__get_heap_obj(header, nbft->filename,			\
		       stringify(descriptor), stringify(obj),	\
		       descriptor->obj, is_string,				\
		       output)

static struct nbft_discovery *discovery_from_index(struct nbft_info *nbft, int i)
{
	struct nbft_discovery *d;

	list_for_each(&nbft->discovery_list, d, node)
		if (d->index == i)
			return d;
	return NULL;
}

static struct nbft_hfi *hfi_from_index(struct nbft_info *nbft, int i)
{
	struct nbft_hfi *h;

	list_for_each(&nbft->hfi_list, h, node)
		if (h->index == i)
			return h;
	return NULL;
}

static struct nbft_security *security_from_index(struct nbft_info *nbft, int i)
{
	struct nbft_security *s;

	list_for_each(&nbft->security_list, s, node)
		if (s->index == i)
			return s;
	return NULL;
}

static int read_ssns_exended_info(struct nbft_info *nbft, struct nbft_subsystem_ns *ssns, struct raw_nbft_ssns_extended_info *ssns_ei)
{
	struct raw_nbft_header *header = (struct raw_nbft_header *)nbft->raw_nbft;

	verify(ssns_ei->structure_id == NBFT_SSNS_EXTENDED_INFO, "invalid ID in SSNS extended info descriptor");
	verify(ssns_ei->version == 1, "invalid version in SSNS extended info descriptor");
	verify(ssns_ei->ssns_index == ssns->index, "SSNS index doesn't match extended info descriptor index");

	if (!(ssns_ei->flags & SSNS_EXTINFO_FLAG_VALID))
		return -EINVAL;

	if (ssns_ei->flags & SSNS_EXTINFO_FLAG_ADMIN_ASQSZ)
		ssns->asqsz = ssns_ei->asqsz;
	ssns->controller_id = ssns_ei->controller_id;
	get_heap_obj(ssns_ei, dhcp_root_path_string, 1, &ssns->dhcp_root_path_string);
	return 0;
}

static int read_ssns(struct nbft_info *nbft, struct raw_nbft_ssns *raw_ssns, struct nbft_subsystem_ns **s)
{
	struct raw_nbft_header *header = (struct raw_nbft_header *)nbft->raw_nbft;
	struct nbft_subsystem_ns *ssns;
	__u8 *ss_hfi_indexes;
	__u8 *tmp;
	int i, ret;

	if (!(raw_ssns->flags & SSNSFLAG_VALID))
		return -EINVAL;
	verify(raw_ssns->structure_id == NBFT_SSNS, "invalid ID in SSNS descriptor");

	ssns = calloc(1, sizeof(*ssns));
	if (!ssns) {
		return -ENOMEM;
	}

	/* index */
	ssns->index = raw_ssns->index;
	/* transport type */
	verify(raw_ssns->transport_type == nbft_trtype_tcp, "invalid transport type in SSNS descriptor");
	strncpy(ssns->transport, trtype_to_string(raw_ssns->transport_type), sizeof(ssns->transport));

	/* transport specific flags */
	if (raw_ssns->transport_type == nbft_trtype_tcp) {
		if (raw_ssns->transport_specific_flags & SSNS_TCP_FLAG_PDU_HEADER_DIGEST)
			ssns->pdu_header_digest_required = true;
		if (raw_ssns->transport_specific_flags & SSNS_TCP_FLAG_DATA_DIGEST)
			ssns->data_digest_required = true;
	}

	/* primary discovery controller */
	if (raw_ssns->primary_discovery_ctrl_index) {
		ssns->discovery = discovery_from_index(nbft, raw_ssns->primary_discovery_ctrl_index);
		if (!ssns->discovery)
			nvme_msg(NULL, LOG_DEBUG, "file %s: namespace %d discovery controller not found\n",
				 nbft->filename, ssns->index);
	}

	/* subsystem transport address */
	ret = get_heap_obj(raw_ssns, subsystem_transport_address, 0, (char **)&tmp);
	if (ret)
		goto fail;

	format_ip_addr(ssns->transport_address, sizeof(ssns->transport_address), tmp);

	/*
	 * subsystem transport service identifier
	 */
	ret = get_heap_obj(raw_ssns, subsystem_transport_svcid, 1, &ssns->transport_svcid);
	if (ret)
		goto fail;

	/* subsystem port ID*/
	ssns->subsys_port_id = raw_ssns->subsystem_port_id;

	/* NSID, NID type, & NID */
	ssns->nsid = raw_ssns->nsid;
	ssns->nid_type = raw_ssns->nid_type;
	ssns->nid = raw_ssns->nid;

	/* security profile */
	if (raw_ssns->security_descriptor_index) {
		ssns->security = security_from_index(nbft, raw_ssns->security_descriptor_index);
		if (!ssns->security)
			nvme_msg(NULL, LOG_DEBUG, "file %s: namespace %d security controller not found\n",
				 nbft->filename, ssns->index);
	}

	/* HFI descriptors */
	ret = get_heap_obj(raw_ssns, secondary_hfi_associations, 0, (char **)&ss_hfi_indexes);
	if (ret)
		goto fail;

	ssns->hfis = calloc(raw_ssns->secondary_hfi_associations.length + 1, sizeof(*ssns->hfis));
	if (!ssns->hfis) {
		ret = -ENOMEM;
		goto fail;
	}

	ssns->hfis[0] = hfi_from_index(nbft, raw_ssns->primary_hfi_descriptor_index);
	if (!ssns->hfis[0]) {
		nvme_msg(NULL, LOG_DEBUG, "file %s: SSNS %d: HFI %d not found\n",
			 nbft->filename, ssns->index, raw_ssns->primary_hfi_descriptor_index);
		ret = -EINVAL;
		goto fail;
	}
	for (i = 0; i < raw_ssns->secondary_hfi_associations.length; i++) {
		ssns->hfis[i + 1] = hfi_from_index(nbft, ss_hfi_indexes[i]);
		if (ss_hfi_indexes[i] && !ssns->hfis[i + 1])
			nvme_msg(NULL, LOG_DEBUG, "file %s: SSNS %d HFI %d not found\n",
				 nbft->filename, ssns->index, ss_hfi_indexes[i]);
		else
			ssns->num_hfis++;
	}

	/* SSNS NQN */
	ret = get_heap_obj(raw_ssns, subsystem_namespace_nqn, 1, &ssns->subsys_nqn);
	if (ret)
		goto fail;

	/* SSNS extended info */
	if (raw_ssns->flags & SSNSFLAG_EXTENDED_INFO_IN_USE) {
		struct raw_nbft_ssns_extended_info *ssns_extended_info;

		if (!get_heap_obj(raw_ssns, ssns_extended_info_descriptor, 0, (char **)&ssns_extended_info))
			read_ssns_exended_info(nbft, ssns, ssns_extended_info); 
	}

	*s = ssns;
	return 0;

fail:
	free(ssns);
	return ret;
}

static int read_hfi_info_tcp(struct nbft_info *nbft, struct raw_nbft_hfi_info_tcp *raw_hfi_info_tcp, struct nbft_hfi *hfi)
{
	struct raw_nbft_header *header = (struct raw_nbft_header *)nbft->raw_nbft;

	if ((raw_hfi_info_tcp->transport_flags & HFIINFOTCPFLAG_VALID) == 0) {
		return -EINVAL;
	}
	verify(raw_hfi_info_tcp->structure_id == NBFT_HFI_TRANSPORT, "invalid ID in HFI transport descriptor");
	verify(raw_hfi_info_tcp->version == 1, "invalid version in HFI transport descriptor");
	if (raw_hfi_info_tcp->hfi_index != hfi->index)
		nvme_msg(NULL, LOG_DEBUG, "file %s: HFI descriptor index %d does not match index in HFI transport descriptor\n",
			 nbft->filename, hfi->index);

	hfi->tcp_info.pci_sbdf = raw_hfi_info_tcp->pci_sbdf;
	hfi->tcp_info.mac_addr = raw_hfi_info_tcp->mac_addr;
	hfi->tcp_info.vlan = raw_hfi_info_tcp->vlan;
	hfi->tcp_info.ip_origin = raw_hfi_info_tcp->ip_origin;
	format_ip_addr(hfi->tcp_info.ipaddr, sizeof(hfi->tcp_info.ipaddr), raw_hfi_info_tcp->ip_address);
	hfi->tcp_info.subnet_mask_prefix = raw_hfi_info_tcp->subnet_mask_prefix;
	format_ip_addr(hfi->tcp_info.gateway_ipaddr, sizeof(hfi->tcp_info.ipaddr), raw_hfi_info_tcp->ip_gateway);
	hfi->tcp_info.route_metric = raw_hfi_info_tcp->route_metric;
	format_ip_addr(hfi->tcp_info.primary_dns_ipaddr, sizeof(hfi->tcp_info.primary_dns_ipaddr), raw_hfi_info_tcp->primary_dns);
	format_ip_addr(hfi->tcp_info.secondary_dns_ipaddr, sizeof(hfi->tcp_info.secondary_dns_ipaddr), raw_hfi_info_tcp->secondary_dns);
	if (raw_hfi_info_tcp->transport_flags & HFIINFOTCPFLAG_DHCP_OVERRIDE) {
		hfi->tcp_info.dhcp_override = true;
		format_ip_addr(hfi->tcp_info.dhcp_server_ipaddr, sizeof(hfi->tcp_info.dhcp_server_ipaddr), raw_hfi_info_tcp->dhcp_server);
	}
	get_heap_obj(raw_hfi_info_tcp, host_name, 1, &hfi->tcp_info.host_name);
	if (raw_hfi_info_tcp->transport_flags & HFIINFOTCPFLAG_GLOBAL_ROUTE)
		hfi->tcp_info.this_hfi_is_default_route = true;
	return 0;
}

static int read_hfi(struct nbft_info *nbft, struct raw_nbft_hfi *raw_hfi, struct nbft_hfi **h)
{
	int ret;
	struct nbft_hfi *hfi;
	struct raw_nbft_header *header = (struct raw_nbft_header *)nbft->raw_nbft;

	if (!(raw_hfi->hfi_flags & HFIFLAG_VALID))
		return -EINVAL;
	verify(raw_hfi->structure_id == NBFT_HFI, "invalid ID in HFI descriptor");

	hfi = calloc(1, sizeof(struct nbft_hfi));
	if (!hfi) {
		return -ENOMEM;
	}

	hfi->index = raw_hfi->index;

	/*
	 * read HFI transport descriptor for this HFI
	 */
	if (raw_hfi->hfi_transport_type == nbft_trtype_tcp) {
		/*
		 * tcp
		 */
		struct raw_nbft_hfi_info_tcp *raw_hfi_info_tcp;

		strncpy(hfi->transport, trtype_to_string(raw_hfi->hfi_transport_type), sizeof(hfi->transport));

		ret = get_heap_obj(raw_hfi, hfi_transport_descriptor, 0, (char **)&raw_hfi_info_tcp);
		if (ret)
			goto fail;

		ret = read_hfi_info_tcp(nbft, raw_hfi_info_tcp, hfi);
		if (ret)
			goto fail;
	} else {
		nvme_msg(NULL, LOG_DEBUG, "file %s: invalid transport type %d\n", nbft->filename, raw_hfi->hfi_transport_type);
		ret = -EINVAL;
		goto fail;
	}

	*h = hfi;
	return 0;

fail:
	free(hfi);
	return ret;
}

static int read_discovery(struct nbft_info *nbft, struct raw_nbft_discovery *raw_discovery, struct nbft_discovery **d)
{
	int ret;
	struct nbft_discovery *discovery;
	struct raw_nbft_header *header = (struct raw_nbft_header *)nbft->raw_nbft;

	if (!(raw_discovery->flags & DISCOVERYFLAG_VALID))
		return -EINVAL;
	verify(raw_discovery->structure_id == NBFT_DISCOVERY, "invalid ID in discovery descriptor");

	discovery = calloc(1, sizeof(struct nbft_discovery));
	if (!discovery) {
		ret = -ENOMEM;
		goto discovery_fail;
	}

	discovery->index = raw_discovery->index;

	if (get_heap_obj(raw_discovery, discovery_ctrl_addr, 1, &discovery->uri))
		return -EINVAL;

	if (get_heap_obj(raw_discovery, discovery_controller_nqn, 1, &discovery->nqn))
		return -EINVAL;

	discovery->hfi = hfi_from_index(nbft, raw_discovery->hfi_index);
	if (raw_discovery->hfi_index && !discovery->hfi)
		nvme_msg(NULL, LOG_DEBUG, "file %s: discovery %d HFI not found\n",
			nbft->filename, discovery->index);

	discovery->security = security_from_index(nbft, raw_discovery->security_index);
	if (raw_discovery->security_index && !discovery->security)
		nvme_msg(NULL, LOG_DEBUG, "file %s: discovery %d security descriptor not found\n",
			nbft->filename, discovery->index);

	*d = discovery;
	return 0;

discovery_fail:
	free(discovery);
	return ret;
}

static int read_security(struct nbft_info *nbft, struct raw_nbft_security *raw_security, struct nbft_security **s)
{
	/*
	 *  TO DO add security stuff
	 */
	return -EINVAL;
}

static void read_hfi_descriptors(struct nbft_info *nbft, int num_hfi, struct raw_nbft_hfi *raw_hfi_array, int hfi_len)
{
	int c;
	struct raw_nbft_hfi *raw_hfi;
	struct nbft_hfi *hfi;

	for (c = 0; c < num_hfi; c++) {
		raw_hfi = &raw_hfi_array[c];
		if (read_hfi(nbft, raw_hfi, &hfi) == 0)
			list_add_tail(&nbft->hfi_list, &hfi->node);
	}
}

static void read_security_descriptors(struct nbft_info *nbft, int num_sec, struct raw_nbft_security *raw_sec_array, int sec_len)
{
	int c;
	struct raw_nbft_security *raw_security;
	struct nbft_security *security;

	for (c = 0; c < num_sec; c++) {
		raw_security = &raw_sec_array[c];
		if (read_security(nbft, raw_security, &security) == 0)
			list_add_tail(&nbft->security_list, &security->node);
	}
}

static void read_discovery_descriptors(struct nbft_info *nbft, int num_disc, struct raw_nbft_discovery *raw_disc_array, int disc_len)
{
	int c;
	struct raw_nbft_discovery *raw_discovery;
	struct nbft_discovery *discovery;

	for (c = 0; c < num_disc; c++) {
		raw_discovery = &raw_disc_array[c];
		if (read_discovery(nbft, raw_discovery, &discovery) == 0)
			list_add_tail(&nbft->discovery_list, &discovery->node);
	}
}

static void read_ssns_descriptors(struct nbft_info *nbft, int num_ssns, struct raw_nbft_ssns *raw_ssns_array, int ssns_len)
{
	int c;
	struct raw_nbft_ssns *raw_ssns;
	struct nbft_subsystem_ns *ss;

	for (c = 0; c < num_ssns; c++) {
		raw_ssns = &raw_ssns_array[c];
		if (read_ssns(nbft, raw_ssns, &ss) == 0)
			list_add_tail(&nbft->subsystem_ns_list, &ss->node);
	}
}

/**
 * parse_raw_nbft - parses raw ACPI NBFT table and fill in abstracted nbft_info structure
 * @nbft: nbft_info struct containing only raw_nbft and raw_nbft_size
 *
 * Returns 0 on success, errno otherwise.
 */
static int parse_raw_nbft(struct nbft_info *nbft)
{
	__u8 *raw_nbft = nbft->raw_nbft;
	int raw_nbft_size = nbft->raw_nbft_size;

	struct raw_nbft_header *header;
	struct raw_nbft_control *control;
	struct raw_nbft_host *host;

	verify(raw_nbft_size >= sizeof(struct raw_nbft_header) + sizeof(struct raw_nbft_control),
	       "table is too short");
	verify(csum(raw_nbft, raw_nbft_size) == 0, "invalid checksum");

	/*
	 * header
	 */
	header = (struct raw_nbft_header *)raw_nbft;

	verify(strncmp(header->signature, NBFT_ACPI_SIG, 4) == 0, "invalid signature");
	verify(header->length <= raw_nbft_size, "length in header exceeds table length");
	verify(header->major_revision == 1, "unsupported major revision");
	verify(header->minor_revision == 0, "unsupported minor revision");
	verify(header->heap_length + header->heap_offset <= header->length,
	       "heap exceeds table length");

	/*
	 * control
	 */
	control = (struct raw_nbft_control *)(raw_nbft + sizeof(struct raw_nbft_header));

	if ((control->flags & CONTROLFLAG_VALID) == 0)
		return 0;
	verify(control->structure_id == NBFT_CONTROL, "invalid ID in control structure");

	/*
	 * host
	 */
	verify(control->host_descriptor.offset + sizeof(struct raw_nbft_host) <= header->length &&
	       control->host_descriptor.offset >= sizeof(struct raw_nbft_host),
	       "host descriptor offset/length is invalid");
	host = (struct raw_nbft_host *)(raw_nbft + control->host_descriptor.offset);

	verify (host->flags & HOSTFLAG_VALID, "host descriptor valid flag not set");
	verify(host->structure_id == NBFT_HOST, "invalid ID in HOST descriptor");
	nbft->host.id = &(host->host_identifier);
	if (get_heap_obj(host, host_nqn, 1, &nbft->host.nqn) != 0)
		return -EINVAL;

	/*
	 * HFI
	 */
	if (control->num_hfi > 0) {
		struct raw_nbft_hfi *raw_hfi_array;

		verify(control->hfi_descriptor_list_offset + sizeof(struct raw_nbft_hfi) * control->num_hfi <= header->length,
		       "invalid hfi descriptor list offset");
		raw_hfi_array = (struct raw_nbft_hfi *)(raw_nbft + control->hfi_descriptor_list_offset);
		read_hfi_descriptors(nbft, control->num_hfi, raw_hfi_array, control->hfi_descriptor_length);
	}

	/*
	 * security
	 */
	if (control->num_sec > 0) {
		struct raw_nbft_security *raw_security_array;

		verify(control->security_profile_descriptor_list_offset + control->security_profile_descriptor_length * control->num_sec <= header->length,
			"invalid security profile desciptor list offset");
		raw_security_array = (struct raw_nbft_security *)(raw_nbft + control->security_profile_descriptor_list_offset);
		read_security_descriptors(nbft, control->num_sec, raw_security_array, control->security_profile_descriptor_length);
	}

	/*
	 * discovery
	 */
	if (control->num_disc > 0) {
		struct raw_nbft_discovery *raw_discovery_array;

		verify(control->discovery_profile_descriptor_list_offset + control->discovery_profile_descriptor_length * control->num_disc <= header->length,
		       "invalid discovery profile descriptor list offset");
		raw_discovery_array = (struct raw_nbft_discovery *)(raw_nbft + control->discovery_profile_descriptor_list_offset);
		read_discovery_descriptors(nbft, control->num_disc, raw_discovery_array, control->discovery_profile_descriptor_length);
	}

	/*
	 * subsystem namespace
	 */
	if (control->num_ssns > 0) {
		struct raw_nbft_ssns *raw_ssns_array;

		verify(control->ssns_descriptor_list_offset + control->ssns_descriptor_length * control->num_ssns <= header->length,
		       "invalid subsystem namespace descriptor list offset");
		raw_ssns_array = (struct raw_nbft_ssns *)(raw_nbft + control->ssns_descriptor_list_offset);
		read_ssns_descriptors(nbft, control->num_ssns, raw_ssns_array, control->ssns_descriptor_length);
	}

	return 0;
}

void nbft_free(struct nbft_info *nbft)
{
	void *subtable;
	struct nbft_subsystem_ns *ns;

	while ((subtable = list_pop(&nbft->hfi_list, struct nbft_hfi, node)))
		free(subtable);
	while ((subtable = list_pop(&nbft->discovery_list, struct nbft_discovery, node)))
		free(subtable);
	while ((subtable = list_pop(&nbft->security_list, struct nbft_security, node)))
		free(subtable);
	while ((ns = list_pop(&nbft->subsystem_ns_list, struct nbft_subsystem_ns, node))) {
		free(ns->hfis);
		free(ns);
	}
	free(nbft->raw_nbft);
	free((void *)nbft->filename);
	free(nbft);
}

/**
 * nbft_read - read ACPI NBFT table and parse contents into struct nbft_info 
 * @nbft: will contain address of struct nbft_info if read successful
 * @filename: location of raw ACPI NBFT table
 *
 * Returns 0 on success, errno otherwise.
 */
int nbft_read(struct nbft_info **nbft, const char *filename)
{
	__u8 *raw_nbft = NULL;
	size_t raw_nbft_size;
	FILE *raw_nbft_fp;
	int i, ret = 0;

	/*
	 * read in raw nbft file
	 */
	raw_nbft_fp = fopen(filename, "rb");
	if (raw_nbft_fp == NULL) {
		nvme_msg(NULL, LOG_ERR, "Failed to open %s: %s\n", filename, strerror(errno));
		return -EINVAL;
	}

	i = fseek(raw_nbft_fp, 0L, SEEK_END);
	if (i) {
		nvme_msg(NULL, LOG_ERR, "Failed to read from %s: %s\n", filename, strerror(errno));
		ret = -EINVAL;
		goto fail_1;
	}

	raw_nbft_size = ftell(raw_nbft_fp);
	rewind(raw_nbft_fp);

	raw_nbft = malloc(raw_nbft_size);
	if (!raw_nbft) {
		nvme_msg(NULL, LOG_ERR, "Failed to allocate memory for NBFT table");
		ret = -ENOMEM;
		goto fail_1;
	}

	i = fread(raw_nbft, sizeof(*raw_nbft), raw_nbft_size, raw_nbft_fp);
	if (i != raw_nbft_size) {
		nvme_msg(NULL, LOG_ERR, "Failed to read from %s: %s\n", filename, strerror(errno));
		ret = -EINVAL;
		goto fail_1;
	}
	fclose(raw_nbft_fp);

	/*
	 * alloc new struct nbft_info, add raw nbft & filename to it, and add it to the list
	 */
	*nbft = calloc(1, sizeof(struct nbft_info));
	if (!*nbft) {
		nvme_msg(NULL, LOG_ERR, "Could not allocate memory for NBFT\n");
		ret = -ENOMEM;
		goto fail_2;
	}

	(*nbft)->filename = strdup(filename);
	(*nbft)->raw_nbft = raw_nbft;
	(*nbft)->raw_nbft_size = raw_nbft_size;
	list_head_init(&(*nbft)->hfi_list);
	list_head_init(&(*nbft)->security_list);
	list_head_init(&(*nbft)->discovery_list);
	list_head_init(&(*nbft)->subsystem_ns_list);

	if (parse_raw_nbft(*nbft)) {
		nvme_msg(NULL, LOG_ERR, "Failed to parse %s\n", filename);
		nbft_free(*nbft);
		return -EINVAL;
	}
	return 0;

fail_1:
	fclose(raw_nbft_fp);
fail_2:
	free(raw_nbft);
	return ret;
}
