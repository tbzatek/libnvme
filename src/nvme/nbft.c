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

static int in_heap(struct nbft_header *header, struct nbft_heap_obj obj)
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

static int __get_heap_obj(struct nbft_header *header, const char *filename,
			  const char *descriptorname, const char *fieldname,
			  struct nbft_heap_obj obj, bool is_string,
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

static struct nbft_info_discovery *discovery_from_index(struct nbft_info *nbft, int i)
{
	struct nbft_info_discovery *d;

	list_for_each(&nbft->discovery_list, d, node)
		if (d->index == i)
			return d;
	return NULL;
}

static struct nbft_info_hfi *hfi_from_index(struct nbft_info *nbft, int i)
{
	struct nbft_info_hfi *h;

	list_for_each(&nbft->hfi_list, h, node)
		if (h->index == i)
			return h;
	return NULL;
}

static struct nbft_info_security *security_from_index(struct nbft_info *nbft, int i)
{
	struct nbft_info_security *s;

	list_for_each(&nbft->security_list, s, node)
		if (s->index == i)
			return s;
	return NULL;
}

static int read_ssns_exended_info(struct nbft_info *nbft, struct nbft_info_subsystem_ns *ssns, struct nbft_ssns_ext_info *ssns_ei)
{
	struct nbft_header *header = (struct nbft_header *)nbft->raw_nbft;

	verify(ssns_ei->structure_id == NBFT_DESC_SSNS_EXT_INFO, "invalid ID in SSNS extended info descriptor");
	verify(ssns_ei->version == 1, "invalid version in SSNS extended info descriptor");
	verify(ssns_ei->ssns_index == ssns->index, "SSNS index doesn't match extended info descriptor index");

	if (!(ssns_ei->flags & NBFT_SSNS_EXT_INFO_VALID))
		return -EINVAL;

	if (ssns_ei->flags & NBFT_SSNS_EXT_INFO_ADMIN_ASQSZ)
		ssns->asqsz = ssns_ei->asqsz;
	ssns->controller_id = ssns_ei->cntlid;
	get_heap_obj(ssns_ei, dhcp_root_path_str_obj, 1, &ssns->dhcp_root_path_string);
	return 0;
}

static int read_ssns(struct nbft_info *nbft, struct nbft_ssns *raw_ssns, struct nbft_info_subsystem_ns **s)
{
	struct nbft_header *header = (struct nbft_header *)nbft->raw_nbft;
	struct nbft_info_subsystem_ns *ssns;
	__u8 *ss_hfi_indexes;
	__u8 *tmp;
	int i, ret;

	if (!(raw_ssns->flags & NBFT_SSNS_VALID))
		return -EINVAL;
	verify(raw_ssns->structure_id == NBFT_DESC_SSNS, "invalid ID in SSNS descriptor");

	ssns = calloc(1, sizeof(*ssns));
	if (!ssns) {
		return -ENOMEM;
	}

	/* index */
	ssns->index = raw_ssns->index;
	/* transport type */
	verify(raw_ssns->trtype == NBFT_TRTYPE_TCP, "invalid transport type in SSNS descriptor");
	strncpy(ssns->transport, trtype_to_string(raw_ssns->trtype), sizeof(ssns->transport));

	/* transport specific flags */
	if (raw_ssns->trtype == NBFT_TRTYPE_TCP) {
		if (raw_ssns->trflags & NBFT_SSNS_PDU_HEADER_DIGEST)
			ssns->pdu_header_digest_required = true;
		if (raw_ssns->trflags & NBFT_SSNS_DATA_DIGEST)
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
	ret = get_heap_obj(raw_ssns, subsys_traddr_obj, 0, (char **)&tmp);
	if (ret)
		goto fail;

	format_ip_addr(ssns->transport_address, sizeof(ssns->transport_address), tmp);

	/*
	 * subsystem transport service identifier
	 */
	ret = get_heap_obj(raw_ssns, subsys_trsvcid_obj, 1, &ssns->transport_svcid);
	if (ret)
		goto fail;

	/* subsystem port ID*/
	ssns->subsys_port_id = raw_ssns->subsys_port_id;

	/* NSID, NID type, & NID */
	ssns->nsid = raw_ssns->nsid;
	ssns->nid_type = raw_ssns->nidt;
	ssns->nid = raw_ssns->nid;

	/* security profile */
	if (raw_ssns->security_desc_index) {
		ssns->security = security_from_index(nbft, raw_ssns->security_desc_index);
		if (!ssns->security)
			nvme_msg(NULL, LOG_DEBUG, "file %s: namespace %d security controller not found\n",
				 nbft->filename, ssns->index);
	}

	/* HFI descriptors */
	ret = get_heap_obj(raw_ssns, secondary_hfi_assoc_obj, 0, (char **)&ss_hfi_indexes);
	if (ret)
		goto fail;

	ssns->hfis = calloc(raw_ssns->secondary_hfi_assoc_obj.length + 1, sizeof(*ssns->hfis));
	if (!ssns->hfis) {
		ret = -ENOMEM;
		goto fail;
	}

	ssns->hfis[0] = hfi_from_index(nbft, raw_ssns->primary_hfi_desc_index);
	if (!ssns->hfis[0]) {
		nvme_msg(NULL, LOG_DEBUG, "file %s: SSNS %d: HFI %d not found\n",
			 nbft->filename, ssns->index, raw_ssns->primary_hfi_desc_index);
		ret = -EINVAL;
		goto fail;
	}
	for (i = 0; i < raw_ssns->secondary_hfi_assoc_obj.length; i++) {
		ssns->hfis[i + 1] = hfi_from_index(nbft, ss_hfi_indexes[i]);
		if (ss_hfi_indexes[i] && !ssns->hfis[i + 1])
			nvme_msg(NULL, LOG_DEBUG, "file %s: SSNS %d HFI %d not found\n",
				 nbft->filename, ssns->index, ss_hfi_indexes[i]);
		else
			ssns->num_hfis++;
	}

	/* SSNS NQN */
	ret = get_heap_obj(raw_ssns, subsys_ns_nqn_obj, 1, &ssns->subsys_nqn);
	if (ret)
		goto fail;

	/* SSNS extended info */
	if (raw_ssns->flags & NBFT_SSNS_EXTENDED_INFO_IN_USE) {
		struct nbft_ssns_ext_info *ssns_extended_info;

		if (!get_heap_obj(raw_ssns, ssns_extended_info_desc_obj, 0, (char **)&ssns_extended_info))
			read_ssns_exended_info(nbft, ssns, ssns_extended_info); 
	}

	*s = ssns;
	return 0;

fail:
	free(ssns);
	return ret;
}

static int read_hfi_info_tcp(struct nbft_info *nbft, struct nbft_hfi_info_tcp *raw_hfi_info_tcp, struct nbft_info_hfi *hfi)
{
	struct nbft_header *header = (struct nbft_header *)nbft->raw_nbft;

	if ((raw_hfi_info_tcp->flags & NBFT_HFI_INFO_TCP_VALID) == 0) {
		return -EINVAL;
	}
	verify(raw_hfi_info_tcp->structure_id == NBFT_DESC_HFI_TRINFO, "invalid ID in HFI transport descriptor");
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
	if (raw_hfi_info_tcp->flags & NBFT_HFI_INFO_TCP_DHCP_OVERRIDE) {
		hfi->tcp_info.dhcp_override = true;
		format_ip_addr(hfi->tcp_info.dhcp_server_ipaddr, sizeof(hfi->tcp_info.dhcp_server_ipaddr), raw_hfi_info_tcp->dhcp_server);
	}
	get_heap_obj(raw_hfi_info_tcp, host_name_obj, 1, &hfi->tcp_info.host_name);
	if (raw_hfi_info_tcp->flags & NBFT_HFI_INFO_TCP_GLOBAL_ROUTE)
		hfi->tcp_info.this_hfi_is_default_route = true;
	return 0;
}

static int read_hfi(struct nbft_info *nbft, struct nbft_hfi *raw_hfi, struct nbft_info_hfi **h)
{
	int ret;
	struct nbft_info_hfi *hfi;
	struct nbft_header *header = (struct nbft_header *)nbft->raw_nbft;

	if (!(raw_hfi->flags & NBFT_HFI_VALID))
		return -EINVAL;
	verify(raw_hfi->structure_id == NBFT_DESC_HFI, "invalid ID in HFI descriptor");

	hfi = calloc(1, sizeof(struct nbft_hfi));
	if (!hfi) {
		return -ENOMEM;
	}

	hfi->index = raw_hfi->index;

	/*
	 * read HFI transport descriptor for this HFI
	 */
	if (raw_hfi->trtype == NBFT_TRTYPE_TCP) {
		/*
		 * tcp
		 */
		struct nbft_hfi_info_tcp *raw_hfi_info_tcp;

		strncpy(hfi->transport, trtype_to_string(raw_hfi->trtype), sizeof(hfi->transport));

		ret = get_heap_obj(raw_hfi, trinfo_obj, 0, (char **)&raw_hfi_info_tcp);
		if (ret)
			goto fail;

		ret = read_hfi_info_tcp(nbft, raw_hfi_info_tcp, hfi);
		if (ret)
			goto fail;
	} else {
		nvme_msg(NULL, LOG_DEBUG, "file %s: invalid transport type %d\n", nbft->filename, raw_hfi->trtype);
		ret = -EINVAL;
		goto fail;
	}

	*h = hfi;
	return 0;

fail:
	free(hfi);
	return ret;
}

static int read_discovery(struct nbft_info *nbft, struct nbft_discovery *raw_discovery, struct nbft_info_discovery **d)
{
	int ret;
	struct nbft_info_discovery *discovery;
	struct nbft_header *header = (struct nbft_header *)nbft->raw_nbft;

	if (!(raw_discovery->flags & NBFT_DISCOVERY_VALID))
		return -EINVAL;
	verify(raw_discovery->structure_id == NBFT_DESC_DISCOVERY, "invalid ID in discovery descriptor");

	discovery = calloc(1, sizeof(struct nbft_info_discovery));
	if (!discovery) {
		ret = -ENOMEM;
		goto discovery_fail;
	}

	discovery->index = raw_discovery->index;

	if (get_heap_obj(raw_discovery, discovery_ctrl_addr_obj, 1, &discovery->uri))
		return -EINVAL;

	if (get_heap_obj(raw_discovery, discovery_ctrl_nqn_obj, 1, &discovery->nqn))
		return -EINVAL;

	discovery->hfi = hfi_from_index(nbft, raw_discovery->hfi_index);
	if (raw_discovery->hfi_index && !discovery->hfi)
		nvme_msg(NULL, LOG_DEBUG, "file %s: discovery %d HFI not found\n",
			nbft->filename, discovery->index);

	discovery->security = security_from_index(nbft, raw_discovery->sec_index);
	if (raw_discovery->sec_index && !discovery->security)
		nvme_msg(NULL, LOG_DEBUG, "file %s: discovery %d security descriptor not found\n",
			nbft->filename, discovery->index);

	*d = discovery;
	return 0;

discovery_fail:
	free(discovery);
	return ret;
}

static int read_security(struct nbft_info *nbft, struct nbft_security *raw_security, struct nbft_info_security **s)
{
	/*
	 *  TO DO add security stuff
	 */
	return -EINVAL;
}

static void read_hfi_descriptors(struct nbft_info *nbft, int num_hfi, struct nbft_hfi *raw_hfi_array, int hfi_len)
{
	int c;
	struct nbft_hfi *raw_hfi;
	struct nbft_info_hfi *hfi;

	for (c = 0; c < num_hfi; c++) {
		raw_hfi = &raw_hfi_array[c];
		if (read_hfi(nbft, raw_hfi, &hfi) == 0)
			list_add_tail(&nbft->hfi_list, &hfi->node);
	}
}

static void read_security_descriptors(struct nbft_info *nbft, int num_sec, struct nbft_security *raw_sec_array, int sec_len)
{
	int c;
	struct nbft_security *raw_security;
	struct nbft_info_security *security;

	for (c = 0; c < num_sec; c++) {
		raw_security = &raw_sec_array[c];
		if (read_security(nbft, raw_security, &security) == 0)
			list_add_tail(&nbft->security_list, &security->node);
	}
}

static void read_discovery_descriptors(struct nbft_info *nbft, int num_disc, struct nbft_discovery *raw_disc_array, int disc_len)
{
	int c;
	struct nbft_discovery *raw_discovery;
	struct nbft_info_discovery *discovery;

	for (c = 0; c < num_disc; c++) {
		raw_discovery = &raw_disc_array[c];
		if (read_discovery(nbft, raw_discovery, &discovery) == 0)
			list_add_tail(&nbft->discovery_list, &discovery->node);
	}
}

static void read_ssns_descriptors(struct nbft_info *nbft, int num_ssns, struct nbft_ssns *raw_ssns_array, int ssns_len)
{
	int c;
	struct nbft_ssns *raw_ssns;
	struct nbft_info_subsystem_ns *ss;

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

	struct nbft_header *header;
	struct nbft_control *control;
	struct nbft_host *host;

	verify(raw_nbft_size >= sizeof(struct nbft_header) + sizeof(struct nbft_control),
	       "table is too short");
	verify(csum(raw_nbft, raw_nbft_size) == 0, "invalid checksum");

	/*
	 * header
	 */
	header = (struct nbft_header *)raw_nbft;

	verify(strncmp(header->signature, NBFT_HEADER_SIG, 4) == 0, "invalid signature");
	verify(header->length <= raw_nbft_size, "length in header exceeds table length");
	verify(header->major_revision == 1, "unsupported major revision");
	verify(header->minor_revision == 0, "unsupported minor revision");
	verify(header->heap_length + header->heap_offset <= header->length,
	       "heap exceeds table length");

	/*
	 * control
	 */
	control = (struct nbft_control *)(raw_nbft + sizeof(struct nbft_header));

	if ((control->flags & NBFT_CONTROL_VALID) == 0)
		return 0;
	verify(control->structure_id == NBFT_DESC_CONTROL, "invalid ID in control structure");

	/*
	 * host
	 */
	verify(control->hdesc.offset + sizeof(struct nbft_host) <= header->length &&
	       control->hdesc.offset >= sizeof(struct nbft_host),
	       "host descriptor offset/length is invalid");
	host = (struct nbft_host *)(raw_nbft + control->hdesc.offset);

	verify (host->flags & NBFT_HOST_VALID, "host descriptor valid flag not set");
	verify(host->structure_id == NBFT_DESC_HOST, "invalid ID in HOST descriptor");
	nbft->host.id = &(host->host_id);
	if (get_heap_obj(host, host_nqn_obj, 1, &nbft->host.nqn) != 0)
		return -EINVAL;

	/*
	 * HFI
	 */
	if (control->num_hfi > 0) {
		struct nbft_hfi *raw_hfi_array;

		verify(control->hfio + sizeof(struct nbft_hfi) * control->num_hfi <= header->length,
		       "invalid hfi descriptor list offset");
		raw_hfi_array = (struct nbft_hfi *)(raw_nbft + control->hfio);
		read_hfi_descriptors(nbft, control->num_hfi, raw_hfi_array, control->hfil);
	}

	/*
	 * security
	 */
	if (control->num_sec > 0) {
		struct nbft_security *raw_security_array;

		verify(control->seco + control->secl * control->num_sec <= header->length,
			"invalid security profile desciptor list offset");
		raw_security_array = (struct nbft_security *)(raw_nbft + control->seco);
		read_security_descriptors(nbft, control->num_sec, raw_security_array, control->secl);
	}

	/*
	 * discovery
	 */
	if (control->num_disc > 0) {
		struct nbft_discovery *raw_discovery_array;

		verify(control->disco + control->discl * control->num_disc <= header->length,
		       "invalid discovery profile descriptor list offset");
		raw_discovery_array = (struct nbft_discovery *)(raw_nbft + control->disco);
		read_discovery_descriptors(nbft, control->num_disc, raw_discovery_array, control->discl);
	}

	/*
	 * subsystem namespace
	 */
	if (control->num_ssns > 0) {
		struct nbft_ssns *raw_ssns_array;

		verify(control->ssnso + control->ssnsl * control->num_ssns <= header->length,
		       "invalid subsystem namespace descriptor list offset");
		raw_ssns_array = (struct nbft_ssns *)(raw_nbft + control->ssnso);
		read_ssns_descriptors(nbft, control->num_ssns, raw_ssns_array, control->ssnsl);
	}

	return 0;
}

void nbft_free(struct nbft_info *nbft)
{
	void *subtable;
	struct nbft_info_subsystem_ns *ns;

	while ((subtable = list_pop(&nbft->hfi_list, struct nbft_info_hfi, node)))
		free(subtable);
	while ((subtable = list_pop(&nbft->discovery_list, struct nbft_info_discovery, node)))
		free(subtable);
	while ((subtable = list_pop(&nbft->security_list, struct nbft_info_security, node)))
		free(subtable);
	while ((ns = list_pop(&nbft->subsystem_ns_list, struct nbft_info_subsystem_ns, node))) {
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
