// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 *    conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list
 *    of conditions and the following disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "nip_hdr.h"

#define INTEGER_MULTIPLE_OF_8 (~7) /* ~7 is an integer multiple of 8 */
#define FMT_FACTORY_NUM_MAX 1
#define ENCAP_FACTORY_NUM_MAX 1

void nip_calc_pkt_frag_num(unsigned int mtu, unsigned int usr_data_len,
			   struct nip_pkt_seg_info *seg_info)
{
	unsigned int mid_usr_pkt_len = (mtu - NIP_HDR_MAX - NIP_UDP_HDR_LEN) &
				       INTEGER_MULTIPLE_OF_8;
	unsigned int mid_pkt_num = usr_data_len / mid_usr_pkt_len;
	unsigned int last_usr_pkt_len = 0;

	if (usr_data_len != 0) {
		last_usr_pkt_len = usr_data_len % mid_usr_pkt_len;
		if (last_usr_pkt_len == 0) {
			last_usr_pkt_len = mid_usr_pkt_len;
			mid_pkt_num--;
		}
	}

	seg_info->last_pkt_num = 1;
	seg_info->mid_pkt_num = mid_pkt_num;
	seg_info->mid_usr_pkt_len = mid_usr_pkt_len;
	seg_info->last_usr_pkt_len = last_usr_pkt_len;
}

static inline void _nip_hdr_ttl_encap(struct nip_hdr_encap *head)
{
	*(head->hdr_buf + head->hdr_buf_pos) = head->ttl;
	head->hdr_buf_pos += sizeof(head->ttl);
}

static inline void _nip_hdr_len_encap(struct nip_hdr_encap *head)
{
	head->hdr_len_pos = head->hdr_buf + head->hdr_buf_pos;
	head->hdr_buf_pos += 1;
}

static inline void _nip_update_hdr_len(struct nip_hdr_encap *head)
{
	*head->hdr_len_pos = head->hdr_buf_pos;
}

static inline void _nip_hdr_nexthdr_encap(struct nip_hdr_encap *head)
{
	*(head->hdr_buf + head->hdr_buf_pos) = head->nexthdr;
	head->hdr_buf_pos += sizeof(head->nexthdr);
}

static inline void _nip_hdr_daddr_encap(struct nip_hdr_encap *head)
{
	(void)build_nip_addr(&head->daddr, (head->hdr_buf + head->hdr_buf_pos));
	head->hdr_buf_pos += (head->daddr.bitlen / NIP_ADDR_BIT_LEN_8);
}

static inline void _nip_hdr_saddr_encap(struct nip_hdr_encap *head)
{
	(void)build_nip_addr(&head->saddr, (head->hdr_buf + head->hdr_buf_pos));
	head->hdr_buf_pos += (head->saddr.bitlen / NIP_ADDR_BIT_LEN_8);
}

static inline void _nip_hdr_total_len_encap(struct nip_hdr_encap *head)
{
	head->total_len_pos = (unsigned short *)(head->hdr_buf + head->hdr_buf_pos);
	head->hdr_buf_pos += sizeof(head->total_len);
}

/* total_len must be network order.(big end) */
void nip_update_total_len(struct nip_hdr_encap *head, unsigned short total_len)
{
	*head->total_len_pos = total_len;
}

static inline void _nip_hdr_encap_udp_bitmap(struct nip_hdr_encap *head)
{
	/* bitmap(1B) + ttl(1B) + total_len(2B) + nexthdr(1B) + daddr(xB) + saddr(xB) */
	/* If the length of the destination address and the source address is even,
	 * the length of the packet header must be odd. You need to add 1-byte alignment
	 * and 1-byte bitmap
	 */
	if (((head->daddr.bitlen / NIP_ADDR_BIT_LEN_8) + (head->saddr.bitlen / NIP_ADDR_BIT_LEN_8))
	    % NIP_BYTE_ALIGNMENT != 0) {
		head->hdr_buf[0] = NIP_UDP_BITMAP_1;
		head->hdr_buf_pos = 1;
	} else {
		head->hdr_buf[0] = NIP_UDP_BITMAP_1_INC_2;
		head->hdr_buf[1] = NIP_NODATA_BITMAP_2;
		head->hdr_buf_pos = 2;
	}
}

static inline void _nip_hdr_encap_comm_bitmap(struct nip_hdr_encap *head)
{
	/* bitmap(1B) + ttl(1B) + nexthdr(1B) + daddr(xB) + saddr(xB) */
	/* If the length of the destination address and the source address is even,
	 * the length of the packet header must be odd. You need to add 1-byte alignment
	 * and 1-byte bitmap
	 */
	if (((head->daddr.bitlen / NIP_ADDR_BIT_LEN_8) + (head->saddr.bitlen / NIP_ADDR_BIT_LEN_8))
	    % NIP_BYTE_ALIGNMENT != 0) {
		head->hdr_buf[0] = NIP_NORMAL_BITMAP_1;
		head->hdr_buf_pos = 1;
	} else {
		head->hdr_buf[0] = NIP_NORMAL_BITMAP_1_INC_2;
		head->hdr_buf[1] = NIP_NODATA_BITMAP_2;
		head->hdr_buf_pos = 2;
	}
}

#define NEWIP_BYTE_ALIGNMENT_ENABLE 1 // 0: disable; 1: enable

void nip_hdr_udp_encap(struct nip_hdr_encap *head)
{
	/* Encapsulate the bitmap into the newIP packet header BUF */
#if (NEWIP_BYTE_ALIGNMENT_ENABLE == 1)
	_nip_hdr_encap_udp_bitmap(head);
#else
	head->hdr_buf[0] = NIP_UDP_BITMAP_1;
	head->hdr_buf_pos = 1;
#endif

	/* Encapsulate bitmap fields into newIP packet header BUF */
	_nip_hdr_ttl_encap(head);
	_nip_hdr_nexthdr_encap(head);
	_nip_hdr_daddr_encap(head);
	_nip_hdr_saddr_encap(head);
}

/* need update total len after this func, call nip_update_total_len */
void nip_hdr_comm_encap(struct nip_hdr_encap *head)
{
	/* Encapsulate the bitmap into the newIP packet header BUF */
#if (NEWIP_BYTE_ALIGNMENT_ENABLE == 1)
	_nip_hdr_encap_comm_bitmap(head);
#else
	head->hdr_buf[0] = NIP_NORMAL_BITMAP_1;
	head->hdr_buf_pos = 1;
#endif

	/* Encapsulate bitmap fields into newIP packet header BUF */
	_nip_hdr_ttl_encap(head);
	_nip_hdr_total_len_encap(head); /* ARP/TCP need include hdr total len */
	_nip_hdr_nexthdr_encap(head);
	_nip_hdr_daddr_encap(head);
	_nip_hdr_saddr_encap(head);
}

