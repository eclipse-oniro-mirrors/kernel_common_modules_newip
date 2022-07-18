/* SPDX-License-Identifier: BSD-2-Clause */
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
#ifndef _UAPI_NEWIP_ADDR_H
#define _UAPI_NEWIP_ADDR_H

#define NIP_ADDR_LEN_1 1
#define NIP_ADDR_LEN_2 2
#define NIP_ADDR_LEN_3 3
#define NIP_ADDR_LEN_4 4
#define NIP_ADDR_LEN_5 5

#define NIP_ADDR_BIT_LEN_8    8
#define NIP_ADDR_BIT_LEN_16   16
#define NIP_ADDR_BIT_LEN_24   24
#define NIP_ADDR_BIT_LEN_40   40
#define NIP_ADDR_BIT_LEN_MAX  64

enum nip_addr_check_value {
	ADDR_FIRST_DC = 0xDC,
	ADDR_FIRST_F0 = 0xF0,
	ADDR_FIRST_F1,
	ADDR_FIRST_F2,
	ADDR_FIRST_F3,
	ADDR_FIRST_F4,
	ADDR_FIRST_FF = 0xFF,
	ADDR_SECOND_MIN_DD = 0xDD,
	ADDR_SECOND_MIN_F1 = 0x14,    /* f1 14 00 */
	ADDR_THIRD_MIN_F2 = 0x01,     /* f2 00 01 00 00 */
};

enum nip_8bit_addr_index {
	NIP_8BIT_ADDR_INDEX_0 = 0,
	NIP_8BIT_ADDR_INDEX_1 = 1,
	NIP_8BIT_ADDR_INDEX_2 = 2,
	NIP_8BIT_ADDR_INDEX_3 = 3,
	NIP_8BIT_ADDR_INDEX_4 = 4,
	NIP_8BIT_ADDR_INDEX_5 = 5,
	NIP_8BIT_ADDR_INDEX_6 = 6,
	NIP_8BIT_ADDR_INDEX_7 = 7,
	NIP_8BIT_ADDR_INDEX_MAX,
};

enum nip_16bit_addr_index {
	NIP_16BIT_ADDR_INDEX_0 = 0,
	NIP_16BIT_ADDR_INDEX_1 = 1,
	NIP_16BIT_ADDR_INDEX_2 = 2,
	NIP_16BIT_ADDR_INDEX_3 = 3,
	NIP_16BIT_ADDR_INDEX_MAX,
};

enum nip_32bit_addr_index {
	NIP_32BIT_ADDR_INDEX_0 = 0,
	NIP_32BIT_ADDR_INDEX_1 = 1,
	NIP_32BIT_ADDR_INDEX_MAX,
};

#define nip_addr_field8 v.u.u8
#define nip_addr_field16 v.u.u16
#define nip_addr_field32 v.u.u32

#pragma pack(1)
struct nip_addr_field {
	union {
		unsigned char u8[NIP_8BIT_ADDR_INDEX_MAX];
		unsigned short u16[NIP_16BIT_ADDR_INDEX_MAX]; /* big-endian */
		unsigned int u32[NIP_32BIT_ADDR_INDEX_MAX];   /* big-endian */
	} u;
};

struct nip_addr {
	unsigned char bitlen;
	struct nip_addr_field v;
};
#pragma pack()

#define POD_SOCKADDR_SIZE 10

struct sockaddr_nin {
	unsigned short sin_family; /* AF_NINET */
	unsigned short sin_port;   /* Transport layer port, big-endian */
	struct nip_addr sin_addr;  /* NIP address */

	/* Pad to size of struct sockaddr
	 * We don't neet to use this field
	 * Due to the flexible size of nip_addr, we consider the extreme situation:
	 * the size of nip_addr is 2 bytes, so we need to add 10 bytes to make sure
	 * it has the same size as struct sockaddr. And it won't have trouble if you
	 * increase the length of nip_addr.
	 */
	unsigned char sin_zero[POD_SOCKADDR_SIZE];
};

extern const struct nip_addr nip_any_addr;
extern const struct nip_addr nip_broadcast_addr_arp;

int nip_addr_invalid(const struct nip_addr *addr);
int nip_addr_public(const struct nip_addr *addr);
int nip_addr_any(const struct nip_addr *ad);
int get_nip_addr_len(const struct nip_addr *addr);
unsigned char *build_nip_addr(const struct nip_addr *addr, unsigned char *buf);
unsigned char *decode_nip_addr(unsigned char *buf, struct nip_addr *addr);

#endif /* _UAPI_NEWIP_ADDR_H */

