/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
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
#ifndef _NIP_LIB_H
#define _NIP_LIB_H

/* AF_NINET by reading/sys/module/newip/parameters/af_ninet file to get the type value */
#define AF_NINET 45

#define DEMO_INPUT_1  2  /* The DEMO program contains one parameter */
#define DEMO_INPUT_2  3
#define DEMO_INPUT_3  4
#define DEMO_INPUT_4  5

/* Change the value based on the actual interface */
#define NIC_NAME       "wlan0"
#define NIC_NAME_CHECK "wlan"
#define CMD_ADD        "add"
#define CMD_DEL        "del"

#define BUFLEN          1024
#define LISTEN_MAX      3
#define PKTCNT          10      /* Number of sent packets */
#define PKTLEN          1024    /* Length of sent packet */
#define SLEEP_US        500000  /* Packet sending interval (ms) */
#define SELECT_TIME     600
#define TCP_SERVER_PORT 5556    /* TCP Server Port */
#define UDP_SERVER_PORT 9090    /* UDP Server Port */

#define ARRAY_LEN     255

int nip_get_ifindex(const char *ifname, int *ifindex);
int nip_get_addr(char **args, struct nip_addr *addr);

#endif /* _NIP_LIB_H */
