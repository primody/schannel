/**
Copyright © 2017 Odzhan. All Rights Reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

3. The name of the author may not be used to endorse or promote products
derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE. */

#ifndef TCP_H
#define TCP_H

#define SECURITY_WIN32

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <ws2tcpip.h>
#include <winsock2.h>
#include <windows.h>
#include <wintrust.h>
#include <schannel.h>
#include <security.h>
#include <sspi.h>

#if defined(DEBUG)
#define DEBUG_PRINT(...) { \
   fprintf(stderr, "\nDEBUG: %s:%d:%s(): ", __FILE__, __LINE__, __FUNCTION__); \
   fprintf(stderr, __VA_ARGS__); \
 }
#else
#define DEBUG_PRINT(...) // Don't do anything in release builds
#endif

#pragma comment(lib, "ws2_32.Lib")

typedef struct tcp_ctx_ {
	char   *address, *port;
	int    s, ai_addrlen;
	HANDLE sck_evt;
	struct sockaddr     *ai_addr;
	struct sockaddr_in  v4;
	struct sockaddr_in6 v6;
	char                ip[INET6_ADDRSTRLEN];
} tcp_ctx;

#ifdef __cplusplus
extern "C" {
#endif

	int tcp_send(int, void*, uint32_t);
	int tcp_recv(int, void*, uint32_t);

	int tcp_open(tcp_ctx*);
	void tcp_close(tcp_ctx*);
	char *tcp_addr2ip(tcp_ctx*);

	tcp_ctx* tcp_new_ctx(int, char*, char*);
	void tcp_free_ctx(tcp_ctx *c);

#ifdef __cplusplus
}
#endif

#endif