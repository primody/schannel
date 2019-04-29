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

#include "tcp.h"

// allocate memory
void* tcp_alloc(int size) {
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

// re-allocate memory
void* tcp_realloc(void* mem, int size) {
	return HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, mem, size);
}

// free memory
void tcp_free(void *mem) {
	HeapFree(GetProcessHeap(), 0, mem);
}

// receive block of data, fragmented if required
int tcp_recv(int s, void *out, uint32_t outlen) {
	int      len;
	uint32_t sum;
	uint8_t  *p = (uint8_t*)out;

	for (sum = 0; sum<outlen; sum += len) {
		len = recv(s, &p[sum], outlen - sum, 0);
		if (len <= 0) return -1;
	}
	return sum;
}

// send block of data, fragmented if required
int tcp_send(int s, void *in, uint32_t inlen) {
	int      len;
	uint32_t sum;
	uint8_t  *p = (uint8_t*)in;

	for (sum = 0; sum<inlen; sum += len) {
		len = send(s, &p[sum], inlen - sum, 0);
		if (len <= 0) return -1;
	}
	return sum;
}

// convert binary network address to string
char *tcp_addr2ip(tcp_ctx *c) {
	DWORD ip_size = INET6_ADDRSTRLEN;

	WSAAddressToString(
		c->ai_addr, c->ai_addrlen,
		NULL, (char*)c->ip, &ip_size);

	return (char*)c->ip;
}

// open connection to remote server
int tcp_open(tcp_ctx *c) {
	return connect(c->s, c->ai_addr, c->ai_addrlen) != SOCKET_ERROR;
}

// close connection to remote server
void tcp_close(tcp_ctx *c) {
	// disable send/receive operations
	shutdown(c->s, SD_BOTH);
	// close socket
	closesocket(c->s);
}

// resolve host, create socket and event handle
tcp_ctx* tcp_new_ctx(int family, char *host, char *port) {
	struct addrinfo *list, *e;
	struct addrinfo hints;
	WSADATA         wsa;
	int             on = 1;
	tcp_ctx         *c;

	WSAStartup(MAKEWORD(2, 0), &wsa);

	ZeroMemory(&hints, sizeof(hints));

	hints.ai_family = family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// try to resolve network address for host
	if (getaddrinfo(host, port, &hints, &list) != 0) {
		return NULL;
	}
	c = tcp_alloc(sizeof(tcp_ctx));

	// traverse list of entries
	for (e = list; e != NULL; e = e->ai_next) {
		if (family == AF_INET) {
			memcpy(&c->v4, e->ai_addr, e->ai_addrlen);
			c->ai_addr = (SOCKADDR*)&c->v4;
		}
		else {
			memcpy(&c->v6, e->ai_addr, e->ai_addrlen);
			c->ai_addr = (SOCKADDR*)&c->v6;
		}
		c->ai_addrlen = e->ai_addrlen;
		// create socket and event for signalling
		c->s = socket(family, SOCK_STREAM, IPPROTO_TCP);
		if (c->s != SOCKET_ERROR) {
			// ensure we can reuse same port later
			setsockopt(
				c->s, SOL_SOCKET, SO_REUSEADDR,
				(char*)&on, sizeof(on));
		}
		break;
	}
	freeaddrinfo(list);
	return c;
}

// shut down socket, close event handle, clean up
void tcp_free_ctx(tcp_ctx *c) {
	// close tcp connection
	tcp_close(c);
	// close event handle
	CloseHandle(c->sck_evt);
	// release memory
	tcp_free(c);
}