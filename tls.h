#ifndef TLS_H
#define TLS_H

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

#pragma comment(lib, "crypt32.Lib")
#pragma comment(lib, "ws2_32.Lib")
#pragma comment(lib, "secur32.Lib")

#define TLS_MAX_BUFSIZ      32768

#define TLS_CONNECTION_INFO SECPKG_ATTR_CONNECTION_INFO
#define TLS_STREAM_SIZE     SECPKG_ATTR_STREAM_SIZES

typedef struct tls_ctx_t {
	SECURITY_STATUS           ss;
	HMODULE                   lib;
	PSecurityFunctionTable    sspi;
	HCERTSTORE                cert;
	SecPkgContext_StreamSizes sizes;
} tls_ctx;

typedef struct tls_session_t {
	int                 established, sck;

	SCHANNEL_CRED       sc;
	CredHandle          cc;
	CtxtHandle          ctx;
	SecBuffer           pExtra;

	uint8_t             *buf;
	DWORD               buflen, maxlen;
	char                *address, *port;
	int                 s, ai_addrlen;
	struct sockaddr     *ai_addr;
	struct sockaddr_in  v4;
	struct sockaddr_in6 v6;
	char                ip[INET6_ADDRSTRLEN];
} tls_session;

typedef struct alg_info_t {
	ALG_ID id;
	char *s;
} alg_info;

#ifdef __cplusplus
extern "C" {
#endif

	void* tls_alloc(int);
	void* tls_realloc(void*, int);
	void tls_free(void*);

	int tls_load_lib(tls_ctx*);

	tls_ctx* tls_new_ctx(void);
	void tls_free_ctx(tls_ctx*);

	tls_session* tls_new_session(tls_ctx *c);
	void tls_free_session(tls_ctx*, tls_session*);

	int tls_hello(tls_ctx*, tls_session*);
	int tls_handshake(tls_ctx*, tls_session*);

	int tls_encrypt(tls_ctx*, tls_session*);
	int tls_decrypt(tls_ctx*, tls_session*);

	void tls_info(tls_ctx*, tls_session*, int);

	int tls_recv(int, void*, uint32_t);
	int tls_send(int, void*, uint32_t);

	void tls_hex_dump(void*, int);

#ifdef __cplusplus
}
#endif

#endif