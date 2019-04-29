
// test unit for tls.c
// odzhan

#define DEBUG 1

#include "tcp.h"
#include "tls.h"

void tls_client(tcp_ctx *tcp, tls_ctx *ctx)
{
	tls_session *tls = tls_new_session(ctx);
	FD_SET      fds;
	int         r;

	if (tls != NULL) {
		// open connection to remote host
		if (connect(tcp->s, tcp->ai_addr,tcp->ai_addrlen) != SOCKET_ERROR) {
			// set socket descriptor
			tls->sck = tcp->s;
			if (tls_handshake(ctx, tls)) {
				printf("\n  [ connected");

				tls_info(ctx, tls, TLS_CONNECTION_INFO);
				tls_info(ctx, tls, TLS_STREAM_SIZE);

				while (1) {
					FD_ZERO(&fds);
					FD_SET(tcp->s, &fds);
					r = select(FD_SETSIZE, &fds, 0, 0, 0);
					if (r <= 0) break;
					tls_decrypt(ctx, tls);
				}
			}
			else {
				printf("\n  [ handshake failed");
			}
			shutdown(tcp->s, SD_BOTH);
			closesocket(tcp->s);
		}
		else {
			printf("\n  [ connect failed");
		}
		tls_free_session(ctx, tls);
	}
}

int main(int argc, char *argv[]) {
	tcp_ctx *tcp;
	tls_ctx *ctx;
	char *host, *port;

	if (argc != 3) {
		printf("\nusage: tls_test <host> <port>\n");
		return 0;
	}

	host = argv[1];
	port = argv[2];

	printf("\n  [ connecting to %s:%i...", host, atoi(port));
	tcp = tcp_new_ctx(AF_INET, host, port);
	if (tcp != NULL) {
		printf("\n  [ host resolved to %s", tcp_addr2ip(tcp));
		ctx = tls_new_ctx();
		if (ctx != NULL) {
			printf("\n  [ TLS client initialized");
			tls_client(tcp, ctx);
			tls_free_ctx(ctx);
		}
		else {
			printf("\nmalloc error");
		}
		tcp_free_ctx(tcp);
	}
	return 0;
}