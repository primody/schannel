#include "tls.h"


// allocate memory
void* tls_alloc(int size) {
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

// re-allocate memory
void* tls_realloc(void* mem, int size) {
	return HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, mem, size);
}

// send block of data, fragmented if required
int tls_send(int s, void *in, uint32_t inlen) {
	int      len;
	uint32_t sum;
	uint8_t  *p = (uint8_t*)in;

	for (sum = 0; sum < inlen; sum += len) {
		len = send(s, (CHAR *)&p[sum], inlen - sum, 0);
		if (len <= 0) return -1;
	}
	return sum;
}

// free memory
void tls_free(void *mem) {
	HeapFree(GetProcessHeap(), 0, mem);
}

// load secur32.dll into memory
int tls_load_lib(tls_ctx *c) {
	INIT_SECURITY_INTERFACE pInitSecurityInterface;
	char secur32[] = { 's','e','c','u','r','3','2','\0' };
	char init[] = { 'I','n','i','t','S','e','c','u','r','i','t','y','I','n','t','e','r','f','a','c','e','A','\0' };

	c->lib = LoadLibrary(TEXT("secur32.dll"));
	if (c->lib == NULL) return 0;

	pInitSecurityInterface = (INIT_SECURITY_INTERFACE)GetProcAddress(c->lib, init);
	if (pInitSecurityInterface == NULL) return 0;
	c->sspi = pInitSecurityInterface();
	return (c->sspi != NULL) ? 1 : 0;
}

// create new tls context
tls_ctx* tls_new_ctx(void) {
	tls_ctx *c;
	char    my[] = { 'M','Y','\0' };

	c = (tls_ctx *)tls_alloc(sizeof(tls_ctx));
	if (c == NULL) return NULL;

	if (!tls_load_lib(c)) {
		tls_free(c);
		return NULL;
	}

	if (c->cert == NULL) {
		c->cert = CertOpenSystemStore(0, (LPCWSTR)my);
		if (c->cert == NULL) {
			tls_free(c);
			return NULL;
		}
	}
	return c;
}

// free tls context
void tls_free_ctx(tls_ctx *c) {
	if (c->cert) {
		CertCloseStore(c->cert, 0);
	}
	FreeLibrary(c->lib);
	tls_free(c);
}

// initialize new tls session
tls_session* tls_new_session(tls_ctx *c) {
	ALG_ID      algs[2];
	tls_session *s = (tls_session *)tls_alloc(sizeof(tls_session));

	if (s == NULL) return NULL;

	s->buf = (uint8_t *)tls_alloc(TLS_MAX_BUFSIZ);
	s->maxlen = TLS_MAX_BUFSIZ;

	if (s->buf == NULL) {
		tls_free(s);
		return NULL;
	}

	algs[0] = CALG_RSA_KEYX;
	s->sc.dwVersion = SCHANNEL_CRED_VERSION;
	s->sc.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
	s->sc.cSupportedAlgs = 1;
	s->sc.palgSupportedAlgs = algs;
	s->sc.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS;
	s->sc.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;


	// EnumerateSecurityPackages
	ULONG packs = 0;
	SecPkgInfoW ar[100];
	PSecPkgInfoW pk = { 0 };

	memset(ar, 0, sizeof(SecPkgInfoW) * 100);

	SECURITY_STATUS K =  EnumerateSecurityPackagesW(&packs, &ar);
	if (K != SEC_E_OK) {
		return NULL;
	}


	CHAR g_lpPackageName[1024];
	memset(g_lpPackageName, 0, sizeof(CHAR) * 1024);
	
	SEC_WCHAR *ok = L"Microsoft Unified Security Protocol Provider";

	c->ss = AcquireCredentialsHandleW(NULL, ok, SECPKG_CRED_OUTBOUND, NULL, &s->sc, NULL, NULL, &s->cc, NULL);

	return s;
}

void tls_free_session(tls_ctx *c, tls_session *s) {
	// free client credentials
	c->sspi->FreeCredentialsHandle(&s->cc);
	// free sspi context handle
	c->ss = c->sspi->DeleteSecurityContext(&s->ctx);
	// free structure
	tls_free(s->buf);
	tls_free(s);
}

/**
ISC_REQ_SEQUENCE_DETECT |
ISC_REQ_REPLAY_DETECT   |
ISC_REQ_CONFIDENTIALITY |
ISC_RET_EXTENDED_ERROR  |
ISC_REQ_ALLOCATE_MEMORY |
ISC_REQ_STREAM;



ISC_REQ_ALLOCATE_MEMORY
The security package allocates output buffers for you.
When you have finished using the output buffers,
free them by calling the FreeContextBuffer function.

ISC_REQ_CONFIDENTIALITY
Encrypt messages by using the EncryptMessage function.

ISC_REQ_EXTENDED_ERROR
When errors occur, the remote party will be notified.

ISC_REQ_MANUAL_CRED_VALIDATION -
Schannel must not authenticate the server automatically.

ISC_REQ_REPLAY_DETECT -
Detect replayed messages that have been encoded by using
the EncryptMessage or MakeSignature functions.

ISC_REQ_SEQUENCE_DETECT -
Detect messages received out of sequence.

ISC_REQ_STREAM -
Support a stream-oriented connection.

*/
int tls_hello(tls_ctx *c, tls_session *s) {
	DWORD         flags_in, flags_out;
	SecBufferDesc out;
	SecBuffer     ob[1];

	flags_in = ISC_REQ_REPLAY_DETECT |
		ISC_REQ_CONFIDENTIALITY |
		ISC_RET_EXTENDED_ERROR |
		ISC_REQ_ALLOCATE_MEMORY |
		ISC_REQ_MANUAL_CRED_VALIDATION;

	ob[0].pvBuffer = NULL;
	ob[0].BufferType = SECBUFFER_TOKEN;
	ob[0].cbBuffer = 0;

	out.cBuffers = 1;
	out.pBuffers = ob;
	out.ulVersion = SECBUFFER_VERSION;

	c->ss = InitializeSecurityContextW(&s->cc, NULL, NULL, flags_in, 0, SECURITY_NATIVE_DREP, NULL, 0, &s->ctx, &out, &flags_out, NULL);
	//WORKING HERE LATEST STUFF


	//c->ss = c->sspi->InitializeSecurityContext(&s->cc, NULL, NULL, flags_in, 0, SECURITY_NATIVE_DREP, NULL, 0,	&s->ctx, &out, &flags_out, NULL);

	if (c->ss != SEC_I_CONTINUE_NEEDED) return 0;

	// send data
	if (ob[0].cbBuffer != 0) {
		tls_send(s->sck, ob[0].pvBuffer, ob[0].cbBuffer);

		c->ss = c->sspi->FreeContextBuffer(ob[0].pvBuffer);

		ob[0].pvBuffer = NULL;
	}
	return c->ss == SEC_E_OK ? 1 : 0;
}

// perform tls handshake
int tls_handshake(tls_ctx *c, tls_session *s) {
	DWORD         flags_in, flags_out;
	SecBuffer     ib[2], ob[1];
	SecBufferDesc in, out;
	int           len;

	// send initial hello
	if (!tls_hello(c, s)) {
		return 0;
	}

	flags_in = ISC_REQ_REPLAY_DETECT |
		ISC_REQ_CONFIDENTIALITY |
		ISC_RET_EXTENDED_ERROR |
		ISC_REQ_ALLOCATE_MEMORY |
		ISC_REQ_MANUAL_CRED_VALIDATION;

	c->ss = SEC_I_CONTINUE_NEEDED;
	s->buflen = 0;

	while (c->ss == SEC_I_CONTINUE_NEEDED ||
		c->ss == SEC_E_INCOMPLETE_MESSAGE ||
		c->ss == SEC_I_INCOMPLETE_CREDENTIALS)
	{
		if (c->ss == SEC_E_INCOMPLETE_MESSAGE)
		{
			// receive data from server
			len = recv(s->sck, (CHAR *)&s->buf[s->buflen], s->maxlen - s->buflen, 0);

			// socket error?
			if (len == SOCKET_ERROR) {
				c->ss = SEC_E_INTERNAL_ERROR;
				break;
				// server disconnected?
			}
			else if (len == 0) {
				c->ss = SEC_E_INTERNAL_ERROR;
				break;
			}
			// increase buffer position
			s->buflen += len;
		}

		// inspect what we've received
		//tls_hex_dump(s->buf, s->buflen);

		// input data
		ib[0].pvBuffer = s->buf;
		ib[0].cbBuffer = s->buflen;
		ib[0].BufferType = SECBUFFER_TOKEN;

		// empty buffer
		ib[1].pvBuffer = NULL;
		ib[1].cbBuffer = 0;
		ib[1].BufferType = SECBUFFER_VERSION;

		in.cBuffers = 2;
		in.pBuffers = ib;
		in.ulVersion = SECBUFFER_VERSION;

		// output from schannel
		ob[0].pvBuffer = NULL;
		ob[0].cbBuffer = 0;
		ob[0].BufferType = SECBUFFER_VERSION;

		out.cBuffers = 1;
		out.pBuffers = ob;
		out.ulVersion = SECBUFFER_VERSION;

		c->ss = InitializeSecurityContextW(&s->cc, &s->ctx, NULL, flags_in, 0,	SECURITY_NATIVE_DREP, &in, 0, NULL,	&out, &flags_out, NULL);

		// what have we got so far?
		if (c->ss == SEC_E_OK ||
			c->ss == SEC_I_CONTINUE_NEEDED ||
			(FAILED(c->ss) && (flags_out & ISC_RET_EXTENDED_ERROR)))
		{
			// response for server?
			if (ob[0].cbBuffer != 0 && ob[0].pvBuffer) {
				// send response
				tls_send(s->sck, ob[0].pvBuffer, ob[0].cbBuffer);
				// free response
				c->sspi->FreeContextBuffer(ob[0].pvBuffer);
				ob[0].pvBuffer = NULL;
			}
		}
		// incomplete message? continue reading
		if (c->ss == SEC_E_INCOMPLETE_MESSAGE) continue;

		// completed handshake?
		if (c->ss == SEC_E_OK) {
			s->established = 1;

			// If the "extra" buffer contains data, this is encrypted application
			// protocol layer stuff and needs to be saved. The application layer
			// will decrypt it later with DecryptMessage.
			if (ib[1].BufferType == SECBUFFER_EXTRA) {
				DEBUG_PRINT("  [ we have extra data after handshake.\n");
				memmove(s->pExtra.pvBuffer,
					&s->buf[(s->buflen - ib[1].cbBuffer)], ib[1].cbBuffer);

				s->pExtra.cbBuffer = ib[1].cbBuffer;
				s->pExtra.BufferType = SECBUFFER_TOKEN;
			}
			else {
				// no extra data encountered
				s->pExtra.pvBuffer = NULL;
				s->pExtra.cbBuffer = 0;
				s->pExtra.BufferType = SECBUFFER_EMPTY;
			}
			break;
		}
		// some other error
		if (FAILED(c->ss)) break;

		// Copy any leftover data from the "extra" buffer, and go around again.
		if (ib[1].BufferType == SECBUFFER_EXTRA) {
			memmove(s->buf, &s->buf[(s->buflen - ib[1].cbBuffer)], ib[1].cbBuffer);
			s->buflen = ib[1].cbBuffer;
			DEBUG_PRINT("  [ we have %i bytes of extra data.\n", s->buflen);

			tls_hex_dump(s->buf, s->buflen);

		}
		else {
			s->buflen = 0;
		}
	}
	return c->ss == SEC_E_OK ? 1 : 0;
}

int tls_encrypt(tls_ctx *c, tls_session *s) {
	SecBufferDesc  msg;
	SecBuffer      sb[4];

	// stream header
	sb[0].pvBuffer = s->buf;
	sb[0].cbBuffer = c->sizes.cbHeader;
	sb[0].BufferType = SECBUFFER_STREAM_HEADER;

	// stream data
	sb[1].pvBuffer = s->buf + c->sizes.cbHeader;
	sb[1].cbBuffer = s->buflen;
	sb[1].BufferType = SECBUFFER_DATA;

	// stream trailer
	sb[2].pvBuffer = s->buf + c->sizes.cbHeader + s->buflen;
	sb[2].cbBuffer = c->sizes.cbTrailer;
	sb[2].BufferType = SECBUFFER_STREAM_TRAILER;

	sb[3].pvBuffer = SECBUFFER_EMPTY;
	sb[3].cbBuffer = SECBUFFER_EMPTY;
	sb[3].BufferType = SECBUFFER_EMPTY;

	msg.ulVersion = SECBUFFER_VERSION;
	msg.cBuffers = 4;
	msg.pBuffers = sb;

	// encrypt
	c->ss = c->sspi->EncryptMessage(&s->ctx, 0, &msg, 0);

	// if encrypted ok, send
	if (c->ss == SEC_E_OK) {
		s->buflen = sb[0].cbBuffer + sb[1].cbBuffer + sb[2].cbBuffer;
		tls_send(s->sck, s->buf, s->buflen);
	}
	return c->ss;
}

int tls_decrypt(tls_ctx *c, tls_session *s) {
	SecBufferDesc  msg;
	SecBuffer      sb[4];
	DWORD          cbIoBuffer = 0;
	SecBuffer      *pData = NULL, *pExtra = NULL;
	int            len, i;

	s->buflen = 0;
	c->ss = 0;

	// read data from server until we have decrypted data
	// or server disconnects or session ends
	for (;;) {
		// if this is first read or last read was incomplete
		if (s->buflen == 0 || c->ss == SEC_E_INCOMPLETE_MESSAGE)
		{
			// receive block of data in buffer
			len = recv(s->sck, (CHAR *)&s->buf[s->buflen], s->maxlen - s->buflen, 0);

			// was there a socket error?
			if (len<0) {
				DEBUG_PRINT("  [ socket error.\n");
				break;
			}
			// did the server disconnect?
			if (len == 0) {
				DEBUG_PRINT("  [ server disconnected.\n");
				// do we have all decrypted data?
				if (s->buflen) {
					DEBUG_PRINT("  [ it was an error.\n");
					// we were in process of receiving data
					// so it's possibly an error
					break;
				}
				DEBUG_PRINT("  [ the session ended.\n");
				// the session ended, we have everything read
				break;
			}
			// advance total length of data in buffer
			s->buflen += len;
		}
		// try decrypt data
		sb[0].pvBuffer = s->buf;
		sb[0].cbBuffer = s->buflen;

		sb[0].BufferType = SECBUFFER_DATA;
		sb[1].BufferType = SECBUFFER_EMPTY;
		sb[2].BufferType = SECBUFFER_EMPTY;
		sb[3].BufferType = SECBUFFER_EMPTY;

		msg.ulVersion = SECBUFFER_VERSION;
		msg.cBuffers = 4;
		msg.pBuffers = sb;

		// try decrypt it
		c->ss = c->sspi->DecryptMessage(&s->ctx, &msg, 0, NULL);

		// end of session?
		if (c->ss == SEC_I_CONTEXT_EXPIRED) {
			DEBUG_PRINT("  [ context expired.\n");
			break;
		}
		// decryption error?
		if (c->ss != SEC_E_OK &&
			c->ss != SEC_I_RENEGOTIATE &&
			c->ss != SEC_I_CONTEXT_EXPIRED)
		{
			DEBUG_PRINT("  [ decryption error.\n");
			return 0;
		}

		// locate data and (optional) extra data
		for (i = 0; i<4; i++) {
			if (pData == NULL && sb[i].BufferType == SECBUFFER_DATA)
				pData = &sb[i];

			if (pExtra == NULL && sb[i].BufferType == SECBUFFER_EXTRA)
				pExtra = &sb[i];
		}

		if (pData != NULL) {
			s->buflen = pData->cbBuffer;
			if (s->buflen != 0) {
				memmove(s->buf, pData->pvBuffer, s->buflen);
				break;
			}
		}
	}

	tls_hex_dump(s->buf, s->buflen);

	return SEC_E_OK;
}

alg_info algos[] = {
	// protocols
	{ SP_PROT_TLS1_CLIENT,   "TLS 1.0" },
	{ SP_PROT_TLS1_1_CLIENT, "TLS 1.1" },
	{ SP_PROT_TLS1_2_CLIENT, "TLS 1.2" },
	{ SP_PROT_PCT1_CLIENT,   "PCT 1.0" },
	{ SP_PROT_SSL2_CLIENT,   "SSL 2.0" },
	{ SP_PROT_SSL3_CLIENT,   "SSL 3.0" },
	// ciphers
	{ CALG_RC2,              "RC2" },
	{ CALG_RC4,              "RC4" },
	{ CALG_DES,              "DES" },
	{ CALG_3DES,             "3DES" },
	{ CALG_AES_128,          "AES" },
	{ CALG_AES_192,          "AES" },
	{ CALG_AES_256,          "AES" },
	// hash
	{ CALG_MD5,              "MD5" },
	{ CALG_SHA,              "SHA-0" },
	{ CALG_SHA1,             "SHA-1" },
	{ CALG_SHA_256,          "SHA-256" },
	{ CALG_SHA_384,          "SHA-384" },
	{ CALG_SHA_512,          "SHA-512" },
	// key exchange
	{ CALG_RSA_KEYX,         "RSA" },
	{ CALG_DH_EPHEM,         "DHE" },
	{ CALG_ECDH,             "ECDH" },
	{ CALG_ECMQV,            "ECMQV" },
};

char *alg2s(ALG_ID id) {
	int i;

	for (i = 0; i<sizeof(algos) / sizeof(alg_info);i++) {
		if (algos[i].id == id)
			return algos[i].s;
	}
	return "unrecognized";
}

void tls_info(tls_ctx *c, tls_session *s, int cls) {
	SecPkgContext_ConnectionInfo *ci;
	SecPkgContext_StreamSizes    *ss;
	uint8_t                      buf[512];

	c->ss = c->sspi->
		QueryContextAttributes(
			&s->ctx, cls,
			(PVOID)buf);

	if (c->ss != SEC_E_OK) {
		printf("\nError 0x%x querying connection for information\n", c->ss);
		return;
	}

	switch (cls)
	{
	case TLS_CONNECTION_INFO:
	{
		ci = (SecPkgContext_ConnectionInfo*)buf;

		printf("  [ Protocol : %s\n",
			alg2s(ci->dwProtocol));

		printf("  [ Cipher   : %s-%i\n",
			alg2s(ci->aiCipher), ci->dwCipherStrength);

		printf("  [ Hash     : %s\n",
			alg2s(ci->aiHash));

		printf("  [ Exchange : %s-%i\n\n",
			alg2s(ci->aiExch), ci->dwExchStrength);
		break;
	}
	case TLS_STREAM_SIZE:
	{
		ss = (SecPkgContext_StreamSizes*)buf;

		printf("  [ Header Size       : %i\n", ss->cbHeader);
		printf("  [ Trailer Size      : %i\n", ss->cbTrailer);
		printf("  [ Max Message Size  : %i\n", ss->cbMaximumMessage);
		printf("  [ Number of Buffers : %i\n", ss->cBuffers);
		printf("  [ Block Size        : %i\n", ss->cbBlockSize);
		break;
	}
	default:
		break;
	}
}

void tls_hex_dump(void *in, int len) {
	DWORD outlen = 0;
	static int ofs = 0;
	LPTSTR out;

	if (ofs == 0) printf("\n");

	ofs += len;

	CHAR *buf = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len);
	CopyMemory(buf, in, len);

	printf("%s", buf);
	return;

	if (CryptBinaryToString((BYTE *)in, len, CRYPT_STRING_HEXASCIIADDR | CRYPT_STRING_NOCR, NULL, &outlen)) {
		out = (LPTSTR)tls_alloc(outlen);
		if (out != NULL) {
			if (CryptBinaryToString((BYTE *)in, len, CRYPT_STRING_HEXASCIIADDR | CRYPT_STRING_NOCR,	out, &outlen)) {
				printf("%S", out);
			}
			tls_free(out);
		}
	}
}