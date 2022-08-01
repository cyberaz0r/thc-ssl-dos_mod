#ifndef __THC_HEADER_H__
#define __THC_HEADER_H__ 1

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>

#include <getopt.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FD_SETSIZE	1024

//#define int_ntoa(x)   inet_ntoa(*((struct in_addr *)&(x)))

#define MAX_PEERS			(999)
#define DEFAULT_PEERS		(400)
#define PROGRAM_NAME		"thc-ssl-dos"
#define TO_TCP_CONNECT		(10)	// 10 second TCP connect() timeout
#define TO_SOCKS5_CONNECT	(10)

#define FL_SECURE_RENEGOTIATION		(0x01)
#define FL_UNSECURE_RENEGOTIATION	(0x02)
#define FL_OUTPUT_SR_ONCE			(0x04)

#define PEER_GET_IDX(xpeer)			(int)(xpeer - &peers[0])
#define FL_PEER_WANT_NEXT_STATE		(0x04)

#define ERREXIT(a...)	do { \
	fprintf(stderr, "%s:%d ", __func__, __LINE__); \
	fprintf(stderr, a); \
	exit(-1); \
} while (0)

#define DEBUGF(a...)	do { \
	fprintf(stderr, "%s:%d ", __FILE__, __LINE__); \
	fprintf(stderr, a); \
} while (0)

#define SSLERR(a...)	do { \
	fprintf(stderr, a); \
	fprintf(stderr, ": %s\n", ERR_error_string(ERR_get_error(), NULL)); \
} while (0)

#define SSLERREXIT(a...)	do { \
	SSLERR(a); \
	exit(-1); \
} while (0)

enum _states {
	STATE_UNKNOWN,
	STATE_TCP_CONNECTING,
	STATE_SSL_CONNECTING,
	STATE_SSL_HANDSHAKING,
	STATE_SSL_DUMMYWRITE
};

enum _protocols {
	SSLv2,
	SSLv3,
	TLSv1,
	TLSv1_1,
	TLSv1_2,
	TLSv1_3,
	DTLSv1,
	DTLSv1_2
};

enum _socks5_status {
	SUCCEEDED = 0x00,
	GENERAL_SOCKS_SERVER_FAILURE = 0x01,
	CONNECTION_NOT_ALLOWED_BY_RULESET = 0x02,
	NETWORK_UNREACHABLE = 0x03,
	HOST_UNREACHABLE = 0x04,
	CONNECTION_REFUSED = 0x05,
	TTL_EXPIRED = 0x06,
	COMMAND_NOT_SUPPORTED = 0x07,
	ADDRESS_TYPE_NOT_SUPPORTED = 0x08
};

struct _statistics {
	uint32_t total_tcp_connections;
	uint32_t total_renegotiations;
	uint32_t total_ssl_connect;
	uint32_t error_count;
	uint64_t epoch_start_usec;
	uint32_t epoch_start_tcp;
	uint32_t epoch_start_ssl;
	uint32_t epoch_start_renegotiations;
};

struct _opt {
	uint32_t flags;
	uint16_t n_peers;
	uint16_t n_max_peers;
	uint32_t ip;
	uint16_t port;
	uint32_t proxy_ip;
	uint16_t proxy_port;
	short reneg_mode;
	fd_set rfds;
	fd_set wfds;
	int max_sox;
	SSL_CTX *ctx;
	enum _protocols prot;
	char *cipher;
	struct _statistics stat;
	int slowstart_last_peer_idx;
};

struct _peer {
	uint32_t flags;
	SSL *ssl;
	int sox;
	enum _states state;
	struct sockaddr_in addr;
	uint32_t count_renegotiations;
	uint32_t tv_connect_sec;
};

enum _protocols protocols = 0;

struct _peer peers[MAX_PEERS];
struct _opt g_opt;

char **split(char *input, char *needle);

static char *int_ntoa(uint32_t ip);
static uint64_t getusec(struct timeval *tv);

static int tcp_connect_io(struct _peer *p);
static int tcp_connect_try_finish(struct _peer *p, int ret);

int tcp_connect(struct _peer *p);
int socks5_connect(struct _peer *p);

static int ssl_connect_io(struct _peer *p);
static int ssl_handshake_io(struct _peer *p);
static int ssl_dummywrite_io(struct _peer *p);

static void PEER_connect(struct _peer *p);
static void PEER_read(struct _peer *p);
static void PEER_write(struct _peer *p);
static void PEER_disconnect(struct _peer *p);

static void PEER_SSL_connect(struct _peer *p);
static void PEER_SSL_dummywrite(struct _peer *p);
static void PEER_SSL_renegotiate(struct _peer *p);

static void SSL_set_rw(struct _peer *p, int ret);

static void NextState(struct _peer *p);
static void CompleteState(struct _peer *p);

static void init_default(void);
static void init_vars(void);
static void usage(void);
static void do_getopt(int argc, char *argv[]);
static void statistics_update(struct timeval *tv);

int main(int argc, char *argv[]);

#endif //__THC_HEADER_H__