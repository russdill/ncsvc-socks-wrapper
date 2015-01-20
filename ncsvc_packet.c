#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include <netif/tunif.h>
#include <lwip/socks.h>

#include "unaligned.h"
#include "ncsvc_main.h"
#include "preload.h"
#include "dbg.h"

/*
 * packet = header + object*
 *
 * header = reserved + msg_type + always_one + not_first + packet_len
 * reserved = 0x00000000
 * msg_type = int (BE)
 * always_one = 0x10000000 (BE)
 * not_first = 0x10000000 | 0x00000000 (BE)
 * packet_len = int (BE) - Length of objects (bytes)
 *
 * object = id + len + element*
 * id = short (BE)
 * len = int (BE) - Length of elements (bytes)
 *
 * element = idx + len + data*
 * idx = short (BE) - Can have missing or duplicate idx
 * len = int (BE) - Data length
 * data = any format
 */

#define REQ_HELLO	0x64
#define REQ_CONFIG	0x7c
#define REQ_CONNECT	0x66
#define REQ_STATUS1	0x69
#define REQ_STATUS2	0x6a

#define REP_HELLO	0x6b
#define REP_CONFIG	0x7d
#define REP_CONNECT	0x6d
#define REP_FAILURE	0x6e
#define REP_STATUS1	0x70
#define REP_STATUS2	0x71

#define RPC_CONFIG		0x00
#define RPC_INTERFACE		0x01
#define RPC_DNS			0x02
#define RPC03			0x03
#define WINS			0x04
#define RPC05			0x05
#define RPC_MTU			0x06
#define RPC_CONNECTION_ID	0x0b
#define RPC_MSG_STATUS		0xc8
#define RPC_STATS		0xc9
#define RPC_VERSION		0xca
#define RPC_DISCONNECT		0xcb
#define RPC_CONNECT		0xcb

enum data_type {
	IPADDR,
	STR,
	U8,
	U32,
	U64,
	END,
};

#define STATE_HEADER	0
#define STATE_PACKET	1

struct packet_ids {
	char name[32];
	int id;
};

struct packet_hdr {
	int reserved;
	int msg_type;
	int always_one;
	int not_first;
	unsigned int packet_len;
} __attribute__((__packed__));

struct ncsvc_context {
	struct bufferevent *bev;
	struct packet_hdr hdr;
	int state;
};

struct field {
	enum data_type typ;
	char *name;
	int idx;
};

struct msg_rpc {
	int rpc_id;
	char *name;
	struct field fields[16];
};

struct packet_builder {
	int rpc_sz_idx;
	int rpc_sz;
	int sz;
	struct packet_hdr *hdr;
};

static const struct packet_ids packet_ids[] = {
	{"REQ_HELLO",	0x64},
	{"REQ_CONFIG",	0x7c},
	{"REQ_CONNECT",	0x66},
	{"REQ_STATUS1",	0x69},
	{"REQ_STATUS2",	0x6a},

	{"REP_HELLO",	0x6b},
	{"REP_CONFIG",	0x7d},
	{"REP_CONNECT",	0x6d},
	{"REP_FAILURE",	0x6e},
	{"REP_STATUS1",	0x70},
	{"REP_STATUS2",	0x71},
};

static const struct msg_rpc rpc_rx_msgs[] = {
	{
		.rpc_id = RPC_INTERFACE,
		.name = "interface",
		.fields = {
			{ .typ = IPADDR, .name = "ip", .idx = 1, },
			{ .typ = IPADDR, .name = "netmask", .idx = 2, },
			{ .typ = IPADDR, .name = "pointopoint", .idx = 3, },
			{ .typ = END, }
		},
	}, {
		.rpc_id = RPC_DNS,
		.name = "dns",
		.fields = {
			{ .typ = IPADDR, .name = "nameserver", .idx = 1, },
			{ .typ = STR, .name = "search", .idx = 2, },
			{ .typ = U32, .name = "idx03", .idx = 3, },
			{ .typ = END, }
		},
	}, {
		.rpc_id = RPC03,
		.name = "rpc03",
		.fields = {
			{ .typ = U8, .name = "idx01", .idx = 1, },
			{ .typ = U8, .name = "idx02", .idx = 2, },
			{ .typ = U64, .name = "idx03", .idx = 3, },
			{ .typ = END, }
		},
	}, {
		.rpc_id = WINS,
		.name = "wins",
		.fields = {
			{ .typ = IPADDR, .name = "server", .idx = 1, },
			{ .typ = END, }
		},
	}, {
		.rpc_id = RPC05,
		.name = "rpc05",
		.fields = {
			{ .typ = U8, .name = "idx03", .idx = 3, },
			{ .typ = END, }
		},
	}, {
		.rpc_id = RPC_MTU,
		.name = "mtu",
		.fields = {
			{ .typ = U32, .name = "val", .idx = 2, },
			{ .typ = END, }
		},
	}, {
		.rpc_id = RPC_CONNECTION_ID,
		.name = "connection_id",
		.fields = {
			{ .typ = STR, .name = "host", .idx = 1, },
			{ .typ = STR, .name = "cookie", .idx = 3, },
			{ .typ = END, }
		},
	}, {
		.rpc_id = RPC_MSG_STATUS,
		.name = "msg_status",
		.fields = {
			{ .typ = U32, .name = "ok", .idx = 1, },
			{ .typ = END, }
		},
	}, {
		.rpc_id = RPC_STATS,
		.name = "stats",
		.fields = {
			{ .typ = U32, .name = "rx_packets", .idx = 1, },
			{ .typ = U32, .name = "tx_packets", .idx = 2, },
			{ .typ = U32, .name = "rx_bytes", .idx = 3, },
			{ .typ = U32, .name = "tx_bytes", .idx = 4, },
			{ .typ = U32, .name = "idx05", .idx = 5, },
			{ .typ = U32, .name = "idx06", .idx = 6, },
			{ .typ = U32, .name = "idx07", .idx = 7, },
			{ .typ = U32, .name = "idx08", .idx = 8, },
			{ .typ = U32, .name = "idx09", .idx = 9, },
			{ .typ = U32, .name = "idx10", .idx = 10, },
			{ .typ = STR, .name = "enc01", .idx = 12, },
			{ .typ = STR, .name = "compression", .idx = 13, },
			{ .typ = STR, .name = "enc01", .idx = 14, },
			{ .typ = U32, .name = "idx15", .idx = 15, },
			{ .typ = END, }
		},
	}, {
		.rpc_id = RPC_VERSION,
		.name = "version?",
		.fields = {
			{ .typ = U32, .name = "idx01", .idx = 1, },
			{ .typ = END, }
		},
	}, {
		.rpc_id = RPC_DISCONNECT,
		.name = "disconnect",
		.fields = {
			{ .typ = U32, .name = "reason", .idx = 1, },
			{ .typ = END, }
		},
	},
};

struct msg_rpc rpc_tx_msgs[] = {
	{
		.rpc_id = 0x00,
		.name = "config",
		.fields = {
			{ .typ = U32, .name = "debug_lvl", .idx = 1, },
			{ .typ = END, }
		},
	}, {
		.rpc_id = 0xc8,
		.name = "msg_status",
		.fields = {
			{ .typ = U32, .name = "ok", .idx = 1, },
			{ .typ = END, }
		},
	}, {
		.rpc_id = 0xcb,
		.name = "connect",
		.fields = {
			{ .typ = STR, .name = "host", .idx = 1, },
			{ .typ = STR, .name = "cookie", .idx = 2, },
			{ .typ = STR, .name = "md5sum", .idx = 10, },
			{ .typ = END, }
		},
	},
};

static struct packet_builder *
packet_new(int msg_type, int not_first)
{
	struct packet_builder *pb;
	pb = malloc(sizeof(*pb));
	pb->hdr = malloc(sizeof(*pb->hdr));
	pb->hdr->reserved = 0;
	pb->hdr->always_one = htonl(0x01000000);
	pb->hdr->not_first = not_first ? htonl(0x01000000) : 0;
	pb->hdr->packet_len = 0;
	pb->hdr->msg_type = htonl(msg_type);
	pb->sz = sizeof(*pb->hdr);
	dbg("%s: msg_type %02x %d bytes\n", __func__, msg_type, pb->sz);
	return pb;
}

static void
packet_add_rpc(struct packet_builder *pb, u_int16_t id)
{
	pb->hdr->packet_len = htonl(ntohl(pb->hdr->packet_len) + 6);
	pb->hdr = realloc(pb->hdr, pb->sz + 6);
	__put_unaligned_be(id, (u_int16_t *) (((char *) pb->hdr) + pb->sz));
	pb->rpc_sz = 0;
	pb->rpc_sz_idx = pb->sz + 2;
	__put_unaligned_be(pb->rpc_sz, (u_int32_t *) (((char *) pb->hdr) + pb->rpc_sz_idx));
	pb->sz += 6;
	dbg("%s: Adding %d bytes\n", __func__, 6);
}

static void
packet_add_idx(struct packet_builder *pb, u_int16_t idx, void *data, int len)
{
	pb->hdr->packet_len = htonl(ntohl(pb->hdr->packet_len) + 6 + len);
	pb->rpc_sz = pb->rpc_sz + 6 + len;
	pb->hdr = realloc(pb->hdr, pb->sz + 6 + len);
	__put_unaligned_be(idx, (u_int16_t *) (((char *) pb->hdr) + pb->sz));
	__put_unaligned_be(len, (u_int32_t *) (((char *) pb->hdr) + pb->sz + 2));
	__put_unaligned_be(pb->rpc_sz, (u_int32_t *) (((char *) pb->hdr) + pb->rpc_sz_idx));
	memcpy((((char *) pb->hdr) + pb->sz + 6), data, len);
	pb->sz += 6 + len;
	dbg("%s: Adding %d bytes\n", __func__, 6 + len);
}

static void
packet_add_u32(struct packet_builder *pb, u_int16_t idx, u_int32_t v)
{
	u_int32_t be = htonl(v);
	dbg("%s: idx %d, %08x\n", __func__, idx, v);
	packet_add_idx(pb, idx, &be, 4);
}

static void
packet_add_str(struct packet_builder *pb, u_int16_t idx, char *str)
{
	dbg("%s: idx %d, %s\n", __func__, idx, str);
	packet_add_idx(pb, idx, str, strlen(str) + 1);
}

static void
packet_send(struct bufferevent *bev, struct packet_builder *pb)
{
#ifdef DEBUG
	char *buf = (char *) pb->hdr;
#endif
	int i;
	dbg("%s: %d bytes\n", __func__, pb->sz);
	dbg("%s: contents", __func__);
	for (i = 0; i < pb->sz; i++)
		dbg_cont(" %02x", buf[i]);
	dbg_cont("\n");
	bufferevent_write(bev, pb->hdr, pb->sz);
	free(pb->hdr);
	free(pb);
}

#ifdef DEBUG
static u_char
rpc_get_u8(char *data, int len)
{
	return len ? *data : '\0';
}
#endif

static u_int16_t
rpc_get_u16(char *data, int len)
{
	return len == 2 ? __get_unaligned_be((u_int16_t *) data) : 0;
}

static u_int32_t
rpc_get_u32(char *data, int len)
{
	return len == 4 ? __get_unaligned_be((u_int32_t *) data) : 0;
}

#ifdef DEBUG
static u_int64_t
rpc_get_u64(char *data, int len)
{
	return len == 8 ? __get_unaligned_be((u_int64_t *) data) : 0;
}
#endif

static u_int32_t
rpc_get_ip(char *data, int len)
{
	return len == 4 ? get_unaligned((unsigned long *) data) : 0;
}

static char *
rpc_get_str(char *data, int len)
{
	char *ret = malloc(len + 1);
	memcpy(ret, data, len);
	ret[len] = '\0';
	return ret;
}

static int mtu;
static u_int32_t ip;
static u_int32_t gw;
static u_int32_t netmask;

static void
ncsvc_process_mtu(char *data, u_int32_t len)
{
	char *end = data + len;
	dbg("%s\n", __func__);
	while (data < end) {
		u_int16_t idx;
		u_int32_t len;

		idx = rpc_get_u16(data, 2);
		len = rpc_get_u32(data + 2, 4);
		data += 6;

		switch (idx) {
		case 2:
			mtu = rpc_get_u32(data, len);
		}
		data += len;
	}
}

static void
ncsvc_process_interface(char *data, u_int32_t len)
{
	char *end = data + len;
	dbg("%s\n", __func__);
	while (data < end) {
		u_int16_t idx;
		u_int32_t len;

		idx = rpc_get_u16(data, 2);
		len = rpc_get_u32(data + 2, 4);
		data += 6;

		switch (idx) {
		case 1:
			ip = rpc_get_ip(data, len);
			break;
		case 2:
			netmask = rpc_get_ip(data, len);
			break;
		case 3:
			gw = rpc_get_ip(data, len);
		}
		data += len;
	}
}

static void
ncsvc_process_dns(char *data, u_int32_t len)
{
	char *end = data + len;
	char *search;
	char *str;
	tunif_clear_dns();
	socks_clear_search();
	dbg("%s\n", __func__);
	while (data < end) {
		u_int16_t idx;
		u_int32_t len;

		idx = rpc_get_u16(data, 2);
		len = rpc_get_u32(data + 2, 4);
		data += 6;

		switch (idx) {
		case 1:
			tunif_add_dns(rpc_get_ip(data, len));
			break;
		case 2:
			search = rpc_get_str(data, len);
			if (!search)
				break;
			while ((str = strchr(search, ','))) {
				str[0] = '\0';
				str++;
				socks_add_search(search);
				search = strdup(str);
			}
			if (search[0])
				socks_add_search(search);
			else
				free(search);
			break;
		}
		data += len;
	}
}

static u_int32_t
ncsvc_process_disconnect(char *data, u_int32_t len)
{
	char *end = data + len;
	u_int32_t ret = 0;

	dbg("%s\n", __func__);
	while (data < end) {
		u_int16_t idx;
		u_int32_t len;

		idx = rpc_get_u16(data, 2);
		len = rpc_get_u32(data + 2, 4);
		data += 6;

		switch (idx) {
		case 1:
			ret = rpc_get_u32(data, len);
		}
		data += len;
	}
	return ret;
}

static void
ncsvc_print_packet(struct packet_hdr *hdr, char *data)
{
#ifdef DEBUG
	int i;
	char *end;

	for (i = 0; i < ARRAY_SIZE(packet_ids); i++)
		if (packet_ids[i].id == ntohl(hdr->msg_type)) break;

	if (i == ARRAY_SIZE(packet_ids))
		dbg("%s: Received REP_%02x message:\n", __func__, ntohl(hdr->msg_type));
	else
		dbg("%s: Received %s message:\n", __func__, packet_ids[i].name);

	end = data + ntohl(hdr->packet_len);

	while (data < end) {
		u_int16_t id;
		u_int32_t len;
		char *idx_data;
		const struct msg_rpc *rpc_msg;
		int first;

		id = rpc_get_u16(data, 2);
		len = rpc_get_u32(data + 2, 4);
		data += 6;

		rpc_msg = NULL;
		for (i = 0; i < ARRAY_SIZE(rpc_rx_msgs); i++)
			if (rpc_rx_msgs[i].rpc_id == id) {
				rpc_msg = &rpc_rx_msgs[i];
				break;
			}

		if (rpc_msg)
			dbg("%s: \t%s(", __func__, rpc_msg->name);
		else
			dbg("%s: \tRPC%02x(", __func__, id);

		idx_data = data;
		data += len;
		first = 1;
		while (idx_data < data) {
			u_int16_t idx;
			u_int32_t idx_len;
			const struct field *field = NULL;
			char tok_buf[80];
			char key_buf[10];
			char *tok;
			char *key;
			u_int32_t slen;
			u_int32_t rem;
			struct in_addr addr;
			int j;

			if (idx_data + 6 > data)
				break;

			idx = rpc_get_u16(idx_data, 2);
			idx_len = rpc_get_u32(idx_data + 2, 4);
			idx_data += 6;

			rem = data - idx_data;
			if (idx_len > rem)
				break;

			for (j = 0; rpc_msg && rpc_msg->fields[j].typ != END; j++)
				if (rpc_msg->fields[j].idx == idx) {
					field = &rpc_msg->fields[j];
					break;
				}

			if (field)
				key = field->name;
			else {
				sprintf(key_buf, "idx%04x", idx);
				key = key_buf;
			}

			tok = tok_buf;
			switch (field ? field->typ : END) {
			case IPADDR:
				addr.s_addr = rpc_get_ip(idx_data, idx_len);
				inet_ntop(AF_INET, &addr, tok_buf, sizeof(tok_buf));
				break;
			case STR:
				slen = idx_len;
				if (slen > sizeof(tok_buf))
					slen = sizeof(tok_buf);
				snprintf(tok_buf, slen, "%s", idx_data);
				break;
			case U8:
				sprintf(tok_buf, "%d", rpc_get_u8(idx_data, idx_len));
				break;
			case U32:
				sprintf(tok_buf, "%d", rpc_get_u32(idx_data, idx_len));
				break;
			case U64:
				sprintf(tok_buf, "%lld", rpc_get_u64(idx_data, idx_len));
				break;
			default:
				sprintf(tok_buf, "(Unknown type)");
			}
			idx_data += idx_len;
			dbg_cont("%s%s='%s'", first ? "" : ", ", key, tok);
			first = 0;
		}
		dbg_cont(")\n");
	}
#endif
}

static void
ncsvc_process_packet(struct bufferevent *bev, struct packet_hdr *hdr, char *data)
{
	struct packet_builder *pb;
	char *end;
	int is_status2 = 0;
	int is_failure = 0;
	int reason = 0;

	end = data + ntohl(hdr->packet_len);

	mtu = 0;
	ip = gw = netmask = 0;

	switch (ntohl(hdr->msg_type)) {
	case REP_HELLO:
		pb = packet_new(REQ_CONFIG, 1);
		packet_add_rpc(pb, RPC_CONFIG);
		packet_add_u32(pb, 0, ncsvc_log_level * 10);
		packet_send(bev, pb);
		break;
	case REP_CONFIG:
		pb = packet_new(REQ_CONNECT, 1);
		packet_add_rpc(pb, RPC_CONNECT);
		packet_add_str(pb, 1, ncsvc_host);
		packet_add_str(pb, 2, ncsvc_cookie);
		packet_add_str(pb, 10, ncsvc_md5sum);
		packet_send(bev, pb);
		break;
	case REP_CONNECT:
		packet_send(bev, packet_new(REQ_STATUS2, 1));
		break;
	case REP_FAILURE:
		is_failure = 1;
		break;
	case REP_STATUS1:
		break;
	case REP_STATUS2:
		is_status2 = 1;
		break;
	}

	while (data < end) {
		u_int16_t id;
		u_int32_t len;
		u_int32_t rem;

		if (data + 6 > end)
			break;

		id = rpc_get_u16(data, 2);
		len = rpc_get_u32(data + 2, 4);
		data += 6;

		rem = end - data;
		if (len > rem)
			break;

		switch (id) {
		case RPC_MTU:
			ncsvc_process_mtu(data, len);
			break;
		case RPC_INTERFACE:
			ncsvc_process_interface(data, len);
			break;
		case RPC_DNS:
			ncsvc_process_dns(data, len);
			break;
		case RPC_DISCONNECT:
			reason = ncsvc_process_disconnect(data, len);
			break;
		}

		data += len;
	}

	if (is_status2)
		tun_ifconfig(ip, gw, netmask, mtu - 40);
	else if (is_failure) {
		printf("Disconnected, reason code %d\n", reason);
		exit(reason);
	}
}

static void
ncsvc_packet_read(struct bufferevent *bev, void *ctx)
{
	struct ncsvc_context *data = ctx;
	struct evbuffer *buf;
	struct packet_hdr *hdr;
	struct evbuffer_iovec vec_out;
	size_t len;

	buf = bufferevent_get_input(data->bev);

again:
	switch (data->state) {
	case STATE_HEADER:
		dbg("%s: STATE_HEADER, need %d/%d bytes\n", __func__, sizeof(*hdr), evbuffer_get_length(buf));
		if (evbuffer_get_length(buf) < sizeof(*hdr))
			break;
		bufferevent_read(bev, &data->hdr, sizeof(data->hdr));
		data->state = STATE_PACKET;
	case STATE_PACKET:
		len = ntohl(data->hdr.packet_len);
		dbg("%s: STATE_PACKET, need %d/%d bytes\n", __func__, len, evbuffer_get_length(buf));
		if (evbuffer_get_length(buf) < len)
			break;
		if (len) {
			evbuffer_pullup(buf, len);
			evbuffer_peek(buf, len, NULL, &vec_out, 1);
			ncsvc_print_packet(&data->hdr, vec_out.iov_base);
			ncsvc_process_packet(bev, &data->hdr, vec_out.iov_base);
			evbuffer_drain(buf, len);
		} else
			ncsvc_process_packet(bev, &data->hdr, NULL);
		data->state = STATE_HEADER;
		goto again;
	}
}

static void
ncsvc_packet_err(struct bufferevent *bev, short events, void *ctx)
{
	dbg("%s\n", __func__);
	if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF))
		bufferevent_free(bev);
}

void
ncsvc_packet_init(struct event_base *base, int fd)
{
	struct ncsvc_context *data;
	struct bufferevent *bev;
	dbg("%s\n", __func__);
	data = malloc(sizeof(*data));
	memset(data, 0, sizeof(*data));
	bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
	data->bev = bev;
	bufferevent_setcb(bev, ncsvc_packet_read, NULL, ncsvc_packet_err, data);
	bufferevent_enable(bev, EV_READ|EV_WRITE);
	packet_send(bev, packet_new(REQ_HELLO, 0));
}

