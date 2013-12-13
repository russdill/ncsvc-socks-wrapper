#include <lwip/raw.h>
#include <lwip/inet_chksum.h>
#include <lwip/icmp.h>
#include <lwip/ip4.h>
#include <lwip/pbuf.h>

#include <arpa/inet.h>

struct icmp_data {
	struct raw_pcb *pcb;
	u_int16_t seqno;
	u_int16_t id;
	void *arg;
	void (*reply)(void *arg);
};

void icmp_send_ping(struct icmp_data *data, u_int32_t addr)
{
	struct pbuf *p;
	struct icmp_echo_hdr *hdr;
	ip_addr_t ipaddr;

	p = pbuf_alloc(PBUF_IP, sizeof(*hdr), PBUF_RAM);
	if (!p)
		return;

	hdr = p->payload;
	ICMPH_TYPE_SET(hdr, ICMP_ECHO);
	ICMPH_CODE_SET(hdr, 0);
	hdr->chksum = 0;
	hdr->id = htons(data->id);
	hdr->seqno = htons(++data->seqno);

	hdr->chksum = inet_chksum(hdr, sizeof(*hdr));

	ipaddr.addr = addr;
	raw_sendto(data->pcb, p, &ipaddr);
	pbuf_free(p);
}

static u8_t icmp_recv(void *arg, struct raw_pcb *pcb, struct pbuf *p,
							ip_addr_t *addr)
{
	struct icmp_data *data = arg;
	struct icmp_echo_hdr *hdr;

	if (pbuf_header(p, -PBUF_IP_HLEN))
		return 0;

	hdr = p->payload;
	if (hdr->id != htons(data->id) || hdr->seqno != htons(data->seqno)) {
		pbuf_header(p, PBUF_IP_HLEN);
		return 0;
	}

	pbuf_free(p);

	data->reply(data->arg);
	return 1;
}

struct icmp_data *icmp_init(void (*reply)(void *arg), void *arg)
{
	struct icmp_data *data;

	data = malloc(sizeof(*data));
	data->pcb = raw_new(IP_PROTO_ICMP);
	data->id = 0xf00d;
	data->seqno = 0;
	data->arg = arg;
	data->reply = reply;
	raw_recv(data->pcb, icmp_recv, data);
	raw_bind(data->pcb, IP_ADDR_ANY);
	return data;
}

void icmp_cleanup(struct icmp_data *data)
{
	raw_remove(data->pcb);
	free(data);
}
