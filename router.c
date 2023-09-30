#include <arpa/inet.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include "queue.h"
#include "lib.h"
#include "protocols.h"
static struct trie_node *route_trie;
static u_int32_t route_count;

static struct arp_entry arp_table[150];
static u_int32_t arp_table_size;

static queue arp_queue;
static uint32_t arp_queue_len;

const uint8_t broadcast[MAC_LENGTH] = {255, 255, 255, 255, 255, 255};
const uint8_t replace[MAC_LENGTH] = {0, 0, 0, 0, 0, 0};

// parses given routing table text file and populates the route trie
int populate_trie(const char *path, struct trie_node *root)
{
	FILE *fp = fopen(path, "r");
	int j = 0, i;
	char *p, line[64];

	while (fgets(line, sizeof(line), fp) != NULL) {
		struct route_table_entry *new = malloc(sizeof(struct route_table_entry));

		p = strtok(line, " .");
		i = 0;
		while (p != NULL) {
			if (i < 4)
				*(((unsigned char *) &new->prefix)  + i % 4) = (unsigned char)atoi(p);

			if (i >= 4 && i < 8)
				*(((unsigned char *) &new->next_hop)  + i % 4) = atoi(p);

			if (i >= 8 && i < 12)
				*(((unsigned char *) &new->mask)  + i % 4) = atoi(p);

			if (i == 12)
				new->interface = atoi(p);
			p = strtok(NULL, " .");
			i++;
		}

		// insert entry in trie
		insert_node(root, new);

		j++;
	}
	return j;
}

struct route_table_entry *get_next_hop(uint32_t dest_ip)
{
	struct trie_node *node_found = search(route_trie, dest_ip);

	if (node_found != NULL)
		return node_found->entry;
	else
		return NULL;
}

void swap(uint32_t *a, uint32_t *b)
{
	uint32_t aux = *a;
	*a = *b;
	*b = aux;
}

// this function will modify the buffer into the given "type" ICMP message
void icmp_message(char *buf, size_t *len, int interface, uint8_t type, uint8_t code)
{
	struct iphdr *ipv4_hdr = (struct iphdr *) (buf + IPv4_START);
	struct icmphdr *icmp_hdr = (struct icmphdr *) (buf + ICMP_START);
	char *icmp_data = malloc(ICMP_DATA_SIZE);
	// total number of bytes added to the buffer
	size_t added_length = sizeof(struct icmphdr) + ICMP_DATA_SIZE;

	// save the IPv4 header and the next 64 bits
	memcpy(icmp_data, ipv4_hdr, ICMP_DATA_SIZE);

	// modify IPv4 header
	ipv4_hdr->daddr = ipv4_hdr->saddr; // the sender will receive this message
	ipv4_hdr->saddr = inet_addr(get_interface_ip(interface)); // sent by the router
	ipv4_hdr->ttl = TTL; // reset TTL
	ipv4_hdr->tot_len = htons(ntohs(ipv4_hdr->tot_len) + added_length); //modify length
	ipv4_hdr->protocol = ICMP; // ICMP packet encapsulated

	// recalculate checksum
	ipv4_hdr->check = 0;
	ipv4_hdr->check = htons(checksum((uint16_t *)ipv4_hdr, sizeof(struct iphdr)));

	// build ICMP header
	memset(icmp_hdr, 0, sizeof(struct icmphdr));
	icmp_hdr->type = type;
	icmp_hdr->code = code;

	// calculate checksum
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *) icmp_hdr, sizeof(struct icmphdr)));

	// encapsulate the old IPv4 header + 64 bits in the ICMP header
	memcpy(buf + ICMP_DATA_START, icmp_data, ICMP_DATA_SIZE);

	free(icmp_data);

	*len += added_length;
}

void forward_ipv4_packet(char *buf, size_t len, int interface)
{
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct iphdr *ipv4_hdr = (struct iphdr *) (buf + IPv4_START);

	/*
	 * if time to live ran out, modify the buffer into an ICMP time excedeed
	 * message sent to the original sender of this packet and let the
	 * forwarding function do the rest
	 */
	if (ipv4_hdr->ttl <= 1)
		icmp_message(buf, &len, interface, TIME_EXCEDEED, TIME_EXCEDEED_CODE);

	uint16_t ipv4_checksum = ipv4_hdr->check;

	ipv4_hdr->check = 0;

	// if checksum is bad, drop packet
	if (ipv4_checksum != htons(checksum((uint16_t *)ipv4_hdr, sizeof(struct iphdr))))
		return;

	// recalculate checksum
	ipv4_hdr->ttl--;
	ipv4_hdr->check = 0;
	ipv4_hdr->check = htons(checksum((uint16_t *)ipv4_hdr, sizeof(struct iphdr)));

	struct route_table_entry *next = get_next_hop(ntohl(ipv4_hdr->daddr));

	/*
	 * if we can't find a route, modify the buffer into an ICMP destination
	 * unreachable message sent to the original sender of this packet and
	 * let the forwarding function do the rest
	 */
	if (next == NULL) {
		icmp_message(buf, &len, interface,
					DESTINATION_UNREACHABLE, DESTINATION_UNREACHABLE_CODE);
		next = get_next_hop(ntohl(ipv4_hdr->daddr));
	}

	get_interface_mac(next->interface, eth_hdr->ether_shost);

	// lazy linear search through the ARP cache
	int found = 0;

	for (int j = 0; j < arp_table_size; j++)
		if (ntohl(arp_table[j].ip) == ntohl(next->next_hop)) {
			found = 1;
			memcpy(eth_hdr->ether_dhost, arp_table[j].mac, MAC_LENGTH);
			break;
		}

	// build an ARP request in case of cache miss
	if (found == 0) {
		// add ipv4 packet to queue
		struct ipv4_packet *current = malloc(sizeof(struct ipv4_packet));

		current->len = len;
		current->data = malloc(len + 10);
		current->interface = next->interface;
		current->next_hop = next->next_hop;
		memcpy(current->data, buf, len);
		queue_enq(arp_queue, (void *) current);
		arp_queue_len++;

		// modify ethernet header
		eth_hdr->ether_type = htons(ARP_ETHERTYPE);
		get_interface_mac(interface, eth_hdr->ether_shost);
		memcpy(eth_hdr->ether_dhost, broadcast, MAC_LENGTH);

		// start building the arp request header
		struct arp_header *arp_hdr = malloc(sizeof(struct arp_header));

		arp_hdr->htype = htons(ETHERNET_HTYPE);
		arp_hdr->hlen = MAC_LENGTH;

		arp_hdr->ptype = htons(IPv4_ETHERTYPE);
		arp_hdr->plen = IP_LENGTH;

		arp_hdr->op = htons(REQUEST_OP);

		arp_hdr->spa = inet_addr(get_interface_ip(next->interface));
		get_interface_mac(next->interface, arp_hdr->sha);

		arp_hdr->tpa = next->next_hop;
		memcpy(arp_hdr->tha, broadcast, MAC_LENGTH);

		// add the arp header to the buffer
		memcpy(buf + sizeof(struct ether_header), arp_hdr, sizeof(struct arp_header));
		len = sizeof(struct ether_header) + sizeof(struct arp_header);

		free(arp_hdr);
	}

	// sends an ARP request in case of a cache miss or forwards the packet
	send_to_link(next->interface, buf, len);
}

void handle_arp_reply(char *buf, size_t len, int interface)
{
	struct arp_header *arp_hdr = (struct arp_header *) (buf + ARP_START);

	// add the new IP:MAC pair to the static ARP cache
	arp_table[arp_table_size].ip = arp_hdr->spa;
	memcpy(arp_table[arp_table_size].mac, arp_hdr->sha, MAC_LENGTH);
	arp_table_size++;

	struct ether_header *current_eth;
	struct ipv4_packet *current;

	int packets_removed = 0;

	// loop through all the IPv4 packets in the queue
	for (int i = 0; i < arp_queue_len; i++) {
		current = (struct ipv4_packet *) queue_deq(arp_queue);
		current_eth = (struct ether_header *) current->data;

		/*
		 * forward the packet if it was waiting for the newly found MAC address
	     * or add it back to the queue otherwise
		 */
		if (ntohl(current->next_hop) == ntohl(arp_hdr->spa)) {
			get_interface_mac(current->interface, current_eth->ether_shost);
			memcpy(current_eth->ether_dhost, arp_hdr->sha, MAC_LENGTH);

			send_to_link(current->interface, current->data, current->len);

			free(current->data);
			free(current);
			packets_removed++;
		} else
			queue_enq(arp_queue, current);
	}

	// keep track of the queue's length
	arp_queue_len -= packets_removed;
}

void handle_arp_request(char *buf, size_t len, int interface)
{
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct arp_header *arp_hdr = (struct arp_header *) (buf + ARP_START);

	// building the reply ARP header
	arp_hdr->op = htons(REPLY_OP);
	memcpy(arp_hdr->tha, arp_hdr->sha, MAC_LENGTH);
	get_interface_mac(interface, arp_hdr->sha);
	arp_hdr->tpa = arp_hdr->spa;
	arp_hdr->spa = inet_addr(get_interface_ip(interface));

	// building the reply ethernet header
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC_LENGTH);
	get_interface_mac(interface, eth_hdr->ether_shost);

	// send the response
	send_to_link(interface, buf, len);
}

void icmp_reply(char *buf, size_t len, int interface)
{
	struct iphdr *ipv4_hdr = (struct iphdr *) (buf + IPv4_START);
	struct icmphdr *icmp_hdr = (struct icmphdr *) (buf + ICMP_START);

	// verify header checksum
	uint16_t icmp_checksum = icmp_hdr->checksum;

	icmp_hdr->checksum = 0;
	// if checksum is bad, drop packet
	if (icmp_checksum != htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr))))
		return;

	// swap IP addresses
	swap(&ipv4_hdr->saddr, &ipv4_hdr->daddr);

	// recalculate checksum
	ipv4_hdr->check = 0;
	ipv4_hdr->check = htons(checksum((uint16_t *)ipv4_hdr, sizeof(struct iphdr)));

	// modify ICMP header for echo reply and recalculate checksum
	icmp_hdr->type = ECHO_REPLY;
	icmp_hdr->code = ECHO_CODE;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

	forward_ipv4_packet(buf, len, interface);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// arp table init
	arp_table_size = 0;

	// route table init
	route_trie = new_trie_node();
	route_count = populate_trie(argv[1], route_trie);

	// arp queue init
	arp_queue = queue_create();
	arp_queue_len = 0;

	// Do not modify this line
	init(argc - 2, argv + 2);

	while (1) {
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;

		// check which type of protocol is encapsulated in the ethernet L2 header
		if (ntohs(eth_hdr->ether_type) == IPv4_ETHERTYPE) {
			struct iphdr *ipv4_hdr = (struct iphdr *) (buf + IPv4_START);

			/*
			 * verify if the router is the packet's destination and respond
			 * through ICMP or forward it according to the routing table
			 */
			if (ipv4_hdr->daddr == inet_addr(get_interface_ip(interface)))
				icmp_reply(buf, len, interface);
			else
				forward_ipv4_packet(buf, len, interface);
		} else if (ntohs(eth_hdr->ether_type) == ARP_ETHERTYPE) {
			struct arp_header *arp_hdr = (struct arp_header *) (buf + ARP_START);

			// check what kind of ARP header we've received and respond
			if (ntohs(arp_hdr->op) == REPLY_OP)
				handle_arp_reply(buf, len, interface);
			else if (ntohs(arp_hdr->op) == REQUEST_OP)
				handle_arp_request(buf, len, interface);
		}
	}

	free_trie(route_trie);

	return 0;
}