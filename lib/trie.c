#include "../include/lib.h"
#include <stdlib.h>
#include <arpa/inet.h>

struct trie_node *new_trie_node(void)
{
	struct trie_node *new = malloc(sizeof(struct trie_node));

	new->entry = NULL;
	new->zero = NULL;
	new->one = NULL;

	return new;
}

void insert_node(struct trie_node *root, struct route_table_entry *entry)
{
	uint32_t prefix = ntohl(entry->prefix);
	uint32_t mask = ntohl(entry->mask);
	uint32_t first_bit = 1 << 31;
	struct trie_node *current = root;

	// for each prefix bit go deeper in the trie
	while (mask) {
		if ((prefix & first_bit) != 0) {
			if (current->one == NULL)
				current->one = new_trie_node();
			current = current->one;
		} else {
			if (current->zero == NULL)
				current->zero = new_trie_node();
			current = current->zero;
		}

		prefix = prefix << 1;
		mask = mask << 1;
	}

	// add the entry to the trie
	current->entry = entry;
}

struct trie_node *search(struct trie_node *root, uint32_t ip)
{
	struct trie_node *current = root;
	struct trie_node *match = NULL;
	uint32_t first_bit = 1 << 31;

	// traverse the trie according to the bits of the IP address
	do {
		// if there is an entry at the current node it is a better match
		if (current->entry)
			match = current;

		// go further or stop if we've reached a leaf
		if ((ip & first_bit) != 0)
			current = current->one;
		else
			current = current->zero;

		ip = ip << 1;
	} while (current);

	return match;
}

void free_trie(struct trie_node *root)
{
	if (root->zero)
		free_trie(root->zero);

	if (root->one)
		free_trie(root->one);

	if (root->entry != NULL)
		free(root->entry);
	free(root);
}
