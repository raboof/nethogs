#include <iostream>
#include <values.h>
#include <malloc.h>
#include <string.h>
#include "hashtbl.h"

HashNode::~HashNode ()
{
	free (key);
	//delete (content);
	if (next)
		delete (next);
}

HashTable::HashTable(int n_size)
{
	size = n_size;
	table = (HashNode **) malloc (size * sizeof(HashNode *));
	for (unsigned int i=0; i<size; i++)
	{
		table[i] = NULL;
	}
}

HashTable::~HashTable()
{
	for (unsigned int i=0; i<size; i++)
	{
		if (table[i])
			delete table[i];
	}
	free (table);
}

unsigned int HashTable::HashString (const char * str)
{
	unsigned int retval = 0;
	int length = strlen(str);

	unsigned int top5bits = 0xf8000000;
	unsigned int carry = 0;

	const int kleftmove=5;
	const int krightmove=27;

	for (int i=0; i<length; i++)
	{
		carry = retval & top5bits;
		carry = carry >> krightmove;
		retval = retval << kleftmove;
		retval ^= carry;
		retval ^= str[i];
	}
	return retval % size;
}

HashNode * HashTable::newHashNode(char * key, void * content, HashNode * next)
{
	HashNode * retval = new HashNode ();
	retval->key = key;
	retval->content = content;
	retval->next = next;
	return retval;
}


void HashTable::add(char * key, void * content)
{
	char * localkey = strdup(key);
	unsigned int hkey = HashString (localkey);
	//std::cout << "(STILL)Adding node: " << localkey << " key " << hkey << endl;
	table[hkey] = newHashNode(localkey, content, table[hkey]);
}

void * HashTable::get(char * key)
{
	HashNode * current_node = table[HashString (key)];
	//cout << "looking for node " << HashString (key) << endl;
	while (current_node != NULL)
	{
		//cout << "found node, key = " << current_node->key << endl;
		if (strcmp(current_node->key, key) == 0)
		{
			return current_node->content;
		}
		current_node = current_node->next;
	}
	return NULL;
}
