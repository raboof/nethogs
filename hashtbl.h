#include <stdlib.h>
#include <stdio.h>

class HashNode
{
public:
	~HashNode();

	char * key;
	void * content;
	HashNode * next;
};

class HashTable
{
public:
	HashTable(int n_size);
	~HashTable();

	/* after calling 'add', the calling application
	 * must free the string */
	void add(char * key, void * content);
	void * get(char * key);

private:
	int size; 
	HashNode ** table;

	HashNode * newHashNode(char * key, void * content, HashNode * next);
	unsigned int HashString(const char * str);

	HashTable(); // We leave this unimplemented ;)
};
