#include <iostream>
#include "hashtbl.h"

void main ()
{
	HashTable * table = new HashTable (10);
	table->add("Foo", (void*)"Bar");
	table->add("Baz", (void*)"Qux");
	cout << "Foo is " << (char*)(table->get("Foo")) << endl;
}

