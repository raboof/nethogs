/* this should be called quickly after the packet
 * arrived, since the inode may disappear from the table
 * quickly, too :) */

#include "nethogs.h"
// #define PROGNAME_WIDTH 200

struct prg_node {
    long inode;
    int pid;
    char name[PROGNAME_WIDTH];
};

struct prg_node * findPID (unsigned long inode);

void prg_cache_clear();
