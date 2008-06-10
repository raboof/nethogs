#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <cstdlib>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string>
#include <map>
#include <sys/stat.h>
#include <fcntl.h>

#include "inode2prog.h"

/* maps from inode to program-struct */
std::map <unsigned long, prg_node *> inodeproc;

bool is_number (char * string) {
	while (*string) {
		if (!isdigit (*string))
			return false;
		string++;
	}
	return true;
}

unsigned long str2ulong (char * ptr) {
	unsigned long retval = 0;

	while ((*ptr >= '0') && (*ptr <= '9')) {
		retval *= 10;
		retval += *ptr - '0';
		ptr++;
	}
	return retval;
}
int str2int (char * ptr) {
	int retval = 0;

	while ((*ptr >= '0') && (*ptr <= '9')) {
		retval *= 10;
		retval += *ptr - '0';
		ptr++;
	}
	return retval;
}

char * getprogname (char * pid) {
	int filenamelen = 14 + strlen(pid) + 1; 
	int bufsize = 80;
	char buffer [bufsize];
	char * filename = (char *) malloc (filenamelen);
	snprintf (filename, filenamelen, "/proc/%s/cmdline", pid);
	int fd = open(filename, O_RDONLY);
	if (fd < 0) {
		fprintf (stderr, "Error opening %s: %s\n", filename, strerror(errno));
		free (filename);
		exit(3);
		return NULL;
	}
	int length = read (fd, buffer, bufsize);
	if (close (fd)) {
		std::cout << "Error closing file: " << strerror(errno) << std::endl;
		exit(34);
	}
	free (filename);
	if (length < bufsize - 1)
		buffer[length]='\0';

	char * retval = buffer;

	/* this removed directory names, but that malfunctions
	 * when the program name is like "sshd: arnouten@pts/8"
	if ((retval = strrchr(buffer, '/')))
		retval++;
	else 
		retval = buffer; 
	*/
	// truncating is now done where it should be, in cui.cpp

	return strdup(retval);
}

void setnode (unsigned long inode, prg_node * newnode)
{
	if (inodeproc[inode] != NULL)
		free (inodeproc[inode]);
	inodeproc[inode] = newnode;
}

void get_info_by_linkname (char * pid, char * linkname) {
	if (strncmp(linkname, "socket:[", 8) == 0) {
		char * ptr = linkname + 8;
		unsigned long inode = str2ulong(ptr);

		char * progname = getprogname (pid);

		//std::cout << "Found socket with inode " << inode << " and pid " << pid << " and progname " << progname << "\n";
		prg_node * newnode = (prg_node *) malloc (sizeof (struct prg_node));
		newnode->inode = inode;
		newnode->pid = str2int(pid);
		// TODO progname could be more memory-efficient
		strncpy (newnode->name, progname, PROGNAME_WIDTH);
		free (progname);
		setnode (inode, newnode);
	} else {
		//std::cout << "Linkname looked like: " << linkname << endl;
	}
}

/* updates the `inodeproc' inode-to-prg_node 
 * for all inodes belonging to this PID 
 * (/proc/pid/fd/42)
 * */
void get_info_for_pid(char * pid) {
	size_t dirlen = 10 + strlen(pid);
	char * dirname = (char *) malloc (dirlen * sizeof(char));
	snprintf(dirname, dirlen, "/proc/%s/fd", pid);

	//std::cout << "Getting info for pid " << pid << std::endl;

	DIR * dir = opendir(dirname);

	if (!dir)
	{
		std::cout << "Couldn't open dir " << dirname << ": " << strerror(errno) << "\n";
		free (dirname);
		return;
	}

	/* walk through /proc/%s/fd/... */
	dirent * entry;
	while ((entry = readdir(dir))) {
		if (entry->d_type != DT_LNK)
			continue;
		//std::cout << "Looking at: " << entry->d_name << std::endl;

		int fromlen = dirlen + strlen(entry->d_name) + 1;
		char * fromname = (char *) malloc (fromlen * sizeof(char));
		snprintf (fromname, fromlen, "%s/%s", dirname, entry->d_name);

		//std::cout << "Linking from: " << fromname << std::endl;

		int linklen = 80;
		char linkname [linklen];
		int usedlen = readlink(fromname, linkname, linklen-1);
		if (usedlen == -1)
		{
			free (fromname);
			continue;
		}
		if (!ROBUST)
			assert (usedlen < linklen);
		linkname[usedlen] = '\0';
		//std::cout << "Linking to: " << linkname << std::endl;
		get_info_by_linkname (pid, linkname);
		free (fromname);
	}
	closedir(dir);
	free (dirname);
}

/* updates the `inodeproc' inode-to-prg_node mapping 
 * for all processes in /proc */
void reread_mapping () {
	DIR * proc = opendir ("/proc");

	if (proc == 0) {
		std::cerr << "Error reading /proc, neede to get inode-to-pid-maping\n";
		exit(1);
	}

	dirent * entry;

	while ((entry = readdir(proc))) {
		if (entry->d_type != DT_DIR) continue;

		if (! is_number (entry->d_name)) continue;

		//std::cout << "Getting info for " << entry->d_name << std::endl;
		get_info_for_pid(entry->d_name);
	}
	//std::cout << "End...\n";
	closedir(proc);
}

struct prg_node * findPID (unsigned long inode)
{
	/* we first look in inodeproc */
	struct prg_node * node = inodeproc[inode];
	
	if (node != NULL)
		return node;

	reread_mapping();
	
	return inodeproc[inode];
}

void prg_cache_clear() {};

/*void main () {
	std::cout << "Fooo\n";
	reread_mapping();
	std::cout << "Haihai\n";
}*/
