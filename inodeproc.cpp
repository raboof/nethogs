/* this comes from netstat.c, but is very useful :)) */

/* now unused, replaced by my own implementation */
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <malloc.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>


#include "nethogs.h"

struct proginfo
{
	int pid;
	char* name;
};

#define PATH_PROC       "/proc"
#define PATH_FD_SUFF "fd"
#define PATH_PROC_X_FD      PATH_PROC "/%s/" PATH_FD_SUFF
#define PATH_FD_SUFFl       strlen(PATH_FD_SUFF)
#define PRG_SOCKET_PFX    "socket:["
#define PRG_SOCKET_PFXl (strlen(PRG_SOCKET_PFX))
#define PRG_SOCKET_PFX2   "[0000]:"
#define PRG_SOCKET_PFX2l  (strlen(PRG_SOCKET_PFX2))
#define PATH_CMDLINE "cmdline"
#define PATH_CMDLINEl       strlen(PATH_CMDLINE)
#define PRG_HASH_SIZE 211
#define PRG_HASHIT(x) ((x) % PRG_HASH_SIZE)

static struct prg_node {
    struct prg_node *next;
    int inode;
    int pid;
    char name[PROGNAME_WIDTH];
} *prg_hash[PRG_HASH_SIZE];

static char prg_cache_loaded = 0;

static void prg_cache_clear(void)
{
    struct prg_node **pnp,*pn;

    if (prg_cache_loaded == 2)
	for (pnp=prg_hash;pnp<prg_hash+PRG_HASH_SIZE;pnp++)
	    while ((pn=*pnp)) {
		*pnp=pn->next;
		free(pn);
	    }
    prg_cache_loaded=0;
}

static prg_node * prg_cache_get(int inode)
{
    unsigned hi=PRG_HASHIT(inode);
    struct prg_node *pn;

    for (pn=prg_hash[hi];pn;pn=pn->next)
	if (pn->inode==inode) return(pn);

    return(NULL);
}

static void prg_cache_add(int inode, char *name, int pid)
{
    unsigned hi = PRG_HASHIT(inode);
    struct prg_node **pnp,*pn;

    prg_cache_loaded=2;
    for (pnp=prg_hash+hi;(pn=*pnp);pnp=&pn->next) {
	if (pn->inode==inode) {
	    /* Some warning should be appropriate here
	       as we got multiple processes for one i-node */
	    return;
	}
    }
    if (!(*pnp=(prg_node*)malloc(sizeof(**pnp)))) 
	return;
    pn=*pnp;
    pn->next=NULL;
    pn->inode=inode;
    pn->pid=pid;
    if (strlen(name)>sizeof(pn->name)-1) 
	name[sizeof(pn->name)-1]='\0';
    strcpy(pn->name,name);
}

static void extract_type_1_socket_inode(const char lname[], long * inode_p) {
    /* If lname is of the form "socket:[12345]", extract the "12345"
       as *inode_p.  Otherwise, return -1 as *inode_p.
       */

    if (strlen(lname) < PRG_SOCKET_PFXl+3) *inode_p = -1;
    else if (memcmp(lname, PRG_SOCKET_PFX, PRG_SOCKET_PFXl)) *inode_p = -1;
    else if (lname[strlen(lname)-1] != ']') *inode_p = -1;
    else {
        char inode_str[strlen(lname + 1)];  /* e.g. "12345" */
        const int inode_str_len = strlen(lname) - PRG_SOCKET_PFXl - 1;
        char *serr;

        strncpy(inode_str, lname+PRG_SOCKET_PFXl, inode_str_len);
        inode_str[inode_str_len] = '\0';
        *inode_p = strtol(inode_str,&serr,0);
        if (!serr || *serr || *inode_p < 0 || *inode_p >= INT_MAX) 
            *inode_p = -1;
    }
}

static void extract_type_2_socket_inode(const char lname[], long * inode_p) {
    /* If lname is of the form "[0000]:12345", extract the "12345"
       as *inode_p.  Otherwise, return -1 as *inode_p.
       */

    if (strlen(lname) < PRG_SOCKET_PFX2l+1) *inode_p = -1;
    else if (memcmp(lname, PRG_SOCKET_PFX2, PRG_SOCKET_PFX2l)) *inode_p = -1;
    else {
        char *serr;

        *inode_p=strtol(lname + PRG_SOCKET_PFX2l,&serr,0);
        if (!serr || *serr || *inode_p < 0 || *inode_p >= INT_MAX) 
            *inode_p = -1;
    }
}


static void prg_cache_load(void)
{
    char line[LINE_MAX],eacces=0;
    int procfdlen,fd,cmdllen,lnamelen;
    char lname[30],cmdlbuf[512],finbuf[PROGNAME_WIDTH];
    long inode;
    const char *cs,*cmdlp;
    DIR *dirproc=NULL,*dirfd=NULL;
    struct dirent *direproc,*direfd;

    if (prg_cache_loaded) return;
    prg_cache_loaded=1;
    cmdlbuf[sizeof(cmdlbuf)-1]='\0';
    if (!(dirproc=opendir(PATH_PROC))) goto fail;
    while (errno=0,direproc=readdir(dirproc)) {
#ifdef DIRENT_HAVE_D_TYPE_WORKS
	if (direproc->d_type!=DT_DIR) continue;
#endif
	for (cs=direproc->d_name;*cs;cs++)
	    if (!isdigit(*cs)) 
		break;
	if (*cs) 
	    continue;
	procfdlen=snprintf(line,sizeof(line),PATH_PROC_X_FD,direproc->d_name);
	if (procfdlen<=0 || procfdlen>=sizeof(line)-5) 
	    continue;
	errno=0;
	dirfd=opendir(line);
	// dirfd = fd for /proc/4322341/fd
	if (! dirfd) {
	    if (errno==EACCES) 
		eacces=1;
	    continue;
	}
	line[procfdlen] = '/';
	// line =~ /proc/4322341/fd/
	cmdlp = NULL;
	while ((direfd = readdir(dirfd))) {
	    if (direfd->d_type!=DT_LNK) 
		continue;
	    if (procfdlen+1+strlen(direfd->d_name)+1>sizeof(line)) 
		continue;
	    // line =~ /proc/4322341/fd/<name>
	    //                       fd/
	    memcpy(line + procfdlen - PATH_FD_SUFFl, PATH_FD_SUFF "/",
		   PATH_FD_SUFFl+1);
	    strcpy(line + procfdlen + 1, direfd->d_name);
	    lnamelen=readlink(line,lname,sizeof(lname)-1);
	    fprintf (stdout, "Checking out link: %s\n", line);
            lname[lnamelen] = '\0';  /*make it a null-terminated string*/
	    fprintf (stdout, "Name: %s\n", lname);

            extract_type_1_socket_inode(lname, &inode);

            if (inode < 0) extract_type_2_socket_inode(lname, &inode);

            if (inode < 0) continue;

	    if (!cmdlp) {
		if (procfdlen - PATH_FD_SUFFl + PATH_CMDLINEl >= 
		    sizeof(line) - 5) 
		    continue;
		strcpy(line + procfdlen-PATH_FD_SUFFl, PATH_CMDLINE);
		fprintf(stdout, "Looking into %s\n", line);
		fd = open(line, O_RDONLY);
		if (fd < 0) 
		    continue;
		cmdllen = read(fd, cmdlbuf, sizeof(cmdlbuf) - 1);
		if (close(fd)) 
		    continue;
		if (cmdllen == -1) 
		    continue;
		if (cmdllen < sizeof(cmdlbuf) - 1) 
		    cmdlbuf[cmdllen]='\0';
		if ((cmdlp = strrchr(cmdlbuf, '/'))) 
		    cmdlp++;
		else 
		    cmdlp = cmdlbuf;
	    }

	    //snprintf(finbuf, sizeof(finbuf), "%s/%s", direproc->d_name, cmdlp);
	    snprintf(finbuf, sizeof(finbuf), "%s", cmdlp);
	    int pid; 
	    sscanf(direproc->d_name, "%d", &pid);
	    fprintf(stdout, "Adding: inode %d, buf %s, pid %d\n", inode, finbuf, pid);
	    prg_cache_add(inode, finbuf, pid);
	}
	closedir(dirfd); 
	dirfd = NULL;
    }
    if (dirproc) 
	closedir(dirproc);
    if (dirfd) 
	closedir(dirfd);
    if (!eacces) 
	return;
    if (prg_cache_loaded == 1) {
    fail:
	fprintf(stderr,"(No info could be read for \"-p\": geteuid()=%d but you should be root.)\n",
		geteuid());
    }
    else
	fprintf(stderr, "(Not all processes could be identified, non-owned process info\n"
			 " will not be shown, you would have to be root to see it all.)\n");
}

void main () {
	prg_cache_load();
}
