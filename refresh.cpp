#include <iostream>
#include <signal.h>
#include <unistd.h>
#include "nethogs.h"

extern bool needrefresh;
extern unsigned refreshdelay;

void alarm_cb (int i)
{
    needrefresh = true;
    //cout << "Setting needrefresh\n";

    signal (SIGALRM, &alarm_cb);
    alarm(refreshdelay);
}

