#include "devices.h"

device * determine_default_device()
{
	return new device("eth0");
}

