#include <cstddef> // NULL

class device {
public:
	device (const char * m_name, device * m_next = NULL) 
	{
		name = m_name; next = m_next;
	}
	const char * name;
	device * next;
};

device * determine_default_device();
