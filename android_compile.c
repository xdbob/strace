#include "defs.h"

#undef btrfs_ioctl
#undef evdev_ioctl

int
btrfs_ioctl(struct tcb *tcp, const unsigned int code, const long arg)
{
	return RVAL_DECODED;
}

int
evdev_ioctl(struct tcb *tcp, const unsigned int code, const long arg)
{
	return RVAL_DECODED;
}
