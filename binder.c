#include "defs.h"

#if defined(HAVE_LINUX_ANDROID_BINDER_H) || defined(__ANDROID__)

#include <linux/ioctl.h>

/*
 * The driver can support either 32 or 64 bit but not both at the same time.
 */
#if SIZEOF_LONG == 4
# define BINDER_IPC_32BIT
#endif
#ifdef HAVE_LINUX_ANDROID_BINDER_H
# include <linux/android/binder.h>
#else
# include <linux/binder.h>
#endif

#include "xlat/binder_driver_commands.h"
#include "xlat/binder_driver_returns.h"

static int
decode_binder_commands_buffer(struct tcb *tcp, uintptr_t buffer, size_t pos,
		size_t size, const struct xlat *x, const char *str)
{
	if (size < sizeof(uint32_t)) {
		printaddr(buffer);
		return 0;
	}

	if (abbrev(tcp)) {
		tprints("[...]");
		return 0;
	}

	uint32_t type;
	int first_time = 1;
	tprints("[");

	while (pos + sizeof(uint32_t) <= size) {
		if (umove(tcp, buffer + pos, &type)) {
			tprints("]");
			return 1;
		}

		if (!first_time)
			tprints(", ");
		else
			first_time = 0;

		if (_IOC_SIZE(type) > 0
				&& pos + sizeof(type) + _IOC_SIZE(type) <= size) {
			tprints("{");
			printxval(x, type, str);
			tprints(", ");
			printstrn(tcp, buffer + pos + sizeof(type),
					_IOC_SIZE(type));
			tprints("}");
		} else
			printxval(x, type, str);

		if (SIZE_MAX - sizeof(uint32_t) + _IOC_SIZE(type) >= pos)
			pos += sizeof(uint32_t) + _IOC_SIZE(type);
		else
			break;
	}

	tprints("]");
	return 0;
}

static int
decode_binder_write_read(struct tcb *tcp, const long addr)
{
	struct binder_write_read wr;

	if (entering(tcp)) {
		tprints(", ");
		if (umove_or_printaddr(tcp, addr, &wr))
			return RVAL_DECODED | RVAL_IOCTL_DECODED;

		tprintf("{write_size=%" PRIu64 ", write_consumed=%" PRIu64
				", write_buffer=",
				(uint64_t)wr.write_size,
				(uint64_t)wr.write_consumed);
		if (decode_binder_commands_buffer(tcp, wr.write_buffer,
					wr.write_consumed, wr.write_size,
					binder_driver_commands, "BC_???")) {
			tprints("}");
			return RVAL_DECODED | RVAL_IOCTL_DECODED;
		}

		tprintf(", read_size=%" PRIu64 ", read_consumed=%" PRIu64 "}",
				(uint64_t)wr.read_size,
				(uint64_t)wr.read_consumed);
		return 0;
	}

	if (syserror(tcp) || umove(tcp, addr, &wr))
		return RVAL_DECODED | RVAL_IOCTL_DECODED;

	tprints(" => ");

	tprintf("{write_size=%" PRIu64 ", write_consumed=%" PRIu64
			", read_size=%" PRIu64 ", read_consumed=%" PRIu64
			", read_buffer=",
			(uint64_t)wr.write_size,
			(uint64_t)wr.write_consumed,
			(uint64_t)wr.read_size,
			(uint64_t)wr.read_consumed);
	if (decode_binder_commands_buffer(tcp, wr.read_buffer, 0,
				wr.read_consumed,
				binder_driver_returns, "BR_???")) {
		tprints("}");
		return RVAL_DECODED | RVAL_IOCTL_DECODED;
	}

	tprints("}");
	return RVAL_DECODED | RVAL_IOCTL_DECODED;
}

int
decode_binder_version(struct tcb *tcp, long addr)
{
	struct binder_version version;

	tprints(", ");
	if (umove_or_printaddr(tcp, addr, &version))
		return RVAL_DECODED | RVAL_IOCTL_DECODED;

	tprintf("{protocol_version=%" PRId32 "}", version.protocol_version);
	return RVAL_DECODED | RVAL_IOCTL_DECODED;
}

int
binder_ioctl(struct tcb *tcp, const unsigned int code, const kernel_ulong_t arg)
{
	if (!verbose(tcp))
		return RVAL_DECODED;

	if (code == BINDER_WRITE_READ)
		return decode_binder_write_read(tcp, arg);

	if (entering(tcp)) {
		switch (code) {
		case BINDER_SET_IDLE_TIMEOUT:
			tprints(", ");
			printnum_int64(tcp, arg, "%lld");
			return RVAL_DECODED | RVAL_IOCTL_DECODED;
		case BINDER_SET_MAX_THREADS:
			tprints(", ");
			printnum_int(tcp, arg, "%u");
			return RVAL_DECODED | RVAL_IOCTL_DECODED;
		case BINDER_SET_IDLE_PRIORITY:
		case BINDER_SET_CONTEXT_MGR:
		case BINDER_THREAD_EXIT:
			tprints(", ");
			printnum_int(tcp, arg, "%d");
			return RVAL_DECODED | RVAL_IOCTL_DECODED;
		default:
			break;
		}
	} else {
		if (code == BINDER_VERSION)
			return decode_binder_version(tcp, arg);
	}

	return 0;
}

#endif /* !(HAVE_LINUX_ANDROID_BINDER_H || __ANDROID__) */
