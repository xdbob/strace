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
#include "xlat/binder_transaction_flags.h"
#include "xlat/binder_types.h"

static void
decode_flat_binder_object(struct flat_binder_object *obj)
{
	tprints("{type=");
	printxval(binder_types, obj->hdr.type, "BINDER_TYPE_???");
	tprints(", flags=");

	if (obj->flags & FLAT_BINDER_FLAG_ACCEPTS_FDS)
		tprints("FLAT_BINDER_FLAG_ACCEPTS_FDS|");
	tprintf("%" PRIx32, FLAT_BINDER_FLAG_PRIORITY_MASK & obj->flags);

	switch (obj->hdr.type) {
	case BINDER_TYPE_HANDLE:
	case BINDER_TYPE_WEAK_HANDLE:
	case BINDER_TYPE_FD:
		tprintf(", {handle=%" PRIu32 "}", obj->handle);
		break;
	case BINDER_TYPE_BINDER:
	case BINDER_TYPE_WEAK_BINDER:
		tprintf(", {binder=0x%" PRIx64 "}", (uint64_t)obj->binder);
		break;
	default:
		break;
	}

	tprintf(", cookie=0x%" PRIx64 "}", (uint64_t)obj->cookie);
}

static bool
print_flat_binder_object(struct tcb *tcp, void *offset, size_t elem_size,
		void *buffer)
{
	(void)elem_size;
	binder_size_t *i = offset;
	struct flat_binder_object obj;

	if (umove(tcp, (uintptr_t)buffer + *i, &obj))
		return false;

	decode_flat_binder_object(&obj);
	return true;
}

static int
decode_binder_transaction_buffer(struct tcb *tcp, struct binder_transaction_data *tr)
{
	binder_size_t sz;

	return !print_array(tcp,
			tr->data.ptr.offsets,
			tr->offsets_size / sizeof(binder_size_t),
			&sz,
			sizeof(binder_size_t),
			umoven_or_printaddr,
			print_flat_binder_object,
			(void *)tr->data.ptr.buffer);
}

static int
decode_binder_transaction(struct tcb *tcp, uintptr_t addr, int reply,
		int command)
{
	struct binder_transaction_data tr;

	if (umove(tcp, addr, &tr))
		return 1;

	tprints("{");
	if (!reply) {
		if (command)
			tprintf("{handle=%" PRIu32 "}, ", tr.target.handle);
		else
			tprintf("{ptr=0x%" PRIx64 "}, ",
					(uint64_t)tr.target.ptr);
	}

	tprintf("cookie=0x%" PRIx64 ", code=%" PRIu32 ", flags=",
			(uint64_t)tr.cookie, tr.code);
	printflags(binder_transaction_flags, tr.flags, "TF_???");
	tprintf(", sender_pid=%d, sender_euid=%d, data_size=%" PRIu64
			", offsets_size=%" PRIu64,
			tr.sender_pid, tr.sender_euid,
			(uint64_t)tr.data_size, (uint64_t)tr.offsets_size);

	tprints(", data=[");
	int err = 0;

	if (!tr.offsets_size)
		printstrn(tcp, tr.data.ptr.buffer, tr.data_size);
	else
		err = decode_binder_transaction_buffer(tcp, &tr);

	tprints("]}");
	return err;
}

static void
decode_binder_ptr_cookie(struct tcb *tcp, uintptr_t addr)
{
	struct binder_ptr_cookie ptr;

	if (!umove(tcp, addr, &ptr))
		tprintf("{ptr=0x%" PRIx64 ", cookie=0x%" PRIx64 "}",
				(uint64_t)ptr.ptr, (uint64_t)ptr.cookie);
}

static void
decode_binder_pri_desc(struct tcb *tcp, uintptr_t addr)
{
	struct binder_pri_desc desc;

	if (!umove(tcp, addr, &desc))
		tprintf("{priority=%" PRId32 ", desc=%" PRIu32 "}",
				desc.priority, desc.desc);
}

static void
decode_binder_handle_cookie(struct tcb *tcp, uintptr_t addr)
{
	struct binder_handle_cookie handle;

	if (!umove(tcp, addr, &handle))
		tprintf("{handle=%" PRIu32 ", cookie=0x%" PRIx64 "}",
				handle.handle, (uint64_t)handle.cookie);
}

static void
decode_binder_pri_ptr_cookie(struct tcb *tcp, uintptr_t addr)
{
	struct binder_pri_ptr_cookie ptr;

	if (!umove(tcp, addr, &ptr))
		tprintf("{priority=%" PRId32 ", ptr=0x%" PRIx64
				", cookie=0x%" PRIx64 "}",
				ptr.priority, (uint64_t)ptr.ptr,
				(uint64_t)ptr.cookie);
}

static int
decode_binder_commands_parameters(struct tcb *tcp, uint32_t type, uintptr_t addr)
{
	int err = 0;

	tprints("{");
	printxval(binder_driver_commands, type, "BC_???");
	tprints(", ");

	switch (type) {
	case BC_TRANSACTION:
		err = decode_binder_transaction(tcp, addr, 0, 1);
		break;
	case BC_REPLY:
		err = decode_binder_transaction(tcp, addr, 1, 1);
		break;
	case BC_ACQUIRE_RESULT: {
		int32_t i;

		if (umove(tcp, addr, &i))
			err = 1;
		else
			tprintf("%" PRId32, i);
		}
		break;
	case BC_FREE_BUFFER:
	case BC_DEAD_BINDER_DONE: {
		binder_uintptr_t ptr;

		if (umove(tcp, addr, &ptr))
			err = 1;
		else
			tprintf("0x%" PRIx64, (uint64_t)ptr);
		}
		break;
	case BC_INCREFS:
	case BC_ACQUIRE:
	case BC_RELEASE:
	case BC_DECREFS: {
		uint32_t i;

		if (umove(tcp, addr, &i))
			err = 1;
		else
			tprintf("%" PRIu32, i);
		}
		break;
	case BC_INCREFS_DONE:
	case BC_ACQUIRE_DONE:
		decode_binder_ptr_cookie(tcp, addr);
		break;
	case BC_ATTEMPT_ACQUIRE:
		decode_binder_pri_desc(tcp, addr);
		break;
	case BC_REQUEST_DEATH_NOTIFICATION:
	case BC_CLEAR_DEATH_NOTIFICATION:
		decode_binder_handle_cookie(tcp, addr);
		break;
	default:
		printstrn(tcp, addr, _IOC_SIZE(type));
		break;
	}

	tprints("}");
	return err;
}

static int
decode_binder_returns_parameters(struct tcb *tcp, uint32_t type, uintptr_t addr)
{
	int err = 0;

	tprints("{");
	printxval(binder_driver_returns, type, "BR_???");
	tprints(", ");

	switch (type) {
	case BR_TRANSACTION:
		err = decode_binder_transaction(tcp, addr, 0, 0);
		break;
	case BR_REPLY:
		err = decode_binder_transaction(tcp, addr, 1, 0);
		break;
	case BR_ACQUIRE_RESULT:
	case BR_ERROR: {
		int32_t i;

		if (umove(tcp, addr, &i))
			err = 1;
		else
			tprintf("%" PRId32, i);
		}
		break;
	case BR_INCREFS:
	case BR_ACQUIRE:
	case BR_RELEASE:
	case BR_DECREFS:
		decode_binder_ptr_cookie(tcp, addr);
		break;
	case BR_ATTEMPT_ACQUIRE:
		decode_binder_pri_ptr_cookie(tcp, addr);
		break;
	case BR_DEAD_BINDER:
	case BR_CLEAR_DEATH_NOTIFICATION_DONE: {
		binder_uintptr_t ptr;

		if (umove(tcp, addr, &ptr))
			err = 1;
		else
			tprintf("0x%" PRIx64, (uint64_t)ptr);
		}
		break;
	default:
		printstrn(tcp, addr, _IOC_SIZE(type));
		break;
	}

	tprints("}");
	return err;
}

static int
decode_binder_commands_buffer(struct tcb *tcp, uintptr_t buffer, size_t pos,
		size_t size, const struct xlat *x, const char *str,
		int (*const decode_func)(struct tcb *, uint32_t, uintptr_t))
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
				&& pos + sizeof(type) + _IOC_SIZE(type) <= size)
			decode_func(tcp, type, buffer + pos + sizeof(uint32_t));
		else
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
					binder_driver_commands, "BC_???",
					decode_binder_commands_parameters)) {
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
				binder_driver_returns, "BR_???",
				decode_binder_returns_parameters)) {
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
