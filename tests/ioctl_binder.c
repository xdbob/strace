#include "tests.h"

#if defined(HAVE_LINUX_ANDROID_BINDER_H) || defined(__ANDROID__)

# include <sys/ioctl.h>
# include <linux/ioctl.h>
# include <stdio.h>
# include <inttypes.h>
# include <stdlib.h>

# if SIZEOF_LONG == 4
#  define BINDER_IPC_32BIT
# endif
# ifdef HAVE_LINUX_ANDROID_BINDER_H
#  include <linux/android/binder.h>
# else
#  include <linux/binder.h>
# endif

int
main(void)
{
	/* All the tests are performed without the driver */
	int32_t snbr = 12;
	ioctl(-1, BINDER_SET_IDLE_PRIORITY, &snbr);
	printf("ioctl(-1, BINDER_SET_IDLE_PRIORITY, [%" PRId32 "]) = "
			"-1 EBADF (Bad file descriptor)\n", snbr);

	snbr = -125;
	ioctl(-1, BINDER_SET_CONTEXT_MGR, &snbr);
	printf("ioctl(-1, BINDER_SET_CONTEXT_MGR, [%" PRId32 "]) = "
			"-1 EBADF (Bad file descriptor)\n", snbr);

	snbr = 42;
	ioctl(-1, BINDER_THREAD_EXIT, &snbr);
	printf("ioctl(-1, BINDER_THREAD_EXIT, [%" PRId32 "]) = "
			"-1 EBADF (Bad file descriptor)\n", snbr);

	uint32_t unbr = 172;
	ioctl(-1, BINDER_SET_MAX_THREADS, &unbr);
	printf("ioctl(-1, BINDER_SET_MAX_THREADS, [%" PRIu32 "]) = "
			"-1 EBADF (Bad file descriptor)\n", unbr);

	int64_t bnbr = 123456789;
	ioctl(-1, BINDER_SET_IDLE_TIMEOUT, &bnbr);
	printf("ioctl(-1, BINDER_SET_IDLE_TIMEOUT, [%" PRIu64 "]) = "
			"-1 EBADF (Bad file descriptor)\n", bnbr);


	struct binder_write_read wr = { 0 };
	wr.write_size = 2 * sizeof(uint32_t)
		+ sizeof(struct binder_transaction_data);
	uint32_t *buf = malloc(wr.write_size);
	if (!buf)
		perror_msg_and_skip("Failed malloc");

	wr.write_buffer = (binder_uintptr_t)buf;
	wr.read_size = 256;
	wr.read_consumed = 15;
	wr.write_consumed = 0;

	buf[0] = BC_ENTER_LOOPER;
	buf[1] = BC_TRANSACTION;
	struct binder_transaction_data *tr = (void *)(buf + 2);
	tr->target.handle = 42;
	tr->cookie = 27;
	tr->code = 99;
	tr->sender_pid = 1000;
	tr->sender_euid = 1500;
	tr->data_size = 0;
	tr->offsets_size = 0;
	tr->data.ptr.buffer = 0;
	tr->data.ptr.offsets = 0;

	ioctl(-1, BINDER_WRITE_READ, &wr);
	printf("ioctl(-1, BINDER_WRITE_READ, {write_size=%" PRIu64
			", write_consumed=%" PRIu64 ", write_buffer=[",
			(uint64_t)wr.write_size, (uint64_t)wr.write_consumed);

	printf("BC_ENTER_LOOPER, {BC_TRANSACTION, {{handle=%" PRIu32
			"}, cookie=0x%" PRIx64 ", code=%" PRIu32
			", flags=0, sender_pid=%d, sender_euid=%d, data_size=%"
			PRIu64 ", offsets_size=%" PRIu64 ", data=[NULL]}}",
			tr->target.handle, (uint64_t)tr->cookie, tr->code,
			tr->sender_pid, tr->sender_euid,
			(uint64_t)tr->data_size, (uint64_t)tr->offsets_size);

	printf("], read_size=%" PRIu64 ", read_consumed=%" PRIu64
			"}) = -1 EBADF (Bad file descriptor)\n",
			(uint64_t)wr.read_size, (uint64_t)wr.read_consumed);

	free(buf);

	puts("+++ exited with 0 +++");

	return 0;
}

#else

SKIP_MAIN_UNDEFINED("HAVE_LINUX_ANDROID_BINDER_H) || __ANDROID__")

#endif
