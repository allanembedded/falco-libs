// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>
#include <helpers/interfaces/variable_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(pread64_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, PREAD64_E_SIZE, PPME_SYSCALL_PREAD_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD) */
	s32 fd = (s32)extract__syscall_argument(regs, 0);
	ringbuf__store_s64(&ringbuf, (s64)fd);

	/* Parameter 2: size (type: PT_UINT32) */
	u32 size = (u32)extract__syscall_argument(regs, 2);
	ringbuf__store_u32(&ringbuf, (u32)size);

	/* Parameter 3: pos (type: PT_UINT64) */
	u64 pos = (u64)extract__syscall_argument(regs, 3);
	ringbuf__store_u64(&ringbuf, pos);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(pread64_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_PREAD_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	if(ret > 0)
	{
		/* We read the minimum between `snaplen` and what we really
		 * have in the buffer.
		 */
		u16 snaplen = maps__get_snaplen();
		apply_dynamic_snaplen(regs, &snaplen, false);
		if(snaplen > ret)
		{
			snaplen = ret;
		}

		/* Parameter 2: data (type: PT_BYTEBUF) */
		unsigned long data_ptr = extract__syscall_argument(regs, 1);
		auxmap__store_bytebuf_param(auxmap, data_ptr, snaplen, USER);
	}
	else
	{
		/* Parameter 2: data (type: PT_BYTEBUF) */
		auxmap__store_empty_param(auxmap);
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap, ctx);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
