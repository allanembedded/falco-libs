// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(brk_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, BRK_E_SIZE, PPME_SYSCALL_BRK_4_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: addr (type: PT_UINT64) */
	unsigned long addr = extract__syscall_argument(regs, 0);
	ringbuf__store_u64(&ringbuf, addr);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(brk_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, BRK_X_SIZE, PPME_SYSCALL_BRK_4_X))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: ret (type: PT_UINT64) */
	/* the return value is the program break */
	ringbuf__store_u64(&ringbuf, ret);

	struct task_struct *task = get_current_task();
	struct mm_struct *mm = NULL;
	READ_TASK_FIELD_INTO(&mm, task, mm);

	u32 vm_size = extract__vm_size(mm);
	u32 rss_size = extract__vm_rss(mm);
	u32 swap_size = extract__vm_swap(mm);

	/* Parameter 2: vm_size (type: PT_UINT32) */
	ringbuf__store_u32(&ringbuf, vm_size);

	/* Parameter 3: vm_rss (type: PT_UINT32) */
	ringbuf__store_u32(&ringbuf, rss_size);

	/* Parameter 4: vm_swap (type: PT_UINT32) */
	ringbuf__store_u32(&ringbuf, swap_size);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
