/* -*- linux-c -*- 
 * Print Flush Function
 * Copyright (C) 2007-2008 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

/** Send the print buffer to the transport now.
 * Output accumulates in the print buffer until it
 * is filled, or this is called. This MUST be called before returning
 * from a probe or accumulated output in the print buffer will be lost.
 *
 * @note Preemption must be disabled to use this.
 */

static DEFINE_SPINLOCK(_stp_print_lock);

void EXPORT_FN(stp_print_flush) (_stp_pbuf *pb)
{
	uint32_t len = pb->len;

	/* check to see if there is anything in the buffer */
	dbug_trans(1, "len = %ud\n", len);
	if (likely (len == 0))
		return;

	pb->len = 0;

//DRS FIXME: this digs down too deep in internals
//	if (unlikely(!_stp_utt || _stp_utt->trace_state != Utt_trace_running))
//		return;

#ifdef STP_BULKMODE
	{
#ifdef NO_PERCPU_HEADERS
		void *buf = utt_reserve(_stp_utt, len);
		if (likely(buf))
			memcpy(buf, pb->buf, len);
		else
			atomic_inc (&_stp_transport_failures);
#else
		void *buf = utt_reserve(_stp_utt,
					sizeof(struct _stp_trace) + len);
		if (likely(buf)) {
			struct _stp_trace t = {	.sequence = _stp_seq_inc(),
						.pdu_len = len};
			memcpy(buf, &t, sizeof(t)); // prevent unaligned access
			memcpy(buf + sizeof(t), pb->buf, len);
		} else 
			atomic_inc (&_stp_transport_failures);
#endif
	} 
#else
	{
		struct _stp_entry *entry;
		unsigned long flags;

		dbug_trans(1, "calling _stp_data_write...\n");
		spin_lock_irqsave(&_stp_print_lock, flags);
#if 0
		entry = _stp_data_write_reserve(len);
		if (likely(entry)) {
			memcpy(entry->buf, pb->buf, len);
			_stp_data_write_commit(entry);
		}
		else
#endif
		{
			uint32_t cnt;
			char *bufp = pb->buf;

#define MAX_RESERVE_SIZE (4080 /*BUF_PAGE_SIZE*/ - sizeof(struct _stp_entry) - 8)
			while (len > 0) {
				if (len > MAX_RESERVE_SIZE) {
					len -= MAX_RESERVE_SIZE;
					cnt = MAX_RESERVE_SIZE;
				}
				else {
					cnt = len;
					len = 0;
				}

				entry = _stp_data_write_reserve(cnt);
				if (likely(entry)) {
					memcpy(entry->buf, bufp, cnt);
					_stp_data_write_commit(entry);
					bufp += cnt;
				}
				else {
					atomic_inc (&_stp_transport_failures);
					break;
				}
			}
		}
		spin_unlock_irqrestore(&_stp_print_lock, flags);
	}
#endif /* STP_BULKMODE */
}
