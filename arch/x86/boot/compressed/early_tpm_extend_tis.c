// SPDX-License-Identifier: GPL-2.0-only
/*
 * Early TPM TIS (FIFO) interface driver for Secure Launch.
 *
 * Copyright (c) 2010-2012 United States Government, as represented by
 * the Secretary of Defense.  All rights reserved.
 *
 * based off of the original tools/vtpm_manager code base which is:
 * Copyright (c) 2005, Intel Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <linux/types.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <asm/io.h>
#include <asm/msr.h>

#include <crypto/sha2.h>
#include <linux/tpm_ptp.h>
#include <linux/tpm_common.h>

#include "tpm.h"

enum early_tis_defaults {
	TIS_DURATION		= 120000, /* 120 secs in ms */
};

/*
 * Locality management — defined first as they are called from
 * the send/recv error paths below.
 */

static bool tpm_tis_check_locality(struct tpm_chip *chip, int loc)
{
	if ((tpm_read8(chip, TPM_ACCESS(loc)) & (TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID)) == (TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID)) {
		chip->locality = loc;
		return true;
	}

	return false;
}

static int tpm_tis_request_locality(struct tpm_chip *chip, int loc)
{
	ktime_t stop;

	if (tpm_tis_check_locality(chip, loc))
		return loc;

	/* Set the new locality */
	tpm_write8(chip, TPM_ACCESS(loc), TPM_ACCESS_REQUEST_USE);

	stop = tpm_now_ms() + chip->timeout_b;
	do {
		if (tpm_tis_check_locality(chip, loc))
			return loc;

		tpm_mdelay(TPM_TIMEOUT);
	} while (tpm_now_ms() < stop);

	return -1;
}

static void tpm_tis_release_locality(struct tpm_chip *chip)
{
	if ((tpm_read8(chip, TPM_ACCESS(chip->locality)) & (TPM_ACCESS_REQUEST_PENDING | TPM_ACCESS_VALID)) == (TPM_ACCESS_REQUEST_PENDING | TPM_ACCESS_VALID))
		tpm_write8(chip, TPM_ACCESS(chip->locality), TPM_ACCESS_RELINQUISH_LOCALITY);

	chip->locality = 0;
}

/*
 * TIS FIFO status helpers
 */

static inline u8 __tis_status(struct tpm_chip *chip)
{
	return tpm_read8(chip, TPM_STS(chip->locality));
}

static inline void __tis_cancel(struct tpm_chip *chip)
{
	/* This causes the current command to be aborted */
	tpm_write8(chip, TPM_STS(chip->locality), TPM_STS_COMMAND_READY);
}

static int __tis_get_burstcount(struct tpm_chip *chip)
{
	ktime_t stop;
	int burstcnt;

	stop = tpm_now_ms() + chip->timeout_d;
	do {
		burstcnt = tpm_read8(chip, (TPM_STS(chip->locality) + 1));
		burstcnt += tpm_read8(chip, TPM_STS(chip->locality) + 2) << 8;

		if (burstcnt)
			return burstcnt;

		tpm_mdelay(TPM_TIMEOUT);
	} while (tpm_now_ms() < stop);

	return -EBUSY;
}

static int __tis_wait_for_stat(struct tpm_chip *chip, u8 mask, ktime_t timeout)
{
	ktime_t stop;
	u8 status;

	if ((__tis_status(chip) & mask) == mask)
		return 0;

	stop = tpm_now_ms() + timeout;
	do {
		tpm_mdelay(TPM_TIMEOUT);

		status = __tis_status(chip);
		if ((status & mask) == mask)
			return 0;
	} while (tpm_now_ms() < stop);

	return -ETIME;
}

static int __tis_recv_data(struct tpm_chip *chip, u8 *buf, int count)
{
	int size = 0;
	int burstcnt;

	while (size < count && __tis_wait_for_stat(chip, TPM_STS_DATA_AVAIL | TPM_STS_VALID, chip->timeout_c) == 0) {
		burstcnt = __tis_get_burstcount(chip);

		for ( ; burstcnt > 0 && size < count; --burstcnt)
			buf[size++] = tpm_read8(chip, TPM_DATA_FIFO(chip->locality));
	}

	return size;
}

/*
 * TIS FIFO send/recv/transmit
 */

/**
 * tpm_tis_recv - Receive response data from TPM via TIS FIFO
 * @chip:	The TPM chip instance
 * @buf:	The response buffer
 * @count:	Length of the response buffer
 *
 * Return:
 *  = 0 - Success, no response data
 *  > 0 - Success, value is the response data length
 *  < 0 - Error occurred
 */
static int tpm_tis_recv(struct tpm_chip *chip, u8 *buf, int count)
{
	int expected, status, size = 0, rc = -EIO;

	if (count < TPM_HEADER_SIZE)
		goto out;

	/* Read first 10 bytes, including tag, paramsize, and result */
	size = __tis_recv_data(chip, buf, TPM_HEADER_SIZE);
	if (size < TPM_HEADER_SIZE)
		goto out;

	expected = be32_to_cpu(*((u32 *)(buf + 2)));
	if (expected > count)
		goto out;

	size += __tis_recv_data(chip, &buf[TPM_HEADER_SIZE], expected - TPM_HEADER_SIZE);
	if (size < expected) {
		rc = -ETIME;
		goto out;
	}

	__tis_wait_for_stat(chip, TPM_STS_VALID, chip->timeout_c);

	status = __tis_status(chip);
	if (status & TPM_STS_DATA_AVAIL) {
		rc = -EIO;
		goto out;
	}

	__tis_cancel(chip);
	return size;
out:
	__tis_cancel(chip);
	tpm_tis_release_locality(chip);
	return rc;
}

/**
 * tpm_tis_send - Send command to TPM via TIS FIFO
 * @chip:	The TPM chip instance
 * @buf:	The command buffer
 * @len:	Length of the command buffer to send
 *
 * Return:
 *  = len - Success, all data sent
 *  < 0	  - Error occurred
 */
static int tpm_tis_send(struct tpm_chip *chip, u8 *buf, int len)
{
	int status, burstcnt = 0;
	int count = 0;
	int rc = 0;

	status = __tis_status(chip);
	if ((status & TPM_STS_COMMAND_READY) == 0) {
		__tis_cancel(chip);
		if (__tis_wait_for_stat(chip, TPM_STS_COMMAND_READY, chip->timeout_b) < 0) {
			rc = -ETIME;
			goto out_err;
		}
	}

	while (count < len - 1) {
		burstcnt = __tis_get_burstcount(chip);
		for ( ; burstcnt > 0 && count < len - 1; --burstcnt)
			tpm_write8(chip, TPM_DATA_FIFO(chip->locality), buf[count++]);

		__tis_wait_for_stat(chip, TPM_STS_VALID, chip->timeout_c);
		status = __tis_status(chip);
		if ((status & TPM_STS_DATA_EXPECT) == 0) {
			rc = -EIO;
			goto out_err;
		}
	}

	/* Write last byte */
	tpm_write8(chip, TPM_DATA_FIFO(chip->locality), buf[count]);
	__tis_wait_for_stat(chip, TPM_STS_VALID, chip->timeout_c);
	status = __tis_status(chip);
	if ((status & TPM_STS_DATA_EXPECT) != 0) {
		rc = -EIO;
		goto out_err;
	}

	/* Go and do it */
	tpm_write8(chip, TPM_STS(chip->locality), TPM_STS_GO);

	return len;

out_err:
	__tis_cancel(chip);
	tpm_tis_release_locality(chip);
	return rc;
}

/**
 * tpm_tis_transmit - Transmit a TPM command via TIS FIFO
 * @chip:	The TPM chip instance
 * @buf:	The request and response buffer object
 * @bufsize:	Entire size available in buffer
 *
 * Return:
 *  = 0 - Success, no returned data
 *  > 0 - Success, value is the return data length
 *  < 0 - Error occurred
 */
static int tpm_tis_transmit(struct tpm_chip *chip, u8 *buf, u32 bufsize)
{
	ktime_t stop;
	u32 count;
	u8 status;
	int rc;

	count = be32_to_cpu(*((u32 *) (buf + 2)));
	if (count == 0)
		return -ENODATA;

	if (count > bufsize)
		return -E2BIG;

	rc = tpm_tis_send(chip, buf, count);
	if (rc < 0)
		goto out;

	stop = tpm_now_ms() + TIS_DURATION;
	do {
		status = __tis_status(chip);
		if ((status & (TPM_STS_DATA_AVAIL | TPM_STS_VALID)) == (TPM_STS_DATA_AVAIL | TPM_STS_VALID))
			goto out_recv;

		if (status == TPM_STS_COMMAND_READY) {
			rc = -ECANCELED;
			goto out;
		}

		tpm_mdelay(TPM_TIMEOUT);
		rmb();
	} while (tpm_now_ms() < stop);

	/* Cancel the command */
	__tis_cancel(chip);
	rc = -ETIME;
	goto out;

out_recv:
	rc = tpm_tis_recv(chip, buf, bufsize);
	if (rc >= 0) {
		if (rc > 0 && rc < TPM_HEADER_SIZE)
			return -EFAULT;
		return rc;
	}
	/* Else return was an error, nothing to receive */

out:
	return rc;
}

/**
 * tpm_tis_disable_interrupts - Disable interrupts for the TPM, use polling only
 * @chip:	The TPM chip instance
 */
static void tpm_tis_disable_interrupts(struct tpm_chip *chip)
{
	u32 intmask;

	intmask = tpm_read32(chip, TPM_INT_ENABLE(chip->locality));
	/* Disable everything to make sure it is in a consistent state */
	intmask &= ~(TPM_GLOBAL_INT_ENABLE | TPM_INTF_CMD_READY_INT | TPM_INTF_LOCALITY_CHANGE_INT | TPM_INTF_STS_VALID_INT | TPM_INTF_DATA_AVAIL_INT);
	tpm_write32(chip, TPM_INT_ENABLE(chip->locality), intmask);
}

void tpm_tis_init_ops(struct tpm_ops *ops)
{
	ops->request_locality	= tpm_tis_request_locality;
	ops->release_locality	= tpm_tis_release_locality;
	ops->transmit		= tpm_tis_transmit;
	ops->disable_interrupts	= tpm_tis_disable_interrupts;
}
