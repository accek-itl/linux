// SPDX-License-Identifier: GPL-2.0-only
/*
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
#include <linux/init.h>
#include <linux/string.h>
#include <crypto/sha2.h>
#include <asm/msr.h>
#include <asm/io.h>

#include <linux/tpm_common.h>
#include <linux/tpm1.h>
#include <linux/tpm2.h>
#include <linux/tpm_ptp.h>
#include <linux/tpm_buf.h>

#include "../../../../drivers/char/tpm/tpm1_structs.h"
#include "../../../../drivers/char/tpm/tpm2_structs.h"

#include "tpm.h"

/* Interface-specific ops initializers (internal) */
void tpm_tis_init_ops(struct tpm_ops *ops);
void tpm_crb_init_ops(struct tpm_ops *ops);

static u8 tpm_buf_page[PAGE_SIZE];

/*
 * Single threaded environment only running on BSP. Use a single shared
 * page for all TPM extend operations.
 */
static inline struct tpm_buf *tpm_buf_alloc_page(void)
{
	memset(tpm_buf_page, 0, PAGE_SIZE);
	return (struct tpm_buf *)tpm_buf_page;
}

static inline void tpm_buf_free_page(void)
{
	memset(tpm_buf_page, 0, PAGE_SIZE);
}

/* Pull in TPM buffer management support */
#undef WARN
#define WARN(c, f...)
#undef WARN_ON
#define WARN_ON(c) (0)

#include "../../../../drivers/char/tpm/tpm-buf.c"

static u32 tpm_get_alg_size(u16 alg_id)
{
	switch (alg_id) {
	case TPM_ALG_SHA1:
		return TPM_DIGEST_SIZE;
	case TPM_ALG_SHA256:
	case TPM_ALG_SM3_256:
		return SHA256_DIGEST_SIZE;
	case TPM_ALG_SHA384:
		return SHA384_DIGEST_SIZE;
	case TPM_ALG_SHA512:
	default:
		return SHA512_DIGEST_SIZE;
	};
}

/**
 * tpm1_pcr_extend - send a TPM1 extend command to the device
 * @chip:	a TPM chip to use
 * @pcr_idx:	the PCR index to extend for the current locality
 * @hash:	the SHA1 hash digest to extend
 *
 * Return:
 * * 0		- OK
 * * -errno	- A system error
 * * TPM_RC	- A TPM error
 */
int tpm1_pcr_extend(struct tpm_chip *chip, u32 pcr_idx, const u8 *hash)
{
	int rc = 0;
	struct tpm_buf *buf = tpm_buf_alloc_page();

	if (!buf)
		return -ENOMEM;

	tpm_buf_init(buf, TPM_BUFSIZE);
	tpm_buf_reset(buf, TPM_TAG_RQU_COMMAND, TPM_ORD_PCR_EXTEND);

	tpm_buf_append_u32(buf, pcr_idx);
	tpm_buf_append(buf, hash, TPM_DIGEST_SIZE);

	rc = chip->ops.transmit(chip, buf->data, PAGE_SIZE);

	/* Ignoring output */
	if (rc > 0)
		rc = 0;

	tpm_buf_free_page();

	return rc;
}

/**
 * tpm2_pcr_extend() - send a TPM2 extend command to the device
 *
 * @chip:		TPM chip to use.
 * @pcr_idx:		index of the PCR.
 * @digests:		list of PCR banks and corresponding digest values to extend.
 * @digest_count:	count of digests to extend
 *
 * Return:
 * * 0		- OK
 * * -errno	- A system error
 * * TPM_RC	- A TPM error
 */
int tpm2_pcr_extend(struct tpm_chip *chip, u32 pcr_idx,
		    struct tpm_digest *digests, u32 digest_count)
{
	struct tpm_buf *buf = tpm_buf_alloc_page();
	int rc = 0, i;

	if (!buf)
		return -ENOMEM;

	tpm_buf_init(buf, TPM_BUFSIZE);
	tpm_buf_reset(buf, TPM2_ST_SESSIONS, TPM2_CC_PCR_EXTEND);

	tpm_buf_append_handle(buf, pcr_idx);

	/* Setup a NULL auth session for the command */
	tpm_buf_append_u32(buf, 9);
	/* auth handle */
	tpm_buf_append_u32(buf, TPM2_RS_PW);
	/* nonce */
	tpm_buf_append_u16(buf, 0);
	/* attributes */
	tpm_buf_append_u8(buf, 0);
	/* passphrase */
	tpm_buf_append_u16(buf, 0);

	tpm_buf_append_u32(buf, digest_count);

	for (i = 0; i < digest_count; i++) {
		tpm_buf_append_u16(buf, digests[i].alg_id);
		tpm_buf_append(buf, (const unsigned char *)&digests[i].digest,
			       tpm_get_alg_size(digests[i].alg_id));
	}

	rc = chip->ops.transmit(chip, buf->data, PAGE_SIZE);

	/* Ignoring output */
	if (rc > 0)
		rc = 0;

	tpm_buf_free_page();

	return rc;
}

int tpm_request_locality(struct tpm_chip *chip, int loc)
{
	return chip->ops.request_locality(chip, loc);
}

void tpm_disable_interrupts(struct tpm_chip *chip)
{
	chip->ops.disable_interrupts(chip);
}

/**
 * early_tpm_init - Detect TPM interface type and family, initialize the chip
 * @chip:	The TPM chip instance to initialize
 * @baseaddr:	MMIO base address for the TPM
 *
 * Detects whether the TPM uses TIS (FIFO) or CRB interface via the
 * TPM_INTF_ID register, determines the TPM family (1.2 or 2.0), sets
 * up function pointers for the detected interface, and performs
 * interface-specific initialization.
 *
 * Return: TPM_SUCCESS (0) on success, TPM_ERR_INVALID_FAMILY on failure
 */
int early_tpm_init(struct tpm_chip *chip, u64 baseaddr)
{
	struct tpm_interface_id intf_id;
	struct tpm_intf_capability intf_cap;

	memset(chip, 0, sizeof(*chip));
	chip->baseaddr = baseaddr;

	/* Set default timeouts */
	chip->timeout_a = TIS_SHORT_TIMEOUT;
	chip->timeout_b = TIS_LONG_TIMEOUT;
	chip->timeout_c = TIS_SHORT_TIMEOUT;
	chip->timeout_d = TIS_SHORT_TIMEOUT;

	/* Detect interface type from TPM_INTF_ID register */
	intf_id.val = tpm_read32(chip, TPM_INTF_ID(0));

	if (intf_id.interface_type == TPM_CRB_INTF_ACTIVE) {
		/* CRB interface — always TPM 2.0 */
		chip->family = TPM_FAMILY_20;
		tpm_crb_init_ops(&chip->ops);
	} else if (intf_id.interface_type == TPM_TIS_INTF_ACTIVE) {
		/* TIS interface — determine family from interface capability */
		intf_cap.val = tpm_read32(chip, TPM_INTF_CAPS(0));
		if ((intf_cap.interface_version == TPM_TIS_INTF_12) ||
		    (intf_cap.interface_version == TPM_TIS_INTF_13))
			chip->family = TPM_FAMILY_12;
		else
			chip->family = TPM_FAMILY_20;
		tpm_tis_init_ops(&chip->ops);
	} else {
		/* Unsupported interface type */
		return TPM_ERR_INVALID_FAMILY;
	}

	return TPM_SUCCESS;
}

int early_tpm_fini(struct tpm_chip *chip)
{
	chip->ops.release_locality(chip);
	memset(chip, 0, sizeof(*chip));

	return TPM_SUCCESS;
}
