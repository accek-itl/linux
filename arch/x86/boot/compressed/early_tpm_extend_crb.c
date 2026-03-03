// SPDX-License-Identifier: GPL-2.0-only
/*
 * Early TPM CRB (Command Response Buffer) interface driver for Secure Launch.
 *
 * Based on drivers/char/tpm/tpm_crb.c and tboot CRB implementation.
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

/*
 * CRB register offsets within a locality page. Each locality occupies
 * a 0x1000-byte region starting at TPM_MEM_X86_LPC_BASE.
 */
#define CRB_LOC_STATE(l)	(0x0000 | ((l) << 12))
#define CRB_LOC_CTRL(l)		(0x0008 | ((l) << 12))
#define CRB_LOC_STS(l)		(0x000C | ((l) << 12))
#define CRB_CTRL_REQ(l)		(0x0040 | ((l) << 12))
#define CRB_CTRL_STS(l)		(0x0044 | ((l) << 12))
#define CRB_CTRL_CANCEL(l)	(0x0048 | ((l) << 12))
#define CRB_CTRL_START(l)	(0x004C | ((l) << 12))
#define CRB_CTRL_CMD_SIZE(l)	(0x0058 | ((l) << 12))
#define CRB_CTRL_CMD_LADDR(l)	(0x005C | ((l) << 12))
#define CRB_CTRL_CMD_HADDR(l)	(0x0060 | ((l) << 12))
#define CRB_CTRL_RSP_SIZE(l)	(0x0064 | ((l) << 12))
#define CRB_CTRL_RSP_ADDR(l)	(0x0068 | ((l) << 12))
#define CRB_DATA_BUFFER(l)	(0x0080 | ((l) << 12))
#define CRB_DATA_BUFFER_SIZE	0x0F80

/* CRB LOC_STATE register bits */
#define CRB_LOC_STATE_LOC_ASSIGNED	BIT(1)
#define CRB_LOC_STATE_REG_VALID_STS	BIT(7)

/* CRB LOC_CTRL register bits */
#define CRB_LOC_CTRL_REQUEST_ACCESS	BIT(0)
#define CRB_LOC_CTRL_RELINQUISH		BIT(1)

/* CRB CTRL_REQ register bits */
#define CRB_CTRL_REQ_CMD_READY		BIT(0)
#define CRB_CTRL_REQ_GO_IDLE		BIT(1)

/* CRB CTRL_STS register bits */
#define CRB_CTRL_STS_ERROR		BIT(0)
#define CRB_CTRL_STS_TPM_IDLE		BIT(1)

/* CRB CTRL_START register bits */
#define CRB_START_INVOKE		BIT(0)

/* CRB CTRL_CANCEL register bits */
#define CRB_CANCEL_INVOKE		BIT(0)

enum crb_defaults {
	CRB_DURATION		= 120000, /* 120 secs in ms */
};

static bool crb_wait_for_reg(struct tpm_chip *chip, u32 field,
			     u32 mask, u32 value, ktime_t timeout)
{
	ktime_t stop;

	if ((tpm_read32(chip, field) & mask) == value)
		return true;

	stop = tpm_now_ms() + timeout;
	do {
		tpm_mdelay(TPM_TIMEOUT);
		if ((tpm_read32(chip, field) & mask) == value)
			return true;
	} while (tpm_now_ms() < stop);

	return false;
}

/**
 * tpm_crb_go_idle - Request TPM CRB device to go idle
 * @chip:	The TPM chip instance
 *
 * Write GO_IDLE to CTRL_REQ and wait for the bit to clear.
 */
static int tpm_crb_go_idle(struct tpm_chip *chip)
{
	tpm_write32(chip, CRB_CTRL_REQ(chip->locality), CRB_CTRL_REQ_GO_IDLE);

	if (!crb_wait_for_reg(chip, CRB_CTRL_REQ(chip->locality),
			      CRB_CTRL_REQ_GO_IDLE, 0, chip->timeout_c))
		return -ETIME;

	return 0;
}

/**
 * tpm_crb_cmd_ready - Request TPM CRB device to enter command-ready state
 * @chip:	The TPM chip instance
 *
 * Write CMD_READY to CTRL_REQ and wait for the bit to clear.
 */
static int tpm_crb_cmd_ready(struct tpm_chip *chip)
{
	tpm_write32(chip, CRB_CTRL_REQ(chip->locality), CRB_CTRL_REQ_CMD_READY);

	if (!crb_wait_for_reg(chip, CRB_CTRL_REQ(chip->locality),
			      CRB_CTRL_REQ_CMD_READY, 0, chip->timeout_c))
		return -ETIME;

	return 0;
}

static int tpm_crb_request_locality(struct tpm_chip *chip, int loc)
{
	u32 mask = CRB_LOC_STATE_LOC_ASSIGNED | CRB_LOC_STATE_REG_VALID_STS;
	u32 value = CRB_LOC_STATE_LOC_ASSIGNED | CRB_LOC_STATE_REG_VALID_STS;

	tpm_write32(chip, CRB_LOC_CTRL(loc), CRB_LOC_CTRL_REQUEST_ACCESS);

	if (!crb_wait_for_reg(chip, CRB_LOC_STATE(loc), mask, value,
			      chip->timeout_c)) {
		return -1;
	}

	chip->locality = loc;
	return loc;
}

static void tpm_crb_release_locality(struct tpm_chip *chip)
{
	u32 mask = CRB_LOC_STATE_LOC_ASSIGNED | CRB_LOC_STATE_REG_VALID_STS;
	u32 value = CRB_LOC_STATE_REG_VALID_STS;

	tpm_write32(chip, CRB_LOC_CTRL(chip->locality), CRB_LOC_CTRL_RELINQUISH);

	crb_wait_for_reg(chip, CRB_LOC_STATE(chip->locality), mask, value,
			 chip->timeout_c);

	chip->locality = 0;
}

/**
 * tpm_crb_transmit - Transmit a TPM command via CRB interface
 * @chip:	The TPM chip instance
 * @buf:	The request and response buffer
 * @bufsize:	Entire size available in buffer
 *
 * The CRB interface uses a shared memory data buffer for both command and
 * response. The flow is:
 *   1. Transition to command-ready state
 *   2. Set up command/response buffer addresses and sizes
 *   3. Copy command into CRB data buffer
 *   4. Write START to begin execution
 *   5. Poll until START clears (command complete)
 *   6. Read response from CRB data buffer
 *
 * Return:
 *  = 0 - Success, no returned data
 *  > 0 - Success, value is the return data length
 *  < 0 - Error occurred
 */
static int tpm_crb_transmit(struct tpm_chip *chip, u8 *buf, u32 bufsize)
{
	u32 cmd_len, expected;
	u32 data_buf_addr;
	int rc;
	int loc = chip->locality;

	cmd_len = be32_to_cpu(*((u32 *)(buf + 2)));
	if (cmd_len == 0)
		return -ENODATA;

	if (cmd_len > bufsize || cmd_len > CRB_DATA_BUFFER_SIZE)
		return -E2BIG;

	/* Ensure TPM is in command-ready state */
	rc = tpm_crb_cmd_ready(chip);
	if (rc)
		return rc;

	/* Clear cancel register */
	tpm_write32(chip, CRB_CTRL_CANCEL(loc), 0);

	/* Set up command/response buffer addresses pointing to CRB data buffer */
	data_buf_addr = chip->baseaddr | CRB_DATA_BUFFER(loc);
	tpm_write32(chip, CRB_CTRL_CMD_LADDR(loc), data_buf_addr);
	tpm_write32(chip, CRB_CTRL_CMD_HADDR(loc), 0);
	tpm_write32(chip, CRB_CTRL_CMD_SIZE(loc), CRB_DATA_BUFFER_SIZE);
	tpm_write64(chip, CRB_CTRL_RSP_ADDR(loc), data_buf_addr);
	tpm_write32(chip, CRB_CTRL_RSP_SIZE(loc), CRB_DATA_BUFFER_SIZE);

	/* Copy command into CRB data buffer */
	memcpy((void *)(uintptr_t)(chip->baseaddr | CRB_DATA_BUFFER(loc)),
	       buf, cmd_len);

	/* Start command execution */
	tpm_write32(chip, CRB_CTRL_START(loc), CRB_START_INVOKE);

	/* Wait for command to complete (START bit clears) */
	if (!crb_wait_for_reg(chip, CRB_CTRL_START(loc),
			      CRB_START_INVOKE, 0, CRB_DURATION)) {
		/* Timeout — try to cancel */
		tpm_write32(chip, CRB_CTRL_CANCEL(loc), CRB_CANCEL_INVOKE);
		crb_wait_for_reg(chip, CRB_CTRL_START(loc),
				 CRB_START_INVOKE, 0, chip->timeout_b);
		return -ETIME;
	}

	/* Check for TPM error */
	if (tpm_read32(chip, CRB_CTRL_STS(loc)) & CRB_CTRL_STS_ERROR)
		return -EIO;

	/* Read response from CRB data buffer */
	memcpy(buf,
	       (void *)(uintptr_t)(chip->baseaddr | CRB_DATA_BUFFER(loc)),
	       TPM_HEADER_SIZE);

	expected = be32_to_cpu(*((u32 *)(buf + 2)));
	if (expected > bufsize || expected > CRB_DATA_BUFFER_SIZE)
		return -EIO;

	if (expected > TPM_HEADER_SIZE) {
		memcpy(buf + TPM_HEADER_SIZE,
		       (void *)(uintptr_t)(chip->baseaddr | CRB_DATA_BUFFER(loc)) + TPM_HEADER_SIZE,
		       expected - TPM_HEADER_SIZE);
	}

	/* Transition back to idle */
	tpm_crb_go_idle(chip);

	return expected;
}

/**
 * tpm_crb_disable_interrupts - No-op for CRB (CRB does not use interrupts)
 * @chip:	The TPM chip instance
 */
static void tpm_crb_disable_interrupts(struct tpm_chip *chip)
{
}

void tpm_crb_init_ops(struct tpm_ops *ops)
{
	ops->request_locality	= tpm_crb_request_locality;
	ops->release_locality	= tpm_crb_release_locality;
	ops->transmit		= tpm_crb_transmit;
	ops->disable_interrupts	= tpm_crb_disable_interrupts;
}
