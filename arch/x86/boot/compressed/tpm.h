/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOOT_COMPRESSED_TPM_H
#define BOOT_COMPRESSED_TPM_H

#include <linux/types.h>
#include <asm/io.h>
#include <asm/msr.h>
#include <asm/tsc.h>

enum early_tpm_defaults {
	TPM_MEM_X86_LPC_BASE	= 0xFED40000,
	TPM_MEM_X86_LEN		= 0x5000,
	TPM_TIMEOUT		= 5, /* ms */
};

enum tpm_family {
	TPM_FAMILY_INVALID	= 0,
	TPM_FAMILY_12		= 1,
	TPM_FAMILY_20		= 2
};

struct tpm_chip;

struct tpm_ops {
	int (*request_locality)(struct tpm_chip *chip, int loc);
	void (*release_locality)(struct tpm_chip *chip);
	int (*transmit)(struct tpm_chip *chip, u8 *buf, u32 bufsize);
	void (*disable_interrupts)(struct tpm_chip *chip);
};

struct tpm_chip {
	enum tpm_family family;
	u64 baseaddr;
	int locality;
	struct tpm_ops ops;

	/* in ms */
	ktime_t timeout_a;
	ktime_t timeout_b;
	ktime_t timeout_c;
	ktime_t timeout_d;
};

int tpm_request_locality(struct tpm_chip *chip, int loc);
void tpm_disable_interrupts(struct tpm_chip *chip);
int tpm1_pcr_extend(struct tpm_chip *chip, u32 pcr_idx, const u8 *hash);
int tpm2_pcr_extend(struct tpm_chip *chip, u32 pcr_idx,
		    struct tpm_digest *digests, u32 digest_count);
int early_tpm_init(struct tpm_chip *chip, u64 baseaddr);
int early_tpm_fini(struct tpm_chip *chip);

/*
 * MMIO register accessors — used by both TIS and CRB interface implementations.
 */
static inline u8 tpm_read8(struct tpm_chip *chip, u32 field)
{
	void *mmio_addr = (void *)(uintptr_t)(chip->baseaddr | field);
	return readb(mmio_addr);
}

static inline void tpm_write8(struct tpm_chip *chip, u32 field, u8 val)
{
	void *mmio_addr = (void *)(uintptr_t)(chip->baseaddr | field);
	writeb(val, mmio_addr);
}

static inline u32 tpm_read32(struct tpm_chip *chip, u32 field)
{
	void *mmio_addr = (void *)(uintptr_t)(chip->baseaddr | field);
	return readl(mmio_addr);
}

static inline void tpm_write32(struct tpm_chip *chip, u32 field, u32 val)
{
	void *mmio_addr = (void *)(uintptr_t)(chip->baseaddr | field);
	writel(val, mmio_addr);
}

static inline u64 tpm_read64(struct tpm_chip *chip, u32 field)
{
	void *mmio_addr = (void *)(uintptr_t)(chip->baseaddr | field);
	return readq(mmio_addr);
}

static inline void tpm_write64(struct tpm_chip *chip, u32 field, u64 val)
{
	void *mmio_addr = (void *)(uintptr_t)(chip->baseaddr | field);
	writeq(val, mmio_addr);
}

/*
 * Timing helpers — we're far too early to calibrate time.  Assume a 5GHz
 * processor (the upper end of the Fam19h range), which causes us to be
 * wrong in the safe direction on slower systems.
 */
static unsigned long ticks_per_ms = (5UL * 1000 * 1000 /* cpu_khz */);

static inline ktime_t tpm_now_ms(void)
{
	return rdtsc()/ticks_per_ms;
}

static inline void tpm_mdelay(unsigned int msecs)
{
	unsigned long ticks = msecs * ticks_per_ms;
	unsigned long s, e;

	s = rdtsc();
	do {
		cpu_relax();
		e = rdtsc();
	} while ((e - s) < ticks);
}

#endif /* BOOT_COMPRESSED_TPM_H */
