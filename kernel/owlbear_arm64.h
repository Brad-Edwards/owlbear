/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * owlbear_arm64.h - ARM64 register definitions for hardware checks
 *
 * Defines bit positions and masks for system registers monitored
 * by the anti-cheat. These are architecture-defined in the ARM ARM
 * but not all are exposed as named constants in the kernel headers.
 */

#ifndef OWLBEAR_ARM64_H
#define OWLBEAR_ARM64_H

#ifdef CONFIG_ARM64

/* -------------------------------------------------------------------------
 * SCTLR_EL1 bit definitions
 * ARM Architecture Reference Manual, D17.2.118
 * ----------------------------------------------------------------------- */

#define OWL_SCTLR_M    (1UL << 0)   /* MMU enable */
#define OWL_SCTLR_A    (1UL << 1)   /* Alignment check enable */
#define OWL_SCTLR_C    (1UL << 2)   /* Data cache enable */
#define OWL_SCTLR_SA   (1UL << 3)   /* Stack alignment check */
#define OWL_SCTLR_I    (1UL << 12)  /* Instruction cache enable */
#define OWL_SCTLR_WXN  (1UL << 19)  /* Write implies eXecute Never */
#define OWL_SCTLR_EE   (1UL << 25)  /* Exception endianness */
#define OWL_SCTLR_EnIA (1UL << 31)  /* PAC: Enable Instruction A key */
#define OWL_SCTLR_EnIB (1UL << 30)  /* PAC: Enable Instruction B key */
#define OWL_SCTLR_EnDA (1UL << 27)  /* PAC: Enable Data A key */
#define OWL_SCTLR_EnDB (1UL << 13)  /* PAC: Enable Data B key */

/* Bits that should be set for a secure configuration */
#define OWL_SCTLR_EXPECTED_SET  (OWL_SCTLR_M | OWL_SCTLR_C | OWL_SCTLR_I)

/* -------------------------------------------------------------------------
 * MDSCR_EL1 - Monitor Debug System Control Register
 * ARM ARM D17.2.80
 * ----------------------------------------------------------------------- */

#define OWL_MDSCR_SS   (1UL << 0)   /* Software step enable */
#define OWL_MDSCR_MDE  (1UL << 15)  /* Monitor Debug Enable */
#define OWL_MDSCR_KDE  (1UL << 13)  /* Kernel Debug Enable */

/* -------------------------------------------------------------------------
 * Debug breakpoint/watchpoint control register bits
 * ARM ARM D17.2.26 (DBGBCR) / D17.2.32 (DBGWCR)
 * ----------------------------------------------------------------------- */

#define OWL_DBGBCR_E   (1UL << 0)   /* Breakpoint enable */
#define OWL_DBGWCR_E   (1UL << 0)   /* Watchpoint enable */

/* Maximum number of breakpoint/watchpoint registers */
#define OWL_MAX_BRP    16
#define OWL_MAX_WRP    16

/* -------------------------------------------------------------------------
 * Register IDs for event payload encoding
 * ----------------------------------------------------------------------- */

enum owl_arm64_reg_id {
	OWL_REG_SCTLR_EL1    = 0x0001,
	OWL_REG_TCR_EL1      = 0x0002,
	OWL_REG_MAIR_EL1     = 0x0003,
	OWL_REG_MDSCR_EL1    = 0x0004,
	OWL_REG_VBAR_EL1     = 0x0005,
	OWL_REG_APIAKEYHI    = 0x0010,
	OWL_REG_APIAKEYLO    = 0x0011,
	OWL_REG_DBGBCR_BASE  = 0x0100,  /* + index 0-15 */
	OWL_REG_DBGBVR_BASE  = 0x0120,  /* + index 0-15 */
	OWL_REG_DBGWCR_BASE  = 0x0140,  /* + index 0-15 */
	OWL_REG_DBGWVR_BASE  = 0x0160,  /* + index 0-15 */
};

/* -------------------------------------------------------------------------
 * System register snapshot structure
 * ----------------------------------------------------------------------- */

struct owl_sysreg_snapshot {
	u64 sctlr_el1;
	u64 tcr_el1;
	u64 mair_el1;
	u64 mdscr_el1;
	u64 vbar_el1;
};

struct owl_pac_keys {
	u64 apia_hi;
	u64 apia_lo;
};

#endif /* CONFIG_ARM64 */
#endif /* OWLBEAR_ARM64_H */
