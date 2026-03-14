// SPDX-License-Identifier: GPL-2.0-only
/*
 * owlbear_arm64.c - ARM64 hardware security checks
 *
 * Monitors ARM64-specific hardware state that cheats may tamper with:
 *
 *   1. System registers (SCTLR_EL1, TCR_EL1, MAIR_EL1, MDSCR_EL1)
 *      Snapshot at init, periodic re-verification. Detects disabling
 *      of WXN, MMU, caches, or debug enable.
 *
 *   2. Exception vector table (VBAR_EL1)
 *      Verify the vector table base hasn't been redirected.
 *
 *   3. Hardware debug registers (DBGBCR/DBGBVR 0-15, DBGWCR/DBGWVR 0-15)
 *      Detect active hardware breakpoints/watchpoints targeting game code.
 *      ARM64 supports up to 16 breakpoints + 16 watchpoints (vs x86's 4).
 *
 *   4. PAC keys (APIAKeyHi/Lo_EL1)
 *      On ARMv8.3+ with PAC, verify instruction A-key hasn't been
 *      substituted. Key rotation would invalidate all signed pointers.
 *
 * All checks run on a delayed workqueue at configurable intervals
 * (default: every 5 seconds). Results are emitted as events to the
 * ring buffer for the daemon to consume.
 *
 * Build guard: entire file is compiled only on CONFIG_ARM64.
 */

#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/delay.h>

#include "owlbear_common.h"
#include "owlbear_arm64.h"

#ifdef CONFIG_ARM64

#include <asm/sysreg.h>
#include <asm/cpufeature.h>

/* -------------------------------------------------------------------------
 * Configuration
 * ----------------------------------------------------------------------- */

#define OWL_CHECK_INTERVAL_MS  5000  /* Check every 5 seconds */

/* -------------------------------------------------------------------------
 * State
 * ----------------------------------------------------------------------- */

static struct owl_sysreg_snapshot baseline;
static bool                      pac_supported;
static struct delayed_work        hw_check_work;
static bool                      work_initialized;

/* -------------------------------------------------------------------------
 * System register reading
 * ----------------------------------------------------------------------- */

static void read_sysregs(struct owl_sysreg_snapshot *snap)
{
	snap->sctlr_el1 = read_sysreg(sctlr_el1);
	snap->tcr_el1   = read_sysreg(tcr_el1);
	snap->mair_el1  = read_sysreg(mair_el1);
	snap->mdscr_el1 = read_sysreg(mdscr_el1);
	snap->vbar_el1  = read_sysreg(vbar_el1);
}

/*
 * Note: PAC key value comparison is intentionally omitted. PAC keys are
 * per-process (each task gets unique keys via the kernel's key management),
 * so reading them from a workqueue context returns the kworker's keys,
 * not the game's. Comparing those values is meaningless and produces
 * false positives every check interval. We only verify that PAC is
 * globally enabled via SCTLR_EL1.EnIA.
 */

/* -------------------------------------------------------------------------
 * System register verification
 * ----------------------------------------------------------------------- */

static void emit_sysreg_event(u32 event_type, u32 reg_id,
			      u64 expected, u64 actual,
			      const char *desc)
{
	struct owlbear_event event = {};

	event.event_type = event_type;
	event.severity = OWL_SEV_CRITICAL;
	event.pid = 0;
	event.target_pid = owl_get_target_pid();
	strscpy(event.comm, "owlbear", sizeof(event.comm));
	event.payload.arm64.expected = expected;
	event.payload.arm64.actual = actual;
	event.payload.arm64.register_id = reg_id;
	strscpy(event.payload.arm64.description, desc,
		sizeof(event.payload.arm64.description));

	owl_emit_event_full(&event);
}

static void check_sysregs(void)
{
	struct owl_sysreg_snapshot now;

	read_sysregs(&now);

	/* SCTLR_EL1: MMU, caches must remain enabled */
	if ((now.sctlr_el1 & OWL_SCTLR_EXPECTED_SET) !=
	    (baseline.sctlr_el1 & OWL_SCTLR_EXPECTED_SET)) {
		emit_sysreg_event(OWL_EVENT_SYSREG_TAMPER,
				  OWL_REG_SCTLR_EL1,
				  baseline.sctlr_el1, now.sctlr_el1,
				  "SCTLR_EL1 critical bits changed");
	}

	/* WXN specifically — if cleared, W+X pages become possible */
	if ((baseline.sctlr_el1 & OWL_SCTLR_WXN) &&
	    !(now.sctlr_el1 & OWL_SCTLR_WXN)) {
		emit_sysreg_event(OWL_EVENT_WXN_DISABLED,
				  OWL_REG_SCTLR_EL1,
				  baseline.sctlr_el1, now.sctlr_el1,
				  "WXN disabled: W+X pages possible");
	}

	/* VBAR_EL1: exception vector table must not move */
	if (now.vbar_el1 != baseline.vbar_el1) {
		emit_sysreg_event(OWL_EVENT_VBAR_MODIFIED,
				  OWL_REG_VBAR_EL1,
				  baseline.vbar_el1, now.vbar_el1,
				  "VBAR_EL1 redirected");
	}

	/* MDSCR_EL1: kernel debug should not be enabled unexpectedly */
	if (!(baseline.mdscr_el1 & OWL_MDSCR_KDE) &&
	    (now.mdscr_el1 & OWL_MDSCR_KDE)) {
		emit_sysreg_event(OWL_EVENT_SYSREG_TAMPER,
				  OWL_REG_MDSCR_EL1,
				  baseline.mdscr_el1, now.mdscr_el1,
				  "Kernel debug enabled");
	}

	/* TCR_EL1 and MAIR_EL1: translation config should not change */
	if (now.tcr_el1 != baseline.tcr_el1) {
		emit_sysreg_event(OWL_EVENT_SYSREG_TAMPER,
				  OWL_REG_TCR_EL1,
				  baseline.tcr_el1, now.tcr_el1,
				  "TCR_EL1 changed");
	}

	if (now.mair_el1 != baseline.mair_el1) {
		emit_sysreg_event(OWL_EVENT_SYSREG_TAMPER,
				  OWL_REG_MAIR_EL1,
				  baseline.mair_el1, now.mair_el1,
				  "MAIR_EL1 changed");
	}
}

/* -------------------------------------------------------------------------
 * Hardware debug register monitoring
 *
 * ARM64 supports up to 16 HW breakpoints (DBGBCR/DBGBVR) and 16 HW
 * watchpoints (DBGWCR/DBGWVR). We read them via MRS and check the
 * enable bit. Any active breakpoint/watchpoint is reported.
 *
 * Reading debug registers requires macro expansion because the
 * register index is encoded in the instruction, not a runtime value.
 * ----------------------------------------------------------------------- */

#define READ_DBGBCR(n) ({ u64 __v; asm volatile("mrs %0, dbgbcr" #n "_el1" : "=r"(__v)); __v; })
#define READ_DBGBVR(n) ({ u64 __v; asm volatile("mrs %0, dbgbvr" #n "_el1" : "=r"(__v)); __v; })
#define READ_DBGWCR(n) ({ u64 __v; asm volatile("mrs %0, dbgwcr" #n "_el1" : "=r"(__v)); __v; })
#define READ_DBGWVR(n) ({ u64 __v; asm volatile("mrs %0, dbgwvr" #n "_el1" : "=r"(__v)); __v; })

/*
 * Check a single breakpoint register pair. Macro because the register
 * index must be a compile-time constant for the MRS instruction.
 */
#define CHECK_BRP(n) do {                                              \
	u64 bcr = READ_DBGBCR(n);                                     \
	if (bcr & OWL_DBGBCR_E) {                                     \
		u64 bvr = READ_DBGBVR(n);                             \
		emit_sysreg_event(OWL_EVENT_DEBUG_REG_ACTIVE,          \
				  OWL_REG_DBGBCR_BASE + (n),           \
				  0, bvr,                              \
				  "HW breakpoint active");             \
		found++;                                               \
	}                                                              \
} while (0)

#define CHECK_WRP(n) do {                                              \
	u64 wcr = READ_DBGWCR(n);                                     \
	if (wcr & OWL_DBGWCR_E) {                                     \
		u64 wvr = READ_DBGWVR(n);                             \
		emit_sysreg_event(OWL_EVENT_DEBUG_REG_ACTIVE,          \
				  OWL_REG_DBGWCR_BASE + (n),           \
				  0, wvr,                              \
				  "HW watchpoint active");             \
		found++;                                               \
	}                                                              \
} while (0)

static void check_debug_registers(void)
{
	int found = 0;

	/*
	 * We check the first 6 breakpoint and 4 watchpoint registers.
	 * Most ARM64 implementations provide 6 BRPs and 4 WRPs.
	 * The actual count can be read from ID_AA64DFR0_EL1 but
	 * accessing more than available traps, so we stay conservative.
	 */
	CHECK_BRP(0);
	CHECK_BRP(1);
	CHECK_BRP(2);
	CHECK_BRP(3);
	CHECK_BRP(4);
	CHECK_BRP(5);

	CHECK_WRP(0);
	CHECK_WRP(1);
	CHECK_WRP(2);
	CHECK_WRP(3);

	if (found > 0)
		pr_warn("owlbear: %d active debug registers detected\n", found);
}

/* -------------------------------------------------------------------------
 * PAC key verification
 * ----------------------------------------------------------------------- */

static void check_pac_keys(void)
{
#ifdef CONFIG_ARM64_PTR_AUTH
	u64 sctlr;

	if (!pac_supported)
		return;

	/*
	 * Only check SCTLR_EL1.EnIA — is PAC globally enabled?
	 * Key value comparison is not meaningful from workqueue context
	 * because PAC keys are per-process. See comment above.
	 */
	sctlr = read_sysreg(sctlr_el1);
	if (!(sctlr & OWL_SCTLR_EnIA)) {
		emit_sysreg_event(OWL_EVENT_PAC_KEY_CHANGED,
				  OWL_REG_SCTLR_EL1,
				  OWL_SCTLR_EnIA, 0,
				  "PAC EnIA disabled in SCTLR");
	}
#endif
}

/* -------------------------------------------------------------------------
 * Periodic check workqueue handler
 * ----------------------------------------------------------------------- */

static void hw_check_handler(struct work_struct *work)
{
	if (!owl.initialized)
		return;

	check_sysregs();
	check_debug_registers();
	check_pac_keys();

	/* Re-schedule if module is still running */
	if (owl.initialized)
		schedule_delayed_work(&hw_check_work,
				      msecs_to_jiffies(OWL_CHECK_INTERVAL_MS));
}

/* -------------------------------------------------------------------------
 * Subsystem init/exit
 * ----------------------------------------------------------------------- */

int owl_arm64_init(void)
{
	/* Take baseline snapshot of system registers */
	read_sysregs(&baseline);

	pr_info("owlbear: ARM64 baseline: SCTLR=0x%llx TCR=0x%llx "
		"MAIR=0x%llx VBAR=0x%llx MDSCR=0x%llx\n",
		baseline.sctlr_el1, baseline.tcr_el1,
		baseline.mair_el1, baseline.vbar_el1,
		baseline.mdscr_el1);

	/* Check PAC support (SCTLR_EL1.EnIA monitoring only) */
#ifdef CONFIG_ARM64_PTR_AUTH
	pac_supported = system_supports_address_auth();
	if (pac_supported)
		pr_info("owlbear: PAC supported, monitoring EnIA bit\n");
	else
		pr_info("owlbear: PAC not supported on this CPU\n");
#else
	pac_supported = false;
	pr_info("owlbear: PAC support not compiled in\n");
#endif

	/* Start periodic hardware checks */
	INIT_DELAYED_WORK(&hw_check_work, hw_check_handler);
	work_initialized = true;
	schedule_delayed_work(&hw_check_work,
			      msecs_to_jiffies(OWL_CHECK_INTERVAL_MS));

	pr_info("owlbear: ARM64 hardware checks active "
		"(interval=%dms, PAC=%s)\n",
		OWL_CHECK_INTERVAL_MS,
		pac_supported ? "yes" : "no");

	return 0;
}

void owl_arm64_exit(void)
{
	if (work_initialized) {
		cancel_delayed_work_sync(&hw_check_work);
		work_initialized = false;
	}

	pr_info("owlbear: ARM64 hardware checks stopped\n");
}

#else /* !CONFIG_ARM64 */

/*
 * Stub for non-ARM64 builds (cross-compilation testing on x86).
 * The module loads but ARM64 checks are no-ops.
 */

int owl_arm64_init(void)
{
	pr_info("owlbear: ARM64 checks disabled (not ARM64)\n");
	return 0;
}

void owl_arm64_exit(void)
{
}

#endif /* CONFIG_ARM64 */
