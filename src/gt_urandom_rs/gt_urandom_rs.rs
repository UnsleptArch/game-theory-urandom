// SPDX-License-Identifier: GPL-2.0-only
//! gt_urandom_rs: game-theoretic entropy-source trust policy, in Rust.
//!
//! See top-level CLAUDE.md for the full threat model. This module treats
//! "which entropy sources to trust, and how much" as a genuine two-layer
//! game against a hypervisor that can cheaply poison RDRAND, virtio-rng,
//! and guest-visible timing, with one channel (a QEMU fw_cfg `opt/seed`
//! blob) outside its reach:
//!
//!   Layer 1 -- adaptive belief tracking (multi-round, sequential Bayes).
//!   Every *tested* source (RDRAND, virtio-rng, the fw_cfg seed) runs
//!   several independent rounds of its health test. After each round the
//!   module updates a posterior corruption probability via Bayes' rule,
//!   not a single static formula -- so a source whose behavior changes
//!   partway through (the adversarial model this layer captures: an
//!   attacker whose apparent behavior isn't assumed constant) gets its
//!   belief revised in real time, round by round. Each source's evidence
//!   likelihoods are parameterized by its own cost to fake: for a cheap
//!   source, "passing" a round is only weakly informative (a competent
//!   attacker's fake looks fine almost as often as the real thing), so
//!   repeated passes barely move its belief; for a source that would be
//!   expensive to fake, the same evidence is far more informative. One
//!   source -- guest-visible timing -- gets NO live test: see
//!   `TIMING_NOTE` below for why (measured, not assumed).
//!
//!   Layer 2 -- equilibrium credit allocation (proportional contest).
//!   Once every source has a final posterior belief, a minimax safety
//!   filter first drops any source whose belief is still at or above
//!   `SAFETY_THRESHOLD_PPM` to zero, full stop, regardless of anything
//!   else. Among the sources that survive that filter, entropy credit is
//!   split in proportion to cost-to-fake -- the Nash equilibrium of a
//!   proportional (Tullock-style) contest in which the attacker's budget
//!   is spent most efficiently against the cheapest surviving target: the
//!   defender's equilibrium response is to weight credit by exactly how
//!   expensive each surviving source would be to have faked. With this
//!   project's declared costs, only the fw_cfg seed ever survives layer 1,
//!   so in practice it gets a 100% share -- but the mechanism is general:
//!   two surviving costly sources would split credit between them.
//!
//! All arithmetic is fixed-point, parts-per-million (0..=1_000_000) -- no
//! floats in kernel code. Every number behind every decision is exposed
//! live under debugfs, not just the resulting policy.

use kernel::c_str;
use kernel::debugfs::{Dir, File};
use kernel::debugfs::Writer;
use kernel::prelude::*;
use kernel::str::CString;

/// Wraps a [`CString`] report so it's shown in debugfs as plain text.
/// `debugfs::Writer` auto-implements via `Debug` for any `T: Debug`, which
/// would quote and `\n`-escape a multi-line report; this newtype opts out
/// of that blanket impl (it doesn't derive `Debug`) and writes the raw
/// string instead.
struct Report(CString);

impl Writer for Report {
    fn write(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0.to_str().unwrap_or("<invalid utf8>"))
    }
}

/// `CString` has no `Default` (it's a fallible heap allocation), so
/// `Result::unwrap_or_default()` isn't available on `Result<CString, _>`;
/// every such call below falls back to this instead. Treating this
/// literal's own allocation failure as fatal (truly OOM) is as reasonable
/// here as anywhere else in a boot-time health-check module.
fn error_cstring() -> CString {
    CString::try_from_fmt(fmt!("<error: allocation failed>"))
        .expect("tiny literal CString allocation should not fail")
}

/// Appends `b` to `a`, falling back to `error_cstring()` on allocation
/// failure. Every multi-line report in this module is built by repeated
/// calls to this (small reports, boot-time only -- not a hot path, so the
/// O(n^2) rebuild-on-append is an acceptable trade for simplicity here).
fn append(a: &CString, b: &CString) -> CString {
    CString::try_from_fmt(fmt!("{}{}", a.to_str().unwrap_or(""), b.to_str().unwrap_or("")))
        .unwrap_or_else(|_| error_cstring())
}

module! {
    type: GtUrandomRs,
    name: "gt_urandom_rs",
    authors: ["game-theory-urandom"],
    description: "Game-theoretic entropy-source trust policy against a hostile hypervisor (Rust)",
    license: "GPL",
}

// ==== fixed-point scoring (parts per million, 0..=1_000_000) ====

const PPM_SCALE: u32 = 1_000_000;

/// Displays a ppm value as a percentage with 2 decimal digits, e.g.
/// `Pct(475_000)` -> "47.50%". (1% = 10_000ppm.)
struct Pct(u32);
impl core::fmt::Display for Pct {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{:02}%", self.0 / 10_000, (self.0 % 10_000) / 100)
    }
}

// Cost-to-fake inputs are measured from this repo's own artifacts at
// *build* time, not hand-typed here -- kernel-module-rust/build.sh counts
// the actual added-line diff of qemu-patch/0001-rdrand-poison.patch
// (32 lines as of this writing) and confirms virtio-rng/timing need zero
// QEMU source changes (both are documented, stock CLI flags in
// scripts/launch-attack.sh), writing the results to this generated,
// gitignored file, included verbatim below. If that patch's size
// changes, these values -- and this module's build -- change with it,
// instead of a hand-typed number silently going stale.
include!("cost_measurements.generated.rs");

/// Verified-safe boundary for the cheap, in-process cost tier (see
/// `cost_from_measured_patch_lines` below). `prior_corrupt_ppm`'s
/// `1/(1+cost)` curve is steep enough that even cost=2 (prior 33.33%)
/// already drops a source's belief to 29.77% after `RDRAND_ROUNDS=4`
/// all-pass rounds -- under `SAFETY_THRESHOLD_PPM` -- where cost=1
/// correctly stays at 45.88% (both hand-computed and confirmed against
/// the live formula). So every measured line count under this limit maps
/// to the same verified-safe cost=1; at or above it, this module has not
/// verified what cost/threshold/round-count combination stays safe, and
/// refuses to guess -- see the `assert!` below. 100 lines is comfortably
/// above the real measured value (32) and comfortably below "a serious
/// engineering project": a conservative, round boundary, not a precise
/// one.
const CHEAP_TIER_PATCH_LINE_LIMIT: u32 = 100;
const COST_INPROCESS_CHEAP: u32 = 1;

/// Maps a measured patch-line count into this module's verified-safe
/// cost scale. Deliberately refuses (via a *build-time* panic, since this
/// runs in a `const` context) to silently produce a cost for a line count
/// this module's safety derivation has never been checked against --
/// better a build failure than an unverified trust decision reaching a
/// live kernel.
const fn cost_from_measured_patch_lines(lines: u32) -> u32 {
    assert!(
        lines < CHEAP_TIER_PATCH_LINE_LIMIT,
        "a source's fake now needs more lines of patch than this module's \
         cheap-tier safety derivation has been checked against -- \
         SAFETY_THRESHOLD_PPM and the round counts need re-deriving for \
         this cost before it's safe to assign one automatically (see \
         CHEAP_TIER_PATCH_LINE_LIMIT's doc comment)",
    );
    COST_INPROCESS_CHEAP
}

const COST_RDRAND: u32 = cost_from_measured_patch_lines(MEASURED_RDRAND_PATCH_LINES);
const COST_VIRTIO_RNG: u32 = cost_from_measured_patch_lines(MEASURED_VIRTIO_RNG_PATCH_LINES);
const COST_TIMING: u32 = cost_from_measured_patch_lines(MEASURED_TIMING_PATCH_LINES);

/// The fw_cfg seed sits in a different category entirely, not a bigger
/// number on the same scale: no finite amount of change to the
/// attacker's own QEMU process can produce it, because its value is
/// chosen and injected by a provisioning/attestation step that runs
/// before and outside the process this threat model grants the attacker
/// control over (see CLAUDE.md). This can't be "measured" the way the
/// in-process costs above are -- there's no patch to count lines of --
/// so it's derived instead, as an explicit multiple of the base
/// in-process cost rather than an independent magic number: if
/// `COST_INPROCESS_CHEAP` ever changes, this moves with it automatically.
/// The multiplier's magnitude doesn't matter precisely -- any value this
/// large or larger yields the same policy outcome -- only that it's
/// large enough to make `prior_corrupt_ppm` round to ~0%.
const OUT_OF_PROCESS_COST_MULTIPLIER: u32 = 10_000;
const COST_FWCFG_SEED: u32 = COST_INPROCESS_CHEAP * OUT_OF_PROCESS_COST_MULTIPLIER;

/// Round-evidence likelihoods (ppm), keyed by whether the source is cheap
/// to fake. `(pass | corrupt, pass | honest)`. For a cheap source these
/// are close together -- passing barely distinguishes honest from
/// competently-faked, which is the whole point (a splitmix64 stream, see
/// qemu-patch/, passes a naive variance test just fine while being
/// entirely attacker-known). For a source that would be hard to fake
/// well, failing is far more damning and passing is far more informative.
const CHEAP_L_PASS_GIVEN_CORRUPT_PPM: u64 = 950_000; // 95%
const CHEAP_L_PASS_GIVEN_HONEST_PPM: u64 = 990_000; // 99%
const COSTLY_L_PASS_GIVEN_CORRUPT_PPM: u64 = 50_000; // 5%
const COSTLY_L_PASS_GIVEN_HONEST_PPM: u64 = 990_000; // 99%

/// Minimax safety threshold: a source whose final posterior corruption
/// belief is still at or above this is credited zero entropy, full stop,
/// regardless of its cost or how well it did in testing.
///
/// Not arbitrary -- it must hold even in the *worst case for the
/// defender*: a cost=1 source (prior 500_000ppm = 50%) that passes every
/// round of its health test. Simulating RDRAND_ROUNDS=4 consecutive
/// passes through `bayes_update_ppm` with the cheap-source likelihoods
/// above: 500_000 -> 489_691 -> 479_489 -> 469_268 -> 459_042ppm. That is
/// the lowest a cost=1 source's belief can ever get with this many
/// rounds; the threshold sits below it with comfortable margin. An
/// earlier, simpler version of this scoring (a single static formula
/// instead of multi-round Bayes, with a looser threshold) was caught via
/// a live boot actually *crediting* RDRAND -- exactly the failure this
/// module exists to prevent. Don't lower this threshold without
/// re-running that simulation for the current round counts.
const SAFETY_THRESHOLD_PPM: u32 = 400_000; // 40%

/// Prior corruption probability (ppm) from cost-to-fake: cheap -> high
/// prior. `1_000_000 / (1 + cost)`. `const fn` so it can also run at
/// compile time, in the safety proof below.
const fn prior_corrupt_ppm(cost: u32) -> u32 {
    PPM_SCALE / (1 + cost)
}

/// One sequential Bayes update from one round's pass/fail evidence.
/// `const fn` so it can also run at compile time, in the safety proof
/// below -- the exact same update logic that runs at boot, not a
/// hand-reimplemented copy of it, is what gets proven safe.
const fn bayes_update_ppm(prior_ppm: u32, passed: bool, cheap: bool) -> u32 {
    let (l_pass_corrupt, l_pass_honest) = if cheap {
        (CHEAP_L_PASS_GIVEN_CORRUPT_PPM, CHEAP_L_PASS_GIVEN_HONEST_PPM)
    } else {
        (COSTLY_L_PASS_GIVEN_CORRUPT_PPM, COSTLY_L_PASS_GIVEN_HONEST_PPM)
    };
    let scale = PPM_SCALE as u64;
    let (l_corrupt, l_honest) = if passed {
        (l_pass_corrupt, l_pass_honest)
    } else {
        (scale - l_pass_corrupt, scale - l_pass_honest)
    };
    let prior = prior_ppm as u64;
    let num = prior * l_corrupt;
    let den = num + (scale - prior) * l_honest;
    if den == 0 {
        return prior_ppm;
    }
    ((num * scale) / den) as u32
}

/// Runs `rounds` independent rounds of a source's health test, updating
/// its belief sequentially after each one (the "adaptive opponent model":
/// belief tracks the evidence round by round rather than being computed
/// once from a single batch). `round_fn(i)` runs round `i` and returns
/// whether it passed, appending whatever it wants to `detail` as it goes
/// (e.g. raw samples); this function appends the round number, verdict,
/// and running belief after each round.
///
/// Every round is also pushed straight to the kernel log via `pr_info!`,
/// not just into the debugfs report this function also builds. debugfs
/// only shows what it's asked to show, after the fact, by whoever cats
/// it; dmesg/the serial console shows this live, interleaved with the
/// rest of boot, without anyone needing to know to go looking for it --
/// that's the actual point of "verbose and transparent" for a module
/// whose whole job is a trust decision nobody should have to take on
/// faith.
fn run_rounds<F: FnMut(usize, &mut CString) -> bool>(
    name: &str,
    cost: u32,
    cheap: bool,
    rounds: usize,
    mut round_fn: F,
) -> (u32, CString) {
    let mut belief = prior_corrupt_ppm(cost);
    pr_info!(
        "{}: starting health test, cost_to_fake={} prior_corrupt={}\n",
        name,
        cost,
        Pct(belief)
    );
    let mut detail = CString::try_from_fmt(fmt!(
        "cost_to_fake={} prior_corrupt={}\n",
        cost,
        Pct(belief)
    ))
    .unwrap_or_else(|_| error_cstring());
    for i in 0..rounds {
        let passed = round_fn(i, &mut detail);
        belief = bayes_update_ppm(belief, passed, cheap);
        pr_info!(
            "{}: round {}/{}: {} -> belief_corrupt={}\n",
            name,
            i + 1,
            rounds,
            if passed { "pass" } else { "FAIL" },
            Pct(belief),
        );
        let line = CString::try_from_fmt(fmt!(
            "  round {}/{}: {} -> belief_corrupt={}\n",
            i + 1,
            rounds,
            if passed { "pass" } else { "FAIL" },
            Pct(belief),
        ))
        .unwrap_or_else(|_| error_cstring());
        detail = append(&detail, &line);
    }
    (belief, detail)
}

struct SourceScore {
    name: &'static str,
    cost: u32,
    final_belief_ppm: u32,
    /// Filled in by `compute_equilibrium` once every source's belief is
    /// known; zero until then.
    equilibrium_weight_ppm: u32,
}

/// Layer 2: among sources whose belief cleared the safety filter, split
/// credit proportional to cost-to-fake -- the equilibrium of a
/// proportional contest game over the surviving sources. Sources that
/// didn't clear the filter get exactly zero, independent of this split.
fn compute_equilibrium(scores: &mut [SourceScore]) {
    let mut survivor_cost_total: u64 = 0;
    let mut survivor_count: usize = 0;
    for s in scores.iter() {
        if s.final_belief_ppm < SAFETY_THRESHOLD_PPM {
            survivor_cost_total += s.cost as u64;
            survivor_count += 1;
        }
    }
    // Each survivor's share is floored independently, so a naive split
    // can leave a few ppm unallocated whenever more than one source
    // survives (never over-allocated -- the safe direction -- but not
    // exactly the 100% a proportional contest's equilibrium calls for
    // either). The last survivor visited absorbs whatever's left instead
    // of also being floored, so the weights always sum to exactly
    // PPM_SCALE when there's at least one survivor, matching this
    // function's own doc comment that the split is a real N-way
    // proportional contest, not just correct for the single-survivor
    // case this project's current costs happen to produce.
    let mut allocated: u32 = 0;
    let mut seen: usize = 0;
    for s in scores.iter_mut() {
        s.equilibrium_weight_ppm = if s.final_belief_ppm < SAFETY_THRESHOLD_PPM
            && survivor_cost_total > 0
        {
            seen += 1;
            if seen == survivor_count {
                PPM_SCALE - allocated
            } else {
                let w = ((s.cost as u64) * (PPM_SCALE as u64) / survivor_cost_total) as u32;
                allocated += w;
                w
            }
        } else {
            0
        };
    }
}

fn decision_line(s: &SourceScore) -> CString {
    CString::try_from_fmt(fmt!(
        "{}: cost_to_fake={} final_belief_corrupt={} equilibrium_weight={} decision={}\n",
        s.name,
        s.cost,
        Pct(s.final_belief_ppm),
        Pct(s.equilibrium_weight_ppm),
        if s.equilibrium_weight_ppm > 0 {
            "TRUSTED"
        } else {
            "UNTRUSTED (0 entropy credit)"
        },
    ))
    .unwrap_or_else(|_| error_cstring())
}

// ==== RDRAND: multi-round variance test (x86_64 inline asm; same idea as
// the kernel's own arch/x86/kernel/cpu/rdrand.c boot-time self-test, just
// run as several independent rounds instead of one batch) ====

#[cfg(target_arch = "x86_64")]
fn rdrand_u64() -> Option<u64> {
    let mut val: u64;
    let mut ok: u8;
    // SAFETY: RDRAND is unconditionally available on the cpu model used by
    // this project's QEMU launch scripts (`-cpu qemu64,+rdrand`); no memory
    // effects, no inputs.
    unsafe {
        core::arch::asm!(
            "rdrand {val}",
            "setc {ok}",
            val = out(reg) val,
            ok = out(reg_byte) ok,
            options(nostack, nomem),
        );
    }
    if ok != 0 { Some(val) } else { None }
}

const RDRAND_ROUNDS: usize = 4;
const RDRAND_SAMPLES_PER_ROUND: usize = 4;
const RDRAND_MIN_CHANGE_PER_ROUND: usize = 2;

fn rdrand_round(i: usize, detail: &mut CString) -> bool {
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = i;
        let line = CString::try_from_fmt(fmt!("    (non-x86_64, no RDRAND)\n"))
            .unwrap_or_else(|_| error_cstring());
        *detail = append(detail, &line);
        return false;
    }
    #[cfg(target_arch = "x86_64")]
    {
        let mut prev: u64 = 0;
        let mut changed = 0usize;
        let mut any_fail = false;
        for j in 0..RDRAND_SAMPLES_PER_ROUND {
            match rdrand_u64() {
                Some(v) => {
                    if j > 0 && v != prev {
                        changed += 1;
                    }
                    prev = v;
                    if let Ok(line) =
                        CString::try_from_fmt(fmt!("    sample: 0x{:016x}\n", v))
                    {
                        *detail = append(detail, &line);
                    }
                }
                None => {
                    any_fail = true;
                    break;
                }
            }
        }
        let _ = i;
        !any_fail && changed >= RDRAND_MIN_CHANGE_PER_ROUND
    }
}

// ==== raw filesystem/usermode-helper access: not yet wrapped safely in
// rust/kernel/fs for kernel-side reads of character devices, so these call
// the same bindgen-generated FFI the C reference module calls. See
// kernel-module/gt_urandom.c's gt_read_file()/gt_read_hwrng() for why
// kernel_read() needs ->read_iter (hw_random's misc device doesn't have
// one) and why the virtio-rng sample goes through a usermode dd into a
// tmpfs scratch file instead. ====

const O_RDONLY: i32 = 0;
const O_NONBLOCK: i32 = 0o4000;

/// # Safety
/// `path` must be a valid NUL-terminated C string for the duration of the
/// call.
unsafe fn read_file_raw(path: &CStr, flags: i32, buf: &mut [u8]) -> Result<usize> {
    // SAFETY: `path` is NUL-terminated per the caller contract; `flags`
    // selects O_RDONLY (+O_NONBLOCK), neither of which implies FMODE_WRITE.
    let f = unsafe {
        kernel::error::from_err_ptr(kernel::bindings::filp_open(path.as_char_ptr(), O_RDONLY | flags, 0))
    }?;
    // SAFETY: `f` is a valid, open `struct file *` just returned by
    // filp_open(); `buf` is a valid mutable slice for its length.
    let n = unsafe {
        kernel::bindings::kernel_read(f, buf.as_mut_ptr().cast(), buf.len(), core::ptr::null_mut())
    };
    // SAFETY: `f` is the same pointer filp_open() returned; not used again
    // after this call.
    unsafe {
        kernel::bindings::filp_close(f, core::ptr::null_mut());
    }
    if n < 0 {
        Err(Error::from_errno(n as i32))
    } else {
        Ok(n as usize)
    }
}

const HWRNG_TMP_PATH: &CStr = c_str!("/tmp/.gt_hwrng_sample_rs");

/// Shell out to `dd` to copy a live sample of /dev/hwrng into a tmpfs
/// scratch file (tmpfs supports ->read_iter, so kernel_read() can read it
/// back; the hw_random misc device does not -- see module doc above).
fn sample_hwrng(buf: &mut [u8]) -> Result<usize> {
    let count_arg = CString::try_from_fmt(fmt!("count={}", buf.len()))?;
    // Built from HWRNG_TMP_PATH, not a second hand-typed literal: the path
    // `dd` writes to and the path `read_file_raw` reads back from must be
    // the same string, and deriving one from the other is what actually
    // guarantees that instead of relying on two literals staying in sync.
    let of_arg = CString::try_from_fmt(fmt!("of={}", HWRNG_TMP_PATH.to_str().unwrap_or("")))?;
    let argv: [*const u8; 7] = [
        c_str!("/bin/busybox").as_char_ptr().cast(),
        c_str!("dd").as_char_ptr().cast(),
        c_str!("if=/dev/hwrng").as_char_ptr().cast(),
        of_arg.as_char_ptr().cast(),
        c_str!("bs=1").as_char_ptr().cast(),
        count_arg.as_char_ptr().cast(),
        core::ptr::null(),
    ];
    let envp: [*const u8; 2] = [
        c_str!("PATH=/sbin:/bin:/usr/sbin:/usr/bin").as_char_ptr().cast(),
        core::ptr::null(),
    ];
    // SAFETY: argv/envp are NUL-terminated arrays of NUL-terminated C
    // strings, valid for the duration of this (blocking, UMH_WAIT_PROC)
    // call; call_usermodehelper does not retain the pointers afterward.
    let rc = unsafe {
        kernel::bindings::call_usermodehelper(
            argv[0].cast(),
            argv.as_ptr() as *mut *mut u8,
            envp.as_ptr() as *mut *mut u8,
            kernel::bindings::UMH_WAIT_PROC as i32,
        )
    };
    if rc != 0 {
        return Err(EIO);
    }
    // SAFETY: HWRNG_TMP_PATH is a static NUL-terminated C string.
    unsafe { read_file_raw(HWRNG_TMP_PATH, 0, buf) }
}

const VIRTIO_ROUNDS: usize = 4;
const VIRTIO_BYTES_PER_ROUND: usize = 16;
const VIRTIO_DEGENERATE_PCT: u32 = 80;

// ==== compile-time safety proof ====
//
// SAFETY_THRESHOLD_PPM's doc comment above justifies 400_000ppm with a
// hand simulation of RDRAND_ROUNDS=4 consecutive passes. A hand
// simulation is only ever checked once, at the moment someone writes
// it -- if RDRAND_ROUNDS or VIRTIO_ROUNDS is ever changed later without
// also re-deriving the threshold, that comment goes stale silently and
// the module could start crediting a corrupted cheap source, which is
// the exact failure this module exists to prevent (and the exact bug a
// live boot once caught in an earlier version of this scoring). Rather
// than trust a comment to get re-checked by hand, this re-runs the
// *actual* `bayes_update_ppm` the module calls at boot, at compile time,
// for the worst case a cheap (cost=1) source can produce -- passing
// every single round -- for both of this module's cheap sources' real
// round counts, and refuses to build at all if either one no longer
// clears the threshold.
const fn worst_case_cheap_belief_after_passes(rounds: usize) -> u32 {
    let mut belief = prior_corrupt_ppm(COST_INPROCESS_CHEAP);
    let mut i = 0;
    while i < rounds {
        belief = bayes_update_ppm(belief, true, true);
        i += 1;
    }
    belief
}

const _: () = assert!(
    worst_case_cheap_belief_after_passes(RDRAND_ROUNDS) >= SAFETY_THRESHOLD_PPM,
    "SAFETY_THRESHOLD_PPM no longer has a safety margin for RDRAND_ROUNDS: \
     a cost=1 source that passes every round would end up credited. \
     Re-derive SAFETY_THRESHOLD_PPM (or RDRAND_ROUNDS) before shipping this.",
);
const _: () = assert!(
    worst_case_cheap_belief_after_passes(VIRTIO_ROUNDS) >= SAFETY_THRESHOLD_PPM,
    "SAFETY_THRESHOLD_PPM no longer has a safety margin for VIRTIO_ROUNDS: \
     a cost=1 source that passes every round would end up credited. \
     Re-derive SAFETY_THRESHOLD_PPM (or VIRTIO_ROUNDS) before shipping this.",
);

fn virtio_round(_i: usize, detail: &mut CString) -> bool {
    let mut buf = [0u8; VIRTIO_BYTES_PER_ROUND];
    match sample_hwrng(&mut buf) {
        Err(e) => {
            let line = CString::try_from_fmt(fmt!(
                "    open/read of /dev/hwrng failed: {:?}\n",
                e
            ))
            .unwrap_or_else(|_| error_cstring());
            *detail = append(detail, &line);
            false
        }
        Ok(n) if n == 0 => {
            let line = CString::try_from_fmt(fmt!("    0 bytes read\n"))
                .unwrap_or_else(|_| error_cstring());
            *detail = append(detail, &line);
            false
        }
        Ok(n) => {
            let same_as_first = buf[..n].iter().filter(|&&b| b == buf[0]).count();
            let pct = (same_as_first as u32) * 100 / (n as u32);
            let line = CString::try_from_fmt(fmt!(
                "    {} bytes, first=0x{:02x}, {}% == first byte\n",
                n, buf[0], pct,
            ))
            .unwrap_or_else(|_| error_cstring());
            *detail = append(detail, &line);
            pct < VIRTIO_DEGENERATE_PCT
        }
    }
}

// ==== the one input outside the simulated hypervisor's reach ====

const FWCFG_SEED_PATH: &CStr = c_str!("/sys/firmware/qemu_fw_cfg/by_name/opt/seed/raw");
const SEED_MAX_LEN: usize = 256;
const SEED_ROUNDS: usize = 1;
const SEED_DEGENERATE_PCT: u32 = 80;

/// The seed gets exactly one round: unlike RDRAND/virtio-rng, its trust
/// doesn't come from passing a test (nothing this module can test proves
/// a channel is outside the attacker's reach -- that's an assumption
/// baked into the threat model, not something measurable in-guest). This
/// round is a basic sanity check only (not degenerate bytes), run because
/// a module that claims to test every source shouldn't give any of them,
/// even the trusted one, a complete pass -- but its low final belief
/// comes overwhelmingly from `COST_FWCFG_SEED`'s prior, not from this.
fn seed_round(buf: &[u8]) -> (bool, CString) {
    if buf.is_empty() {
        return (
            false,
            CString::try_from_fmt(fmt!("    0 bytes, cannot sanity-check\n"))
                .unwrap_or_else(|_| error_cstring()),
        );
    }
    let n = buf.len();
    let same_as_first = buf.iter().filter(|&&b| b == buf[0]).count();
    let pct = (same_as_first as u32) * 100 / (n as u32);
    let line = CString::try_from_fmt(fmt!(
        "    {} bytes, first=0x{:02x}, {}% == first byte\n",
        n, buf[0], pct,
    ))
    .unwrap_or_else(|_| error_cstring());
    (pct < SEED_DEGENERATE_PCT, line)
}

/// Reads the fw_cfg seed and, if layer 2's equilibrium credits nonzero
/// weight to it, mixes it into the CRNG via add_hwgenerator_randomness()
/// (same exported GPL symbol the C reference module uses; not yet
/// wrapped safely in rust/kernel) scaled by that weight.
fn load_seed(score: &SourceScore) -> (usize, CString) {
    let mut buf = [0u8; SEED_MAX_LEN];
    let n = match unsafe { read_file_raw(FWCFG_SEED_PATH, O_NONBLOCK, &mut buf) } {
        Ok(n) if n > 0 => n,
        Ok(_) => {
            return (
                0,
                CString::try_from_fmt(fmt!(
                    "status: DEGRADED -- fw_cfg seed present but empty (0 bytes)\n"
                ))
                .unwrap_or_else(|_| error_cstring()),
            );
        }
        Err(e) => {
            return (
                0,
                CString::try_from_fmt(fmt!(
                    "status: DEGRADED -- fw_cfg seed not present ({:?}).\n\
                     No trusted channel available. Per the stated hard limit,\n\
                     a fully hostile+deterministic hypervisor cannot be\n\
                     defeated without one.\n",
                    e
                ))
                .unwrap_or_else(|_| error_cstring()),
            );
        }
    };

    if score.equilibrium_weight_ppm == 0 {
        return (
            n,
            CString::try_from_fmt(fmt!(
                "status: read {} bytes but the equilibrium allocation credited\n\
                 this source 0 weight (final_belief_corrupt={} >= threshold)\n",
                n,
                Pct(score.final_belief_ppm),
            ))
            .unwrap_or_else(|_| error_cstring()),
        );
    }

    let entropy_bits = n * 8 * (score.equilibrium_weight_ppm as usize) / (PPM_SCALE as usize);
    // SAFETY: `buf[..n]` is a valid, initialized byte slice for its
    // length; add_hwgenerator_randomness copies out of it synchronously
    // and does not retain the pointer.
    unsafe {
        kernel::bindings::add_hwgenerator_randomness(buf.as_ptr().cast(), n, entropy_bits, false);
    }

    (
        n,
        CString::try_from_fmt(fmt!(
            "status: OK -- read {} bytes from {}\n\
             credited {} bits ({} of {} bytes) via add_hwgenerator_randomness()\n\
             per this source's equilibrium weight below.\n",
            n,
            FWCFG_SEED_PATH.to_str().unwrap_or("?"),
            entropy_bits,
            Pct(score.equilibrium_weight_ppm),
            n,
        ))
        .unwrap_or_else(|_| error_cstring()),
    )
}

// `kernel::Module::init` returns a plain (unpinned) `Self` by value, which
// rules out making the top-level module struct itself `#[pin_data]` (its
// `File` fields must never move once debugfs has a pointer into them). So,
// same pattern as samples/rust/rust_debugfs_scoped.rs: a pinned `Inner`
// holds the actual debugfs entries behind `Pin<KBox<Inner>>`, and the
// top-level struct just owns that box. Built directly inline in
// Module::init() below (not via a separate helper function) because every
// value involved is owned, not borrowed -- a helper's elided `+ '_` return
// lifetime has nothing to tie to and fails to infer outside that context.
#[pin_data]
struct Inner {
    _debugfs: Dir,
    #[pin]
    _summary: File<Report>,
    #[pin]
    _rdrand: File<Report>,
    #[pin]
    _virtio_rng: File<Report>,
    #[pin]
    _timing: File<Report>,
    #[pin]
    _seed: File<Report>,
    #[pin]
    _policy: File<Report>,
}

struct GtUrandomRs {
    _inner: Pin<KBox<Inner>>,
}

impl kernel::Module for GtUrandomRs {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        // This project's launch scripts boot with `quiet` on the kernel
        // cmdline, which raises console_loglevel enough to suppress even
        // pr_warn! from ever reaching the serial console (it still lands
        // in the dmesg ring buffer, just not live on screen) -- silently
        // defeating the entire point of logging a poisoned-source
        // detection as it happens. console_verbose() is the kernel's own
        // API for exactly this (used by, e.g., the OOM killer and panic
        // paths to force their output through regardless of the console's
        // configured level): it only raises console_loglevel globally for
        // the rest of this boot, no arguments, no preconditions, nothing
        // module-specific to get wrong.
        //
        // SAFETY: console_verbose() takes no arguments and has no
        // preconditions; it only writes the global console_loglevel.
        unsafe {
            kernel::bindings::console_verbose();
        }
        pr_info!("loading\n");

        // ---- layer 1: multi-round adaptive belief tracking, per source ----

        let (rdrand_belief, rdrand_report) =
            run_rounds("RDRAND", COST_RDRAND, true, RDRAND_ROUNDS, rdrand_round);
        let (virtio_belief, virtio_report) =
            run_rounds("virtio-rng", COST_VIRTIO_RNG, true, VIRTIO_ROUNDS, virtio_round);

        // The seed gets its own small round loop too (SEED_ROUNDS=1 -- see
        // seed_round()'s doc comment for why just one), fed through the
        // same run_rounds() machinery as everything else rather than a
        // special-cased bypass. The actual bytes are read once up front
        // (sampling it twice would mean two independent fw_cfg reads for
        // what is, each boot, a single fixed blob -- the second read would
        // just re-confirm the first, so the round count reflects that it's
        // one real observation, not an attempt to inflate confidence).
        let mut seed_buf = [0u8; SEED_MAX_LEN];
        let seed_n = unsafe { read_file_raw(FWCFG_SEED_PATH, O_NONBLOCK, &mut seed_buf) }
            .unwrap_or(0);
        let (seed_belief, seed_rounds_report) = run_rounds(
            "fw_cfg-seed",
            COST_FWCFG_SEED,
            false,
            SEED_ROUNDS,
            |_i, detail| {
                let (passed, line) = seed_round(&seed_buf[..seed_n]);
                *detail = append(detail, &line);
                passed
            },
        );

        // TIMING_NOTE: guest-visible timing (the third poisoned channel in
        // this project's threat model, alongside RDRAND and virtio-rng) is
        // deliberately NOT given a live health test here. We built and ran
        // one: an RDTSC-based tight-loop jitter measurement, calibrated
        // against both this project's `-icount` attack config and plain
        // TCG execution. The hoped-for signal (icount-controlled timing
        // being detectably more regular than real hardware jitter) did not
        // hold up reliably across workload sizes in that calibration --
        // both configurations showed comparable regularity, just via
        // different mechanisms (icount-batch quantization vs. a quiet
        // kernel loop with no competing scheduler noise). Rather than ship
        // a health test whose pass/fail could flip based on environment
        // noise, this source is scored with NO health test at all: its
        // belief is simply its cost-derived prior, assumed worst case,
        // never reduced. It is still fully "played" in the layer-2
        // equilibrium below -- it has a cost, a belief, and a shot at
        // credit -- it just never gets the chance a passing test would
        // otherwise give it.
        let timing_belief = prior_corrupt_ppm(COST_TIMING);
        pr_info!(
            "timing: no live health test (see TIMING_NOTE in module \
             source), scored at its worst-case cost-derived prior belief_corrupt={}\n",
            Pct(timing_belief),
        );
        let timing_report = CString::try_from_fmt(fmt!(
            "cost_to_fake={} prior_corrupt={} (== final belief: no live\n\
             health test for this source -- see TIMING_NOTE in module source)\n",
            COST_TIMING,
            Pct(timing_belief),
        ))
        .unwrap_or_else(|_| error_cstring());

        // ---- layer 2: equilibrium credit allocation among survivors ----

        let mut scores = [
            SourceScore { name: "RDRAND", cost: COST_RDRAND, final_belief_ppm: rdrand_belief, equilibrium_weight_ppm: 0 },
            SourceScore { name: "virtio-rng", cost: COST_VIRTIO_RNG, final_belief_ppm: virtio_belief, equilibrium_weight_ppm: 0 },
            SourceScore { name: "timing", cost: COST_TIMING, final_belief_ppm: timing_belief, equilibrium_weight_ppm: 0 },
            SourceScore { name: "fw_cfg-seed", cost: COST_FWCFG_SEED, final_belief_ppm: seed_belief, equilibrium_weight_ppm: 0 },
        ];
        compute_equilibrium(&mut scores);

        // Final, loud, one-line-per-source verdict straight to the kernel
        // log, on top of everything run_rounds() already logged live
        // above. pr_warn! (not pr_info!) for anything untrusted, so a
        // detected or assumed poisoned source actually stands out in
        // dmesg/the serial console instead of scrolling past at the same
        // level as routine boot noise. Wording is deliberately different
        // per source rather than one generic templated line: RDRAND and
        // virtio-rng ran a real multi-round test and crossed the safety
        // threshold, which is a detection; timing never got a test at
        // all, which is an assumption, not a detection, and this module
        // doesn't get to claim otherwise in its own log.
        if scores[0].equilibrium_weight_ppm == 0 {
            pr_warn!(
                "POISONED SOURCE DETECTED: RDRAND tested over {} rounds, \
                 final belief_corrupt={} >= safety threshold {} -- distrusted, \
                 0 entropy credit\n",
                RDRAND_ROUNDS, Pct(scores[0].final_belief_ppm), Pct(SAFETY_THRESHOLD_PPM),
            );
        } else {
            pr_info!(
                "RDRAND: final belief_corrupt={} -- TRUSTED, \
                 equilibrium_weight={}\n",
                Pct(scores[0].final_belief_ppm), Pct(scores[0].equilibrium_weight_ppm),
            );
        }
        if scores[1].equilibrium_weight_ppm == 0 {
            pr_warn!(
                "POISONED SOURCE DETECTED: virtio-rng tested over {} rounds, \
                 final belief_corrupt={} >= safety threshold {} -- distrusted, \
                 0 entropy credit\n",
                VIRTIO_ROUNDS, Pct(scores[1].final_belief_ppm), Pct(SAFETY_THRESHOLD_PPM),
            );
        } else {
            pr_info!(
                "virtio-rng: final belief_corrupt={} -- TRUSTED, \
                 equilibrium_weight={}\n",
                Pct(scores[1].final_belief_ppm), Pct(scores[1].equilibrium_weight_ppm),
            );
        }
        if scores[2].equilibrium_weight_ppm == 0 {
            pr_warn!(
                "timing distrusted by default: no live test ran, \
                 worst-case prior belief_corrupt={} >= safety threshold {} -- \
                 0 entropy credit\n",
                Pct(scores[2].final_belief_ppm), Pct(SAFETY_THRESHOLD_PPM),
            );
        } else {
            pr_info!(
                "timing: final belief_corrupt={} -- TRUSTED, \
                 equilibrium_weight={}\n",
                Pct(scores[2].final_belief_ppm), Pct(scores[2].equilibrium_weight_ppm),
            );
        }
        // fw_cfg-seed's verdict can't be logged from equilibrium_weight_ppm
        // alone, unlike the other three sources: the layer-1 belief here
        // comes almost entirely from this source's huge cost-derived
        // prior, not from the one weak sanity-check round, so "the fw_cfg
        // blob is completely absent" and "it's present and looks fine"
        // both land at a belief near 0% and both clear the safety filter
        // as "TRUSTED". That's fine for the belief math, credit is still
        // correctly withheld because load_seed() independently checks for
        // an actual non-empty read before ever calling
        // add_hwgenerator_randomness() -- but it means this verdict has
        // to wait for load_seed()'s real result instead of running off
        // the equilibrium weight like the other three, or it can claim
        // this boot was seeded from a channel that was never actually
        // there. (Caught exactly this way: a live boot with no fw_cfg
        // device configured at all still showed TRUSTED/100% here when
        // this check ran before load_seed(), while load_seed() itself
        // correctly reported 0 bytes read and nothing credited.)
        let (seed_bytes_read, seed_status) = load_seed(&scores[3]);
        if scores[3].equilibrium_weight_ppm > 0 && seed_bytes_read > 0 {
            pr_info!(
                "fw_cfg-seed: final belief_corrupt={} -- TRUSTED, \
                 equilibrium_weight={}, this is the channel the CRNG actually gets \
                 seeded from this boot ({} bytes credited)\n",
                Pct(scores[3].final_belief_ppm), Pct(scores[3].equilibrium_weight_ppm),
                seed_bytes_read,
            );
        } else if scores[3].equilibrium_weight_ppm > 0 {
            pr_warn!(
                "fw_cfg-seed: belief_corrupt={} cleared the safety filter, but the \
                 channel itself read 0 bytes this boot (missing or empty) -- NO entropy \
                 was actually credited from any source. Per the stated hard limit, a \
                 fully hostile hypervisor cannot be defeated without a working trusted \
                 channel, and this boot didn't have one\n",
                Pct(scores[3].final_belief_ppm),
            );
        } else {
            pr_warn!(
                "fw_cfg-seed: final belief_corrupt={} >= safety threshold \
                 {} -- UNTRUSTED. No source cleared the safety filter this boot; the CRNG \
                 is getting 0 bits of credited entropy from this module\n",
                Pct(scores[3].final_belief_ppm), Pct(SAFETY_THRESHOLD_PPM),
            );
        }

        let seed_report = append(&seed_rounds_report, &seed_status);

        let mut policy_report = CString::try_from_fmt(fmt!(
            "cost-to-fake, measured at build time from this repo's own artifacts\n\
             (kernel-module-rust/build.sh; see cost_measurements.generated.rs):\n\
             RDRAND patch: {} added lines (cheap-tier limit: {})\n\
             virtio-rng patch: {} added lines  timing patch: {} added lines\n\
             fw_cfg-seed: not measurable this way (out-of-process category, see source)\n\n\
             safety threshold {} proven at compile time, not hand-verified in a\n\
             comment: a cost=1 source that passes every round still can't clear it,\n\
             re-checked against this build's actual round counts (RDRAND={}, virtio-rng={})\n\n\
             layer 1 (adaptive multi-round belief) -> layer 2 (equilibrium credit split):\n",
            MEASURED_RDRAND_PATCH_LINES,
            CHEAP_TIER_PATCH_LINE_LIMIT,
            MEASURED_VIRTIO_RNG_PATCH_LINES,
            MEASURED_TIMING_PATCH_LINES,
            Pct(SAFETY_THRESHOLD_PPM),
            RDRAND_ROUNDS,
            VIRTIO_ROUNDS,
        ))
        .unwrap_or_else(|_| error_cstring());
        for s in &scores {
            policy_report = append(&policy_report, &decision_line(s));
        }

        let summary = CString::try_from_fmt(fmt!(
            "gt_urandom_rs loaded: RDRAND={} virtio-rng={} timing={} fw_cfg-seed={}\n\
             see rdrand, virtio_rng, timing, seed, policy files in this directory\n",
            if scores[0].equilibrium_weight_ppm > 0 { "trusted" } else { "untrusted" },
            if scores[1].equilibrium_weight_ppm > 0 { "trusted" } else { "untrusted" },
            if scores[2].equilibrium_weight_ppm > 0 { "trusted" } else { "untrusted" },
            // Same reasoning as the verdict log above: "trusted" here has
            // to mean bytes were actually credited, not just that the
            // belief math cleared the safety filter, or this one-line
            // summary (the first thing anyone glances at) would claim
            // success on a boot that credited nothing.
            if scores[3].equilibrium_weight_ppm > 0 && seed_bytes_read > 0 { "trusted" } else { "untrusted" },
        ))
        .unwrap_or_else(|_| error_cstring());

        pr_info!("{}\n", summary.to_str().unwrap_or("?"));

        let debugfs = Dir::new(c_str!("gt_urandom_rs"));
        let summary = Report(summary);
        let rdrand_report = Report(rdrand_report);
        let virtio_report = Report(virtio_report);
        let timing_report = Report(timing_report);
        let seed_report = Report(seed_report);
        let policy_report = Report(policy_report);
        let inner = KBox::try_pin_init(
            try_pin_init!(Inner {
                _summary <- debugfs.read_only_file(c_str!("summary"), summary),
                _rdrand <- debugfs.read_only_file(c_str!("rdrand"), rdrand_report),
                _virtio_rng <- debugfs.read_only_file(c_str!("virtio_rng"), virtio_report),
                _timing <- debugfs.read_only_file(c_str!("timing"), timing_report),
                _seed <- debugfs.read_only_file(c_str!("seed"), seed_report),
                _policy <- debugfs.read_only_file(c_str!("policy"), policy_report),
                _debugfs: debugfs,
            }),
            GFP_KERNEL,
        )?;

        Ok(Self { _inner: inner })
    }
}
