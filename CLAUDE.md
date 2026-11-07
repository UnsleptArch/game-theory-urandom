# game-theory-urandom

Hackathon project (make UC, security track). Defensive kernel module that
treats "which entropy sources to trust, and how much" as a game-theoretic
policy decision, plus a PoC that demonstrates the problem it solves.

## Premise

Inspired by Taylor Hornby's "Prototyping an RDRAND Backdoor in Bochs"
(PoC||GTFO 3:6): a hypervisor/emulator that controls a guest's RDRAND output
can, on old kernels (<3.13), cancel out the kernel's other entropy sources and
force `/dev/urandom` to return attacker-chosen bytes. Modern Linux (post-2013
mitigation, and the 5.17/5.18 `random.c` rewrite) no longer lets one source
dominate like that — so the PoC and the module both target the **modern**
version of this problem: a hypervisor that poisons *every* source it can
cheaply reach at once (RDRAND, virtio-rng, guest-visible timing), not just
RDRAND alone.

## Threat model (agreed, do not relitigate without reason)

- Attacker = the hypervisor/emulator. It fully controls RDRAND output,
  the virtio-rng backend, and — via QEMU `-icount` — the guest's view of time
  (RDTSC, interrupt timing, scheduling jitter), making the whole guest
  execution deterministic.
- **Hard limit, stated explicitly and not to be papered over:** if literally
  every guest-visible input is deterministic and attacker-controlled, there
  is zero entropy in the system. No module, game-theoretic or otherwise, can
  derive true randomness from a fully deterministic process with no outside
  input. This is information theory, not an engineering gap.
- Resolution: the defender gets exactly **one** input the simulated
  hypervisor cannot reach — a seed blob injected at VM launch via QEMU
  `fw_cfg` (`opt/seed`), modeling a real trust boundary (a provisioning/
  attestation system separate from the runtime hypervisor). The module's job
  is to detect that RDRAND/virtio-rng/timing are degenerate and fall back to
  that seed rather than ever trusting the poisoned sources by default.
- We are NOT building offensive tooling. No code here performs an attack
  against a real machine; everything runs only inside disposable QEMU guests
  built for this demo, on an isolated/no-bridge network.

## Two demo configurations, same guest image

**Attack config** (module NOT loaded):
- RDRAND → patched in QEMU's TCG software emulation to return a fixed value
  (same category of move as Hornby's Bochs hook, applied to QEMU instead).
- virtio-rng → backend pointed at a fixed/predictable file instead of host
  `/dev/urandom` (`-object rng-random,filename=...`), no QEMU patch needed.
- Timing → `-icount` makes RDTSC/interrupt/scheduling timing a deterministic
  function of instruction count instead of real wall-clock noise.
- Result: SSH host key (or any key generated at boot) is **the same every
  run** — a provable, repeatable "break," not a one-off.

**Fix config** (module loaded, identical guest image, same QEMU flags):
- Module runs online health tests on RDRAND and virtio-rng output at boot,
  detects degenerate/repeating output, zeroes their entropy credit.
- Falls back to the `fw_cfg`-injected seed (the one channel outside the
  attack surface above), mixes it in properly, blocks key generation until
  it has something trustworthy.
- Result: key becomes unpredictable to anyone who only controls RDRAND /
  virtio-rng / timing.

If health tests alone aren't conclusive enough live, the module may also use
simple game-theoretic source weighting (favor sources costly for a
hypervisor to fake) — but the headline mechanism for the demo is detection +
fail-safe-to-trusted-seed, not a claim that beats total determinism.

## Build plan / status

- [x] Guest kernel: mainline 6.18.62 (LTS), built at `build/linux-src`
      (defconfig + kvm_guest.config + virtio-pci/virtio-rng/devtmpfs/
      ext4/debugfs/fw_cfg-sysfs/modules enabled, module signing off).
      bzImage at `build/linux-src/arch/x86/boot/bzImage`.
- [x] Guest rootfs: Alpine minirootfs tree at `guest/rootfs` (already
      present), packed with `guest/overlay/init` (a custom init script,
      not Alpine's OpenRC) via `scripts/build-initramfs.sh` into
      `build/initramfs.cpio.gz`. Note: `guest/rootfs/bin/bbsuid`-backed
      busybox applets (mount, several others) are unreadable by this user
      and excluded from the packed image; the init script calls
      `/bin/busybox <applet>` directly instead of relying on those
      symlinks.
- [x] QEMU RDRAND patch: `qemu-patch/0001-rdrand-poison.patch`, applied to
      `build/qemu-src` (QEMU 11.1.2, Arch/CachyOS source package), built
      at `build/qemu-src/build-out/qemu-system-x86_64`. `GT_POISON_RDRAND`
      (hex u64) seeds a deterministic splitmix64 stream returned by the
      TCG `rdrand`/`rdseed` helper -- a flat constant was tried first and
      rejected, since the guest kernel's own RDRAND boot self-test
      (arch/x86/kernel/cpu/rdrand.c) disables RDRAND outright when every
      sample is identical, which would defeat the attack demo.
- [x] fw_cfg seed plumbing: `-fw_cfg name=opt/seed,file=...` plus guest
      kernel's built-in `qemu_fw_cfg` driver exposes it at
      `/sys/firmware/qemu_fw_cfg/by_name/opt/seed/raw`; confirmed readable
      from guest userspace and from the kernel module.
- [x] Kernel module (`kernel-module/gt_urandom.c`): online health tests on
      RDRAND (repeated-sample variance check, mirrors the kernel's own
      test) and on live virtio-rng output (reads `/dev/hwrng` via a
      `call_usermodehelper()`-run `dd` into a tmpfs scratch file, since
      `hw_random`'s misc device only implements the legacy `f_op->read`
      and `kernel_read()` requires `->read_iter` on this kernel). Policy:
      RDRAND and virtio-rng are *always* untrusted (0 entropy credit)
      regardless of health-test result -- a competent attacker's RDRAND
      stream can look statistically fine, so detection is a bonus signal,
      not the safety mechanism. The fw_cfg seed is the only source
      credited, via `add_hwgenerator_randomness()` with full credit.
      Telemetry under `/sys/kernel/debug/gt_urandom/{summary,rdrand,
      virtio_rng,seed}`. Builds clean against `build/linux-src`.
- [x] Launch scripts: `scripts/launch-attack.sh`, `scripts/launch-fix.sh`.
      Module loaded only in the fix path via `gt=1` on the kernel cmdline,
      read by `guest/overlay/init`. Note: plain QEMU `-icount` does *not*
      give bit-identical execution across separate live boots (idle/HLT
      timing isn't fully pinned to instruction count outside record/
      replay -- see `build/qemu-src/docs/devel/tcg-icount.rst`); confirmed
      this empirically (diverging keys even with RDRAND/virtio-rng/NIC/RTC
      all pinned). `launch-attack.sh` therefore records the
      attacker-controlled run once (`-icount rr=record`) and replays that
      exact trace for each requested boot (`-icount rr=replay`) -- each
      replay still fully re-executes the guest, so "same attacker inputs
      -> same key" remains a faithful demonstration, not a cached result.
      `launch-fix.sh` does NOT need rr (it's demonstrating
      unpredictability, not reproducibility) and gives each boot a fresh
      random fw_cfg seed, modeling independent per-VM provisioning.
- [x] Demo script: `scripts/demo.sh [N]` boots attack config N times
      (expect identical key -- confirmed), fix config N times (expect
      different keys -- confirmed), and dumps the module's debugfs
      telemetry from one fix-config boot. All three parts verified
      working end-to-end as of 2026-11-07.

## Environment notes (checked, don't re-check unless something changes)

- Host: CachyOS, kernel 7.2.8-2-cachyos, kernel headers present at
  `/lib/modules/$(uname -r)/build` — **irrelevant to the guest module**,
  which builds against the guest kernel's own build tree, not the host's.
- QEMU: `qemu-system-x86_64` 11.1.2, from Arch package `qemu-system-x86`.
- No Buildroot, no docker/podman installed. Network access confirmed working.
- 16 cores, 61G RAM, 1.5T free disk — not a constraint for this build.

## Non-goals (explicitly out of scope, don't drift into these)

- Defeating a fully omniscient hypervisor (see hard limit above).
- VM snapshot/clone-based entropy reuse (considered, explicitly dropped in
  favor of the source-poisoning approach above).
- Any attack tooling usable outside this project's disposable QEMU guests.
- KVM/VMX hardware-acceleration-level RDRAND interception (would need a host
  kernel/KVM patch) — using QEMU TCG software emulation instead, which is
  sufficient and far less fragile to build under time pressure.
