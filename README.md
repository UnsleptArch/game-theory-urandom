# game-theory-urandom

A defensive kernel module that treats "which entropy sources to trust, and
how much" as a game-theoretic policy decision, plus a proof-of-concept
that demonstrates the problem it solves.

Inspired by Taylor Hornby's "Prototyping an RDRAND Backdoor in Bochs"
(PoC||GTFO 3:6): a
hypervisor that controls a guest's RDRAND output can, on old kernels
(<3.13), force `/dev/urandom` to return attacker-chosen bytes. Modern
Linux no longer lets one source dominate like that, so this project
targets the modern version of the same problem: a hypervisor that
poisons *every* source it can cheaply reach at once (RDRAND, virtio-rng,
and guest-visible timing via `-icount`), not just RDRAND alone.

## The attack

A 32-line QEMU patch replaces RDRAND's output with a deterministic
stream chosen by the attacker, the virtio-rng backend is pointed at a
fixed file, and `-icount` makes the guest's entire sense of time a
function of instruction count. With all three poisoned and the kernel
module **not** loaded, the resulting SSH host key is identical on every
boot, known before the guest ever finishes booting.

## The fix

`src/gt_urandom_rs/` is a Rust kernel module that scores every entropy
source through multi-round sequential Bayesian inference (does this
source's output look honest, re-checked round by round) and allocates
entropy credit via a minimax safety filter plus a proportional
equilibrium over each source's cost-to-fake, measured from this repo's
own QEMU patch at build time, not asserted by hand. With the module
loaded and a trusted seed injected through QEMU's `fw_cfg` (the one
channel outside the simulated hypervisor's reach), the same poisoned
inputs produce a different, unpredictable key on every boot.

The safety threshold behind that decision isn't just hand-derived, it's
checked by the Rust compiler at build time: a dedicated `const fn` proof
re-runs the module's own belief-update function against the worst case
and refuses to compile if the threshold doesn't hold.

The module also logs its reasoning live, not just into debugfs after the
fact: every round's pass/fail and running belief goes to the kernel log as
it happens, and each source gets a final verdict line once the policy
resolves, `pr_warn!` (so it stands out in dmesg) for anything untrusted,
worded per-source rather than one generic template (e.g. RDRAND/virtio-rng
get "POISONED SOURCE DETECTED" when a live test actually catches them).

## Layout

- `src/gt_urandom_rs/` — the Rust kernel module (the one the demo loads).
- `src/c-reference/` — an earlier C implementation, kept for reference.
- `toolage/qemu-patch/` — the RDRAND poisoning patch.
- `toolage/guest/` — guest rootfs and init overlays for the disposable QEMU VM.
- `toolage/scripts/` — build, launch, and demo scripts.

## Running it

```
toolage/scripts/launch-attack.sh     # module not loaded: same key every boot
toolage/scripts/launch-fix.sh        # module loaded: different key every boot
toolage/scripts/demo.sh              # both, plus the module's own telemetry
```

See each script's header comment for details, and the module's own
`/sys/kernel/debug/gt_urandom_rs/` files (or the kernel log, once loaded)
for the live belief-tracking and policy decisions behind each run.

## Non-goals

This does not defeat a fully omniscient hypervisor that controls
*every* guest-visible input, there is no entropy left to extract from a
fully deterministic process with no outside input. That's information
theory, not an engineering gap. The one channel this project relies on
being safe is the `fw_cfg`-injected seed, modeling a provisioning step
outside the runtime hypervisor's reach.
