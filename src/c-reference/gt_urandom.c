// SPDX-License-Identifier: GPL-2.0-only
/*
 * gt_urandom: game-theoretic entropy-source policy for a hostile hypervisor.
 *
 * Threat model (see top-level CLAUDE.md): a hypervisor/emulator that fully
 * controls RDRAND output, the virtio-rng backend, and guest-visible timing
 * can, on old kernels, force /dev/urandom to return attacker-chosen bytes.
 * This module does not try to out-clever a hypervisor that controls every
 * guest-visible input -- that is information-theoretically impossible and
 * is explicitly out of scope. Instead it:
 *
 *   1. Runs simple online health tests on RDRAND and on the live hwrng
 *      (virtio-rng) output, and reports what it finds via debugfs. A
 *      cheap/lazy backdoor (e.g. a hypervisor pointing virtio-rng at a
 *      constant file) fails even this trivial test.
 *   2. By policy, trusts neither RDRAND nor virtio-rng for initial seeding
 *      regardless of what the health test says -- a competent attacker's
 *      RDRAND stream can look statistically fine (that is the whole point
 *      of the deterministic-PRNG demo in scripts/launch-attack.sh) while
 *      still being entirely known to the attacker in advance. Detection is
 *      a bonus signal, not the safety mechanism.
 *   3. Reads a seed blob injected at VM launch via QEMU fw_cfg
 *      (opt/seed), the one channel outside the hypervisor's attack
 *      surface in this threat model (modeling a provisioning/attestation
 *      system), and mixes it into the kernel CRNG with full entropy
 *      credit via add_hwgenerator_randomness().
 *
 * All findings are exposed under /sys/kernel/debug/gt_urandom/ for the
 * demo script to show side by side with the (un)fixed boot.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/debugfs.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/random.h>
#include <linux/uaccess.h>

#ifdef CONFIG_X86
#include <asm/archrandom.h>
#endif

#define GT_FWCFG_SEED_PATH "/sys/firmware/qemu_fw_cfg/by_name/opt/seed/raw"
#define GT_HWRNG_PATH      "/dev/hwrng"
#define GT_RDRAND_SAMPLES  16
#define GT_RDRAND_MIN_CHANGE 10   /* kernel's own x86_init_rdrand uses 5/8 */
#define GT_HWRNG_SAMPLE_LEN 64
#define GT_HWRNG_DEGENERATE_FRAC 80 /* % of bytes equal to byte[0] -> fail */
#define GT_SEED_MAX_LEN 512
#define GT_RDRAND_REPORT_LEN 1536

static struct dentry *gt_dir;

/* ---- formatted report buffers, one per source, shown via debugfs ---- */
static char *rdrand_report;
static char *virtio_report;
static char *seed_report;
static char *summary_report;

static ssize_t gt_read_str(struct file *f, char __user *buf, size_t len,
			    loff_t *ppos)
{
	const char *s = f->f_inode->i_private;

	if (!s)
		return 0;
	return simple_read_from_buffer(buf, len, ppos, s, strlen(s));
}

static const struct file_operations gt_fops = {
	.owner = THIS_MODULE,
	.read  = gt_read_str,
	.llseek = default_llseek,
};

static void gt_add_file(const char *name, char *contents)
{
	struct dentry *d = debugfs_create_file(name, 0444, gt_dir, NULL,
						&gt_fops);
	if (!IS_ERR(d))
		d_inode(d)->i_private = contents;
}

/* Read up to max_len bytes from a kernel-visible file (sysfs/devtmpfs). */
static ssize_t gt_read_file(const char *path, void *buf, size_t max_len,
			     int flags)
{
	struct file *f;
	ssize_t ret;

	f = filp_open(path, O_RDONLY | flags, 0);
	if (IS_ERR(f))
		return PTR_ERR(f);

	ret = kernel_read(f, buf, max_len, NULL);
	filp_close(f, NULL);
	return ret;
}

#define GT_HWRNG_TMP_PATH "/tmp/.gt_hwrng_sample"

/*
 * /dev/hwrng (hw_random core) only implements the legacy f_op->read, not
 * ->read_iter -- kernel_read() on a modern kernel requires ->read_iter and
 * returns -EINVAL otherwise (see fs/read_write.c:__kernel_read()). There is
 * no in-kernel consumer API for "the currently active hwrng" either
 * (hw_random/core.c only exports register/unregister for providers). So:
 * shell out to dd(1) to copy a live sample into a tmpfs file (tmpfs's
 * read_iter works fine with kernel_read), then read that back. This is a
 * one-shot boot-time health check, not a hot path.
 */
static ssize_t gt_read_hwrng(void *buf, size_t max_len)
{
	char count_arg[32];
	char *argv[] = {
		"/bin/busybox", "dd",
		"if=" GT_HWRNG_PATH,
		"of=" GT_HWRNG_TMP_PATH,
		"bs=1", count_arg, NULL,
	};
	char *envp[] = { "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
	struct file *f;
	ssize_t ret;
	int rc;

	scnprintf(count_arg, sizeof(count_arg), "count=%zu", max_len);

	rc = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
	if (rc)
		return -EIO;

	f = filp_open(GT_HWRNG_TMP_PATH, O_RDONLY, 0);
	if (IS_ERR(f))
		return PTR_ERR(f);
	ret = kernel_read(f, buf, max_len, NULL);
	filp_close(f, NULL);
	/* Leave the tmpfs scratch file -- it's in a disposable boot's tmpfs
	 * and gone at shutdown; not worth the extra unlink plumbing here. */
	return ret;
}

/*
 * RDRAND health test: same idea as arch/x86/kernel/cpu/rdrand.c's own
 * boot-time check -- sample repeatedly and verify the values actually
 * change. This catches a lazy/broken fake (constant output); it will NOT
 * catch a competent attacker-controlled PRNG stream, which is exactly why
 * step 2 of the module's policy ignores the result and distrusts RDRAND
 * unconditionally.
 */
static void gt_test_rdrand(void)
{
	char *p = rdrand_report;
	size_t off = 0;
	int i, changed = 0;
	bool have_rdrand = boot_cpu_has(X86_FEATURE_RDRAND);
	unsigned long sample = 0, prev = 0;
	bool ok = false, any_fail = false;

	off += scnprintf(p + off, GT_RDRAND_REPORT_LEN - off,
			  "available: %s\n", have_rdrand ? "yes" : "no");

	if (have_rdrand) {
		for (i = 0; i < GT_RDRAND_SAMPLES; i++) {
			ok = rdrand_long(&sample);
			if (!ok) {
				any_fail = true;
				break;
			}
			if (i)
				changed += (sample != prev);
			prev = sample;
			off += scnprintf(p + off, GT_RDRAND_REPORT_LEN - off,
					  "sample[%2d]: 0x%016lx\n", i, sample);
		}
	}

	off += scnprintf(p + off, GT_RDRAND_REPORT_LEN - off,
		"health_test: %s (changed=%d/%d, cpu_fail=%s)\n",
		(have_rdrand && !any_fail && changed >= GT_RDRAND_MIN_CHANGE)
			? "PASS (looks varied)" : "FAIL (degenerate/unavailable)",
		changed, GT_RDRAND_SAMPLES - 1, any_fail ? "yes" : "no");
	off += scnprintf(p + off, GT_RDRAND_REPORT_LEN - off,
		"policy: UNTRUSTED (0 entropy credit) -- health test passing\n"
		"        does not imply the stream is unknown to a\n"
		"        hypervisor that controls RDRAND; see module header.\n");
}

/*
 * virtio-rng (hwrng) health test: read a live sample from /dev/hwrng and
 * flag the degenerate case a lazy backdoor actually produces (a fixed
 * byte/file backend). Policy still never trusts it, same reasoning as
 * RDRAND above.
 */
static void gt_test_virtio(void)
{
	char *p = virtio_report;
	size_t off = 0;
	u8 buf[GT_HWRNG_SAMPLE_LEN];
	ssize_t n;
	int i, same_as_first = 0;

	n = gt_read_hwrng(buf, sizeof(buf));

	if (n <= 0) {
		off += scnprintf(p + off, GT_SEED_MAX_LEN - off,
			"available: no (open/read of %s failed: %zd)\n",
			GT_HWRNG_PATH, n);
		off += scnprintf(p + off, GT_SEED_MAX_LEN - off,
			"policy: UNTRUSTED (0 entropy credit)\n");
		return;
	}

	for (i = 0; i < n; i++)
		if (buf[i] == buf[0])
			same_as_first++;

	off += scnprintf(p + off, GT_SEED_MAX_LEN - off,
			  "available: yes (%zd bytes sampled from %s)\n",
			  n, GT_HWRNG_PATH);
	off += scnprintf(p + off, GT_SEED_MAX_LEN - off,
			  "first_bytes: %02x %02x %02x %02x %02x %02x %02x %02x ...\n",
			  buf[0], buf[1 % n], buf[2 % n], buf[3 % n],
			  buf[4 % n], buf[5 % n], buf[6 % n], buf[7 % n]);
	off += scnprintf(p + off, GT_SEED_MAX_LEN - off,
			  "health_test: %s (%d%% of bytes == first byte)\n",
			  (same_as_first * 100 / (int)n >= GT_HWRNG_DEGENERATE_FRAC)
				  ? "FAIL (degenerate: looks like a fixed backend)"
				  : "PASS (byte distribution looks varied)",
			  same_as_first * 100 / (int)n);
	off += scnprintf(p + off, GT_SEED_MAX_LEN - off,
			  "policy: UNTRUSTED (0 entropy credit) regardless of\n"
			  "        health_test result -- see module header.\n");
}

/*
 * The one input outside the simulated hypervisor's reach: a seed blob
 * injected at VM launch via QEMU fw_cfg (opt/seed), modeling a
 * provisioning/attestation channel. Mixed in with full entropy credit.
 */
static void gt_load_seed(void)
{
	char *p = seed_report;
	size_t off = 0;
	u8 *buf;
	ssize_t n;

	buf = kmalloc(GT_SEED_MAX_LEN, GFP_KERNEL);
	if (!buf) {
		off += scnprintf(p + off, GT_SEED_MAX_LEN - off,
				  "status: ERROR (no memory)\n");
		return;
	}

	n = gt_read_file(GT_FWCFG_SEED_PATH, buf, GT_SEED_MAX_LEN, O_NONBLOCK);

	if (n <= 0) {
		off += scnprintf(p + off, GT_SEED_MAX_LEN - off,
			"status: DEGRADED -- fw_cfg seed (%s) not present (%zd)\n"
			"        No trusted channel available. Per the stated\n"
			"        hard limit, a fully hostile+deterministic\n"
			"        hypervisor cannot be defeated without one.\n",
			GT_FWCFG_SEED_PATH, n);
		goto out;
	}

	add_hwgenerator_randomness(buf, n, n * 8, false);

	off += scnprintf(p + off, GT_SEED_MAX_LEN - off,
		"status: OK -- read %zd bytes from %s\n"
		"policy: TRUSTED -- mixed into CRNG with full credit (%zd bits)\n"
		"        via add_hwgenerator_randomness(). This is the only\n"
		"        source this module credits by default.\n",
		n, GT_FWCFG_SEED_PATH, n * 8);

out:
	kfree(buf);
}

static int __init gt_urandom_init(void)
{
	rdrand_report  = kzalloc(GT_RDRAND_REPORT_LEN, GFP_KERNEL);
	virtio_report  = kzalloc(GT_SEED_MAX_LEN, GFP_KERNEL);
	seed_report    = kzalloc(GT_SEED_MAX_LEN, GFP_KERNEL);
	summary_report = kzalloc(GT_SEED_MAX_LEN, GFP_KERNEL);
	if (!rdrand_report || !virtio_report || !seed_report || !summary_report) {
		kfree(rdrand_report);
		kfree(virtio_report);
		kfree(seed_report);
		kfree(summary_report);
		return -ENOMEM;
	}

	gt_dir = debugfs_create_dir("gt_urandom", NULL);
	if (IS_ERR(gt_dir)) {
		pr_warn("gt_urandom: debugfs unavailable, continuing without telemetry\n");
		gt_dir = NULL;
	}

	gt_test_rdrand();
	gt_test_virtio();
	gt_load_seed();

	scnprintf(summary_report, GT_SEED_MAX_LEN,
		  "gt_urandom loaded: RDRAND=untrusted virtio-rng=untrusted "
		  "fw_cfg-seed=trusted-fallback\n"
		  "see rdrand, virtio_rng, seed files in this directory for detail\n");

	if (gt_dir) {
		gt_add_file("rdrand", rdrand_report);
		gt_add_file("virtio_rng", virtio_report);
		gt_add_file("seed", seed_report);
		gt_add_file("summary", summary_report);
	}

	pr_info("gt_urandom: loaded. %s", summary_report);
	return 0;
}

static void __exit gt_urandom_exit(void)
{
	debugfs_remove_recursive(gt_dir);
	kfree(rdrand_report);
	kfree(virtio_report);
	kfree(seed_report);
	kfree(summary_report);
}

module_init(gt_urandom_init);
module_exit(gt_urandom_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("game-theory-urandom");
MODULE_DESCRIPTION("Game-theoretic entropy-source trust policy against a hostile hypervisor");
