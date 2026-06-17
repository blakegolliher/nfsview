/*
 * nfsview eBPF latency probes.
 *
 * Pairs NFS-client-layer enter/exit tracepoints to measure per-op latency
 * in log2-ns buckets. Userspace folds the histograms into MountDerived.bpf
 * alongside the existing /proc-derived counters; this code never replaces
 * the /proc path.
 *
 * Two probe families:
 *
 *  1. Async paged I/O (raw_tracepoint, hdr/cdata-pointer keyed).
 *       nfs_initiate_read   / nfs_readpage_done    -> OP_READ
 *       nfs_initiate_write  / nfs_writeback_done   -> OP_WRITE
 *       nfs_initiate_commit / nfs_commit_done      -> OP_COMMIT
 *     The init probe walks `(hdr|cdata) -> inode -> i_sb -> s_dev` via CO-RE
 *     to tag the in-flight entry with the originating mount's super_block
 *     device id. The done probe copies that id into the histogram key.
 *     In-flight key: pointer (stable across init/done since it's the same
 *     pgio/commit object).
 *
 *  2. Sync metadata ops (formatted tracepoint, pid+op keyed).
 *       nfs_<op>_enter / nfs_<op>_exit -> OP_<OP>
 *     Each event payload carries dev_t directly; no inode walk needed.
 *     A given task can't have two in-flight instances of the same sync op,
 *     so (pid_tgid << 16 | op_id) is a unique key.
 *
 * Histogram key: (dev, op_id, log2(latency_ns)). Userspace deltas the
 * counts each tick (snapshot-and-diff), no map reset.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "nfs_lat.bpf.h"

char LICENSE[] SEC("license") = "GPL";

/*
 * Minimal CO-RE struct stubs. libbpf relocates the field offsets against
 * the running kernel's BTF at load time — we never assume a layout.
 * Listing only the fields we read keeps this header free of vmlinux.h
 * bloat and the bpftool runtime dep that would come with generating it.
 */
struct super_block {
	__u32 s_dev;
} __attribute__((preserve_access_index));

struct inode {
	struct super_block *i_sb;
} __attribute__((preserve_access_index));

struct nfs_pgio_header {
	struct inode *inode;
} __attribute__((preserve_access_index));

struct nfs_commit_data {
	struct inode *inode;
} __attribute__((preserve_access_index));

/*
 * Per-tracepoint event-arg stubs for the sync-op probes. Each NFS
 * tracepoint expands to its own kernel struct (e.g.
 * `struct trace_event_raw_nfs_getattr_enter`), and they don't share a
 * common header layout — `_with_flags` events insert an
 * `unsigned long flags` before `dev`, the rest don't. Declaring each by
 * its real BTF name and tagging with preserve_access_index lets libbpf
 * locate `dev` by field name regardless of where it actually sits in
 * the running kernel's struct.
 */
#define NFS_ENTER_STRUCT(event) \
	struct trace_event_raw_##event { __u32 dev; } __attribute__((preserve_access_index))

NFS_ENTER_STRUCT(nfs_getattr_enter);
NFS_ENTER_STRUCT(nfs_setattr_enter);
NFS_ENTER_STRUCT(nfs_lookup_enter);
NFS_ENTER_STRUCT(nfs_access_enter);
NFS_ENTER_STRUCT(nfs_create_enter);
NFS_ENTER_STRUCT(nfs_remove_enter);
NFS_ENTER_STRUCT(nfs_rename_enter);
NFS_ENTER_STRUCT(nfs_link_enter);
NFS_ENTER_STRUCT(nfs_symlink_enter);
NFS_ENTER_STRUCT(nfs_mkdir_enter);
NFS_ENTER_STRUCT(nfs_rmdir_enter);
NFS_ENTER_STRUCT(nfs_mknod_enter);
NFS_ENTER_STRUCT(nfs_fsync_enter);
NFS_ENTER_STRUCT(nfs_atomic_open_enter);

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct hist_key);
	__type(value, __u64);
} hist SEC(".maps");

/* In-flight bookkeeping for async paged I/O. Key: hdr/cdata pointer. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct inflight_val);
} inflight_ptr SEC(".maps");

/* In-flight bookkeeping for sync metadata ops. Key: (pid_tgid << 16 | op_id).
 * Sized smaller than inflight_ptr because sync calls are short-lived and
 * one task can have at most NFS_OP_MAX entries in flight. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct inflight_val);
} inflight_pid SEC(".maps");

/* floor(log2(ns)) capped at 63; returns 0 for ns < 2.
 *
 * Unrolled bit-narrowing rather than `63 - __builtin_clzll(ns)`: the BPF
 * target has no count-leading-zeros instruction, and LLVM's BPF backend
 * (through at least clang 18) aborts lowering the CTLZ expansion with
 * "fatal error: unimplemented opcode" under the default -mcpu. The shift
 * sequence below is fully branch-unrolled, verifier-friendly, and the u64
 * exponent never exceeds 63 so the result is inherently capped. */
static __always_inline __u16 log2_bucket(__u64 ns)
{
	__u16 b = 0;
	if (ns >= (1ULL << 32)) { ns >>= 32; b += 32; }
	if (ns >= (1ULL << 16)) { ns >>= 16; b += 16; }
	if (ns >= (1ULL << 8))  { ns >>= 8;  b += 8;  }
	if (ns >= (1ULL << 4))  { ns >>= 4;  b += 4;  }
	if (ns >= (1ULL << 2))  { ns >>= 2;  b += 2;  }
	if (ns >= (1ULL << 1))  {            b += 1;  }
	return b;
}

static __always_inline __u32 dev_from_pgio(void *hdr_ptr)
{
	struct nfs_pgio_header *hdr = hdr_ptr;
	struct inode *ino = BPF_CORE_READ(hdr, inode);
	if (!ino)
		return 0;
	return BPF_CORE_READ(ino, i_sb, s_dev);
}

static __always_inline __u32 dev_from_commit(void *cdata_ptr)
{
	struct nfs_commit_data *c = cdata_ptr;
	struct inode *ino = BPF_CORE_READ(c, inode);
	if (!ino)
		return 0;
	return BPF_CORE_READ(ino, i_sb, s_dev);
}

/* Race-safe cold-start: two CPUs landing on a never-seen
 * (dev, op_id, bucket) both BPF_NOEXIST(zero); whichever loses still
 * sees the entry on the second lookup, so neither sample is lost. */
static __always_inline void bump_hist(__u32 dev, __u16 op_id, __u64 lat_ns)
{
	struct hist_key hk = {
		.dev = dev,
		.op_id = op_id,
		.bucket = log2_bucket(lat_ns),
	};
	__u64 *cnt = bpf_map_lookup_elem(&hist, &hk);
	if (!cnt) {
		__u64 zero = 0;
		bpf_map_update_elem(&hist, &hk, &zero, BPF_NOEXIST);
		cnt = bpf_map_lookup_elem(&hist, &hk);
		if (!cnt)
			return;
	}
	__sync_fetch_and_add(cnt, 1);
}

static __always_inline int record_start_ptr(__u64 key, __u16 op_id, __u32 dev)
{
	struct inflight_val v = {};
	v.ts_ns = bpf_ktime_get_ns();
	v.op_id = op_id;
	v.dev = dev;
	bpf_map_update_elem(&inflight_ptr, &key, &v, BPF_ANY);
	return 0;
}

static __always_inline int record_done_ptr(__u64 key)
{
	struct inflight_val *v = bpf_map_lookup_elem(&inflight_ptr, &key);
	if (!v)
		return 0;
	__u64 lat = bpf_ktime_get_ns() - v->ts_ns;
	bump_hist(v->dev, v->op_id, lat);
	bpf_map_delete_elem(&inflight_ptr, &key);
	return 0;
}

static __always_inline int record_start_pid(__u64 key, __u16 op_id, __u32 dev)
{
	struct inflight_val v = {};
	v.ts_ns = bpf_ktime_get_ns();
	v.op_id = op_id;
	v.dev = dev;
	bpf_map_update_elem(&inflight_pid, &key, &v, BPF_ANY);
	return 0;
}

static __always_inline int record_done_pid(__u64 key)
{
	struct inflight_val *v = bpf_map_lookup_elem(&inflight_pid, &key);
	if (!v)
		return 0;
	__u64 lat = bpf_ktime_get_ns() - v->ts_ns;
	bump_hist(v->dev, v->op_id, lat);
	bpf_map_delete_elem(&inflight_pid, &key);
	return 0;
}

/* Read: init has 1 arg (hdr); done has 2 args (task, hdr). */
SEC("raw_tracepoint/nfs_initiate_read")
int handle_read_init(struct bpf_raw_tracepoint_args *ctx)
{
	void *hdr = (void *)ctx->args[0];
	return record_start_ptr((__u64)hdr, OP_READ, dev_from_pgio(hdr));
}

SEC("raw_tracepoint/nfs_readpage_done")
int handle_read_done(struct bpf_raw_tracepoint_args *ctx)
{
	return record_done_ptr(ctx->args[1]);
}

/* Write: init has 1 arg (hdr); done has 2 args (task, hdr). */
SEC("raw_tracepoint/nfs_initiate_write")
int handle_write_init(struct bpf_raw_tracepoint_args *ctx)
{
	void *hdr = (void *)ctx->args[0];
	return record_start_ptr((__u64)hdr, OP_WRITE, dev_from_pgio(hdr));
}

SEC("raw_tracepoint/nfs_writeback_done")
int handle_write_done(struct bpf_raw_tracepoint_args *ctx)
{
	return record_done_ptr(ctx->args[1]);
}

/* Commit: init has 1 arg (data); done has 2 args (task, data). */
SEC("raw_tracepoint/nfs_initiate_commit")
int handle_commit_init(struct bpf_raw_tracepoint_args *ctx)
{
	void *cdata = (void *)ctx->args[0];
	return record_start_ptr((__u64)cdata, OP_COMMIT, dev_from_commit(cdata));
}

SEC("raw_tracepoint/nfs_commit_done")
int handle_commit_done(struct bpf_raw_tracepoint_args *ctx)
{
	return record_done_ptr(ctx->args[1]);
}

/* Sync metadata ops. Each pair attaches to nfs_<event>_enter / _exit
 * formatted tracepoints. The enter probe reads dev_t straight from the
 * event payload (CO-RE relocates the field offset); the exit probe just
 * needs the (pid_tgid, op) key to find its in-flight entry. */
#define NFS_OP_PROBES(event, op_id_val)                                         \
	SEC("tracepoint/nfs/nfs_" #event "_enter")                              \
	int handle_##event##_enter(struct trace_event_raw_nfs_##event##_enter *ctx) \
	{                                                                       \
		__u64 key = ((__u64)bpf_get_current_pid_tgid() << 16) | (op_id_val); \
		return record_start_pid(key, (op_id_val), ctx->dev);            \
	}                                                                       \
	SEC("tracepoint/nfs/nfs_" #event "_exit")                               \
	int handle_##event##_exit(void *ctx)                                    \
	{                                                                       \
		__u64 key = ((__u64)bpf_get_current_pid_tgid() << 16) | (op_id_val); \
		return record_done_pid(key);                                    \
	}

NFS_OP_PROBES(getattr,     OP_GETATTR)
NFS_OP_PROBES(setattr,     OP_SETATTR)
NFS_OP_PROBES(lookup,      OP_LOOKUP)
NFS_OP_PROBES(access,      OP_ACCESS)
NFS_OP_PROBES(create,      OP_CREATE)
NFS_OP_PROBES(remove,      OP_REMOVE)
NFS_OP_PROBES(rename,      OP_RENAME)
NFS_OP_PROBES(link,        OP_LINK)
NFS_OP_PROBES(symlink,     OP_SYMLINK)
NFS_OP_PROBES(mkdir,       OP_MKDIR)
NFS_OP_PROBES(rmdir,       OP_RMDIR)
NFS_OP_PROBES(mknod,       OP_MKNOD)
NFS_OP_PROBES(fsync,       OP_FSYNC)
NFS_OP_PROBES(atomic_open, OP_OPEN)
