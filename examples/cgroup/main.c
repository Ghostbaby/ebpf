#include <common.h>
#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_tracing.h>

struct event {
	__u32 pid;
	u64 cgroup_id;
	char cgroup_name[256];
};
struct event *unused_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
	struct event event          = {};
	u32 pid                     = bpf_get_current_pid_tgid() >> 32;
	u64 cgroup_id               = bpf_get_current_cgroup_id();
	event.pid                   = pid;
	event.cgroup_id             = cgroup_id;
	struct task_struct *cur_tsk = (struct task_struct *)bpf_get_current_task();

	const char *name = BPF_CORE_READ(cur_tsk, cgroups, subsys[0], cgroup, kn, name);
	bpf_probe_read_str(&event.cgroup_name, sizeof(event.cgroup_name), name);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
