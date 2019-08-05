#include <linux/module.h>
#include <linux/tracepoint.h>
#include <linux/sched.h>


extern int trace_set_clr_event(const char *, const char *, int);

//https://gist.github.com/HugoGuiroux/0894091275169750d22f#file-makefile
//do this stuff ---^^^

/*
 * Tracepoint for do_fork.
 * Saving both TID and PID information, especially for the child, allows
 * trace analyzers to distinguish between creation of a new process and
 * creation of a new thread. Newly created processes will have child_tid
 * == child_pid, while creation of a thread yields to child_tid !=
 * child_pid.
 */
DECLARE_TRACE(sched_process_fork,
	TP_PROTO(struct task_struct *parent, struct task_struct *child),
	TP_ARGS(parent, child)
  );

static void probe_sched_process_fork(void *ignore,
    struct task_struct *parent, struct task_struct *child)
{
		if (child) {
      pid_t child_pid, child_tid;
      child_pid = child->pid;
      child_tid = child->tgid;
      if (child_pid == child_tid) {
        //fork
        pr_info("%s: parent pid %d called fork() and created child pid %d\n",
            __func__, parent->pid, child_pid);
      } else {
        //clone
        pr_info("%s: parent pid %d called clone() and created child tid %d\n",
            __func__, parent->pid, child_tid);
      }
    }
}

static int __init theia_trace_init(void)
{
        int ret;

        ret = register_trace_sched_process_fork(probe_sched_process_fork, NULL);
        WARN_ON(ret);

//int trace_set_clr_event(const char *system, const char *event, int set)
        ret = trace_set_clr_event("sched", "sched_process_fork", 1);
        WARN_ON(ret);

        return 0;
}

module_init(theia_trace_init);

static void __exit theia_trace_exit(void)
{
        int ret = trace_set_clr_event("sched", "sched_process_fork", 0);
        WARN_ON(ret);
        unregister_trace_sched_process_fork(probe_sched_process_fork, NULL);
        tracepoint_synchronize_unregister();
}

module_exit(theia_trace_exit);

//MODULE_LICENSE("GPL");
//MODULE_AUTHOR("Mathieu Desnoyers");
//MODULE_DESCRIPTION("Tracepoint Probes Samples");
