#include <linux/module.h>
#include <linux/tracepoint.h>
#include <linux/sched.h>
#include <linux/version.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0))
  #include <linux/trace_events.h>
#else
  #include <linux/ftrace_event.h>
#endif

#include <theia_core.h>

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
    if (!atomic_read(&all_traces_enabled)) return;
    if (!get_record_thread()) return;
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

/**
 * signal_generate - called when a signal is generated
 * @sig: signal number
 * @info: pointer to struct siginfo
 * @task: pointer to struct task_struct
 * @group: shared or private
 * @result: TRACE_SIGNAL_*
 *
 * Current process sends a 'sig' signal to 'task' process with
 * 'info' siginfo. If 'info' is SEND_SIG_NOINFO or SEND_SIG_PRIV,
 * 'info' is not a pointer and you can't access its field. Instead,
 * SEND_SIG_NOINFO means that si_code is SI_USER, and SEND_SIG_PRIV
 * means that si_code is SI_KERNEL.
 */
DECLARE_TRACE(signal_generate,
    TP_PROTO(int sig, struct siginfo *info, struct task_struct *task,
            int group, int result),
    TP_ARGS(sig, info, task, group, result)
    );

static void probe_signal_generate(void *ignore, int sig, struct siginfo *info,
    struct task_struct *task, int group, int result)
{
    if (!atomic_read(&all_traces_enabled)) return;
    if (!get_record_thread()) return;

    if ( info == SEND_SIG_NOINFO )
    { //SI_USER generated signal s for pid p
        pr_info("%s: SI_USER generated signal %d for pid %d\n",
            __func__, sig, current->pid);
    }
    else if ( info == SEND_SIG_PRIV )
    { //SI_KERNEL generated signal s for pid p
        pr_info("%s: SI_KERNEL generated signal %d for pid %d\n",
            __func__, sig, current->pid);
    }
    else
    { //pid sent signal s to pid
        pr_info("%s: pid %d generated signal %d for pid %d\n",
            __func__, current->pid, sig, task->pid);
    }
}

/**
 * signal_deliver - called when a signal is delivered
 * @sig: signal number
 * @info: pointer to struct siginfo
 * @ka: pointer to struct k_sigaction
 *
 * A 'sig' signal is delivered to current process with 'info' siginfo,
 * and it will be handled by 'ka'. ka->sa.sa_handler can be SIG_IGN or
 * SIG_DFL.
 * Note that some signals reported by signal_generate tracepoint can be
 * lost, ignored or modified (by debugger) before hitting this tracepoint.
 * This means, this can show which signals are actually delivered, but
 * matching generated signals and delivered signals may not be correct.
 */
DECLARE_TRACE(signal_deliver,
    TP_PROTO(int sig, struct siginfo *info, struct k_sigaction *ka),
    TP_ARGS(sig, info, ka)
    );

static void probe_signal_deliver(void *ignore, int sig, struct siginfo *info, struct k_sigaction *ka)
{
    if (!atomic_read(&all_traces_enabled)) return;
    if (!get_record_thread()) return;
    pr_info("%s: signal %d delivered to pid %d\n", __func__, sig, current->pid);
}

static int __init theia_trace_init(void)
{
        int ret;

        ret = register_trace_sched_process_fork(probe_sched_process_fork, NULL);
        WARN_ON(ret);
        ret = trace_set_clr_event("sched", "sched_process_fork", 1);
        WARN_ON(ret);

        ret = register_trace_signal_generate(probe_signal_generate, NULL);
        WARN_ON(ret);
        ret = trace_set_clr_event("signal", "signal_generate", 1);
        WARN_ON(ret);

        ret = register_trace_signal_deliver(probe_signal_deliver, NULL);
        WARN_ON(ret);
        ret = trace_set_clr_event("signal", "signal_deliver", 1);
        WARN_ON(ret);

        atomic_set(&all_traces_enabled, 1);
        return 0;
}

module_init(theia_trace_init);

static void __exit theia_trace_exit(void)
{
        int ret;
        atomic_set(&all_traces_enabled, 0);

        ret = trace_set_clr_event("sched", "sched_process_fork", 0);
        WARN_ON(ret);
        unregister_trace_sched_process_fork(probe_sched_process_fork, NULL);

        ret = trace_set_clr_event("signal", "signal_generate", 0);
        WARN_ON(ret);
        unregister_trace_signal_generate(probe_signal_generate, NULL);

        ret = trace_set_clr_event("signal", "signal_deliver", 0);
        WARN_ON(ret);
        unregister_trace_signal_deliver(probe_signal_deliver, NULL);

        tracepoint_synchronize_unregister();
}

module_exit(theia_trace_exit);

MODULE_DESCRIPTION("Theia tracepoint hooks");
MODULE_AUTHOR("wilson.martin@gtri.gatech.edu");
// all of the kernel tracing exports use EXPORT_SYMBOL_GPL()
// therefore, this module must use GPL license or it won't load
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1-THEIA-0000");
