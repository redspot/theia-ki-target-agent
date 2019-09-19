#ifndef __SHIM_H__
#define __SHIM_H__
/*
 * all the theia syscall macros:
 * 
 * 5 main types:
 *     create a record function
 *     create a replay function
 *     create a theia_sys_name
 *         call sys_name
 *         if logging, call theia_name_ahgx()
 *     create a syscall shim, to be called by syscall table
 *     create all the calls using the other macros
 * 
 * RECORDING macros:
 *     //call and record a syscall, but do not log it
 *     SIMPLE_RECORD(name, sysnum, ...)
 * 
 *     //like SIMPLE_RECORD except that the syscall
 *     //returns something to the user in dest,
 *     //and its size is the sizeof(type)
 *     //then we save that by passing it to new_syscall_exit
 *     RET1_RECORD(name, sysnum, type, dest, ...)
 * 
 *     //like SIMPLE_RECORD except that the syscall
 *     //returns something to the user in dest,
 *     //and its size is the syscall return code
 *     //then we save that by passing it to new_syscall_exit
 *     RET1_COUNT_RECORD(name, sysnum, dest, ...)
 * 
 * REPLAYING macros:
 *     //replay a syscall. the args are ignored, for some reason ...
 *     SIMPLE_REPLAY(name, sysnum, args...)
 * 
 *     //like simple replay, but copy something into dest.
 *     //size is passed in
 *     RET1_REPLAYG(name, sysnum, dest, size, args...)
 * 
 *     //like RET1_REPLAYG except the size is just sizeof(type)
 *     //this is probably not needed
 *     RET1_REPLAY(name, sysnum, type, dest, args...)
 *         RET1_REPLAYG(name, sysnum, dest, sizeof(type), args)
 * 
 *     //like simple replay, but copy something into dest.
 *     //size is syscall return code
 *     RET1_COUNT_REPLAY(name, sysnum, dest, args...)
 * 
 * LOGGING macros:
 *     //call and log a syscall, but do not record it
 *     //theia_name_ahgx() needs to be defined.
 *     THEIA_SIMPLE_SHIM(name, sysnum, ...)
 * 
 * SHIM macros:
 *     //make a shim that is to be used in syscall table.
 *     SHIM_CALL_MAIN(number, F_RECORD, F_REPLAY, F_SYS)
 *         if recording
 *             if ignore_flag return F_SYS
 *             return F_RECORD
 *         if replay return F_REPLAY
 *         return F_SYS
 * 
 *     //make a shim that is to be used in syscall table. use default names for record/replay/sys
 *     SHIM_CALL(name, number, args...)
 *         SHIM_CALL_MAIN(number, record_##name(args), replay_##name(args), sys_##name(args))
 * 
 *     //make a shim that is to be used in syscall table. if ignore_flag return IGNORED version
 *     SHIM_CALL_MAIN_IGNORE(number, F_RECORD, F_REPLAY, F_SYS, F_RECORD_IGNORED)
 *         if recording
 *             if ignore_flag return F_RECORD_IGNORED
 *             return F_RECORD
 *         if replay return F_REPLAY
 *         return F_SYS
 * 
 *     //make a shim that is to be used in syscall table. use default names for record/replay/sys
 *     SHIM_CALL_IGNORE(name, number, args...)
 *         SHIM_CALL_MAIN_IGNORE(number, record_##name(args), replay_##name(args), sys_##name(args), record_##name##_ignored(args))
 * 
 * CREATE_SHIMS macros:
 *     //make a shim for syscall.
 *     //use simple record. use simple replay.
 *     //no additional calls need to be defined.
 *     //record_name() does not log
 *     //shim_name() does not log
 *     SIMPLE_SHIM(name, sysnum, ...)
 * 
 *     //make a shim for syscall.
 *     //use simple record. use simple replay.
 *     //theia_name_ahgx() needs to be defined.
 *     //record_name() does not log
 *     //theia_sys_name() does log
 *     //when recording, call is not logged
 *     THEIA_SHIM(name, sysnum, ...)
 * 
 *     //just like SIMPLE_SHIM except:
 *     //    record_name() saves dest
 *     //    replay_name() copies something to dest
 *     //    size is defaulted to sizeof(type)
 *     //no additional calls need to be defined.
 *     //record_name() does not log
 *     //shim_name() does not log
 *     RET1_SHIM(name, sysnum, type, dest, ...)
 * 
 *     //just like SIMPLE_SHIM1 except:
 *     //    record_name() saves dest
 *     //    replay_name() copies something to dest
 *     //    size is syscall return code
 *     //no additional calls need to be defined.
 *     //record_name() does not log
 *     //shim_name() does not log
 *     RET1_COUNT_SHIM(name, sysnum, dest, ...)
 * 
 * Examples:
 *     //the prototypes need to be declared
 *     static long record_read(unsigned int fd, char __user *buf, size_t count);
 *     static long replay_read(unsigned int fd, char __user *buf, size_t count);
 *     static long theia_sys_read(unsigned int fd, char __user *buf, size_t count);
 *     //noinline is required since this must be a real function for ftrace to use
 *     //asmlinkage is only needed by something that will directly receive args intended
 *     //for a syscall from userspace
 *     noinline asmlinkage long shim_read(unsigned int fd, char __user *buf, size_t count)
 *     SHIM_CALL_MAIN(0, record_read(fd, buf, count), replay_read(fd, buf, count), theia_sys_read(fd, buf, count))
 * 
 *     RET1_SHIM(waitpid, 7, int, stat_addr, pid_t, pid, int __user *, stat_addr, int, options);
 * 
 *     //void theia_creat_ahgx(const char __user *pathname, int mode, long fd, int sysnum);
 *     //the THEIA_SHIM macro will declare the prototype for theia_creat_ahgx()
 *     THEIA_SHIM(creat, 85, const char __user *, pathname, int, mode);
 */

/*
 * Helper macros use for making the shim macros variadic
 */

#define _GET_NTH_ARG(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, N, ...) N
#define _INNER_CONCAT(a, ...) a ## __VA_ARGS__

#define _0_PAIR(_macro, ...) _INNER_CONCAT(_macro, _0)()
#define _1_PAIR(_macro, type, arg) _macro(type, arg)
#define _2_PAIR(_macro, type, arg, ...) _macro(type, arg), _1_PAIR(_macro, __VA_ARGS__)
#define _3_PAIR(_macro, type, arg, ...) _macro(type, arg), _2_PAIR(_macro, __VA_ARGS__)
#define _4_PAIR(_macro, type, arg, ...) _macro(type, arg), _3_PAIR(_macro, __VA_ARGS__)
#define _5_PAIR(_macro, type, arg, ...) _macro(type, arg), _4_PAIR(_macro, __VA_ARGS__)
#define _6_PAIR(_macro, type, arg, ...) _macro(type, arg), _5_PAIR(_macro, __VA_ARGS__)
#define _PAIR_ERROR(_macro, ...) __undefined__syscall_wrap_must_be_in_pairs()

#define _FOR_EACH_PAIR(_macro, ...) \
  _GET_NTH_ARG("macro", ##__VA_ARGS__, \
  _PAIR_ERROR, _6_PAIR, \
  _PAIR_ERROR, _5_PAIR, \
  _PAIR_ERROR, _4_PAIR, \
  _PAIR_ERROR, _3_PAIR, \
  _PAIR_ERROR, _2_PAIR, \
  _PAIR_ERROR, _1_PAIR, \
  _0_PAIR, _PAIR_ERROR)(_macro, ##__VA_ARGS__)

#define _TH_PROTO(type, arg) type arg
#define _TH_PROTO_0(...) void
#define _TH_ARG(type, arg) arg
#define _TH_ARG_0(...)

/*
 * begin RECORDING macros
 */

#define SIMPLE_RECORD(name, sysnum, ...)    \
  static long            \
  record_##name(_FOR_EACH_PAIR(_TH_PROTO, __VA_ARGS__))       \
  {               \
    long rc;            \
    new_syscall_enter (sysnum);       \
    rc = real_sys_##name(_FOR_EACH_PAIR(_TH_ARG, __VA_ARGS__));        \
    new_syscall_done (sysnum, rc);        \
    new_syscall_exit (sysnum, NULL);      \
    return rc;            \
  }

#define RET1_RECORD(name, sysnum, type, dest, ...)  \
  static long            \
  record_##name(_FOR_EACH_PAIR(_TH_PROTO, __VA_ARGS__))       \
  {                 \
    long rc;              \
    type *pretval = NULL;           \
                    \
    new_syscall_enter (sysnum);         \
    rc = real_sys_##name(_FOR_EACH_PAIR(_TH_ARG, __VA_ARGS__));        \
    new_syscall_done (sysnum, rc);          \
    if (rc >= 0 && dest) {            \
            pretval = ARGSKMALLOC (sizeof(type), GFP_KERNEL); \
      if (pretval == NULL) {          \
        TPRINT ("record_##name: can't allocate buffer\n"); \
        return -ENOMEM;         \
      }             \
      if (copy_from_user (pretval, dest, sizeof (type))) {  \
        TPRINT ("record_##name: can't copy to buffer\n"); \
        ARGSKFREE(pretval, sizeof(type));   \
        pretval = NULL;         \
        rc = -EFAULT;         \
      }             \
    }               \
                    \
    new_syscall_exit (sysnum, pretval);       \
    return rc;              \
  }

#define RET1_COUNT_RECORD(name, sysnum, dest, ...) \
  static long            \
  record_##name(_FOR_EACH_PAIR(_TH_PROTO, __VA_ARGS__))       \
  {                 \
    long rc;              \
    char *pretval = NULL;           \
                    \
    new_syscall_enter (sysnum);         \
    rc = real_sys_##name(_FOR_EACH_PAIR(_TH_ARG, __VA_ARGS__));        \
    new_syscall_done (sysnum, rc);          \
    if (rc >= 0 && dest) {            \
      pretval = ARGSKMALLOC (rc, GFP_KERNEL);     \
      if (pretval == NULL) {          \
        TPRINT ("record_##name: can't allocate buffer\n"); \
        return -ENOMEM;         \
      }             \
      if (copy_from_user (pretval, dest, rc)) {   \
        TPRINT ("record_##name: can't copy to buffer\n"); \
        ARGSKFREE(pretval, rc);       \
        pretval = NULL;         \
        rc = -EFAULT;         \
      }             \
    }               \
                    \
    new_syscall_exit (sysnum, pretval);       \
    return rc;              \
  }

/*
 * end RECORDING macros
 */

/*
 * begin REPLAYING macros
 */

#define SIMPLE_REPLAY(name, sysnum, args...)    \
  static long replay_##name (args)          \
  {             \
    return get_next_syscall (sysnum, NULL); \
  }

#define RET1_REPLAYG(name, sysnum, dest, size, args...)     \
  static long replay_##name (args)       \
  {                 \
    char *retparams = NULL;           \
    long rc = get_next_syscall (sysnum, &retparams);  \
                    \
    if (retparams) {            \
      if (copy_to_user (dest, retparams, size)) \
        TPRINT ("replay_##name: pid %d cannot copy to user\n", current->pid); \
      TPRINT("argsconsume called at %d, size: %lu\n", __LINE__, size); \
      argsconsume (current->replay_thrd->rp_record_thread, size); \
    }               \
    return rc;              \
  }                 \

#define RET1_REPLAY(name, sysnum, type, dest, args...) \
  RET1_REPLAYG(name, sysnum, dest, sizeof(type), args)

#define RET1_COUNT_REPLAY(name, sysnum, dest, args...)      \
  static long replay_##name (args)       \
  {                 \
    char *retparams = NULL;           \
    long rc = get_next_syscall (sysnum, &retparams);    \
                    \
    if (retparams) {            \
      if (copy_to_user (dest, retparams, rc)) \
        TPRINT ("replay_##name: pid %d cannot copy to user\n", current->pid); \
      argsconsume (current->replay_thrd->rp_record_thread, rc); \
    }               \
    return rc;              \
  }                 \

/*
 * end REPLAYING macros
 */

/*
 * begin LOGGING macros
 */

#define THEIA_SIMPLE_SHIM(name, sysnum, ...)    \
  static long theia_sys_##name(_FOR_EACH_PAIR(_TH_PROTO, __VA_ARGS__))       \
  {               \
    long rc;            \
    rc = real_sys_##name(_FOR_EACH_PAIR(_TH_ARG, __VA_ARGS__));        \
    if (theia_logging_toggle) \
      theia_##name##_ahgx(_FOR_EACH_PAIR(_TH_ARG, __VA_ARGS__), rc, sysnum);               \
    return rc;            \
  }

/*
 * end LOGGING macros
 */

/*
 * begin SHIM macros
 */

//special SHIM function for ignored syscalls; currently, only used for futex, gettimeofday and clock_gettime
#define SHIM_CALL_MAIN_IGNORE(number, F_RECORD, F_REPLAY, F_SYS, F_RECORD_IGNORED)  \
{ \
  long ret; \
  int ignore_flag;            \
  try_module_get(THIS_MODULE); \
  if (current->record_thrd) {         \
    if (current->record_thrd->rp_ignore_flag_addr) {  \
      get_user (ignore_flag, current->record_thrd->rp_ignore_flag_addr); \
      if (ignore_flag) {          \
        ret = F_RECORD_IGNORED;    \
        goto out; \
      }             \
    }             \
    ret = F_RECORD;          \
    goto out; \
  }               \
  if (current->replay_thrd && test_app_syscall(number)) {   \
    if (current->replay_thrd->rp_record_thread->rp_ignore_flag_addr) { \
      get_user (ignore_flag, current->replay_thrd->rp_record_thread->rp_ignore_flag_addr); \
      if (ignore_flag) { \
        TPRINT ("syscall %d ignored\n", number); \
        goto call_sys;       \
      }           \
    }             \
    ret = F_REPLAY;          \
    goto out; \
  }               \
  else if (current->replay_thrd) {        \
    if (*(current->replay_thrd->rp_preplay_clock) > pin_debug_clock) {  \
      DPRINT("Pid %d, pin syscall %d\n", current->pid, number); \
    }             \
  }               \
call_sys: \
  ret = F_SYS; \
out: \
  module_put(THIS_MODULE); \
  return ret;             \
}

#define SHIM_CALL_MAIN(number, F_RECORD, F_REPLAY, F_SYS) \
  SHIM_CALL_MAIN_IGNORE(number, F_RECORD, F_REPLAY, F_SYS, F_SYS)

#define SHIM_CALL(name, number, args...)          \
  SHIM_CALL_MAIN(number, record_##name(args), replay_##name(args), real_sys_##name(args))

#define SHIM_CALL_IGNORE(name, number, args...)         \
  SHIM_CALL_MAIN_IGNORE(number, record_##name(args), replay_##name(args), real_sys_##name(args), record_##name##_ignored(args))

/*
 * end SHIM macros
 */

/*
 * begin CREATE_SHIMS macros
 */
#define SIMPLE_SHIM(name, sysnum, ...) \
  SIMPLE_RECORD(name, sysnum, ##__VA_ARGS__); \
  SIMPLE_REPLAY(name, sysnum, _FOR_EACH_PAIR(_TH_PROTO, __VA_ARGS__)); \
  long shim_##name (_FOR_EACH_PAIR(_TH_PROTO, __VA_ARGS__)) \
  SHIM_CALL(name, sysnum, _FOR_EACH_PAIR(_TH_ARG, __VA_ARGS__));

#define THEIA_SHIM(name, sysnum, ...) \
  SIMPLE_RECORD(name, sysnum, ##__VA_ARGS__); \
  SIMPLE_REPLAY(name, sysnum, _FOR_EACH_PAIR(_TH_PROTO, __VA_ARGS__)); \
  void theia_##name##_ahgx(_FOR_EACH_PAIR(_TH_PROTO, __VA_ARGS__), long rc, int sysnum); \
  THEIA_SIMPLE_SHIM(name, sysnum, ##__VA_ARGS__); \
  long shim_##name (_FOR_EACH_PAIR(_TH_PROTO, __VA_ARGS__)) \
  SHIM_CALL_MAIN(sysnum, \
    record_##name(_FOR_EACH_PAIR(_TH_ARG, __VA_ARGS__)), \
    replay_##name(_FOR_EACH_PAIR(_TH_ARG, __VA_ARGS__)), \
    theia_sys_##name(_FOR_EACH_PAIR(_TH_ARG, __VA_ARGS__)), \
  );

#define RET1_SHIM(name, sysnum, type, dest, ...) \
  RET1_RECORD(name, sysnum, type, dest, ##__VA_ARGS__); \
  RET1_REPLAY(name, sysnum, type, dest, _FOR_EACH_PAIR(_TH_PROTO, __VA_ARGS__)); \
  long shim_##name (_FOR_EACH_PAIR(_TH_PROTO, __VA_ARGS__)) \
  SHIM_CALL(name, sysnum, _FOR_EACH_PAIR(_TH_ARG, __VA_ARGS__));

#define RET1_COUNT_SHIM(name, sysnum, dest, ...) \
  RET1_COUNT_RECORD(name, sysnum, dest, ##__VA_ARGS__); \
  RET1_COUNT_REPLAY(name, sysnum, dest, _FOR_EACH_PAIR(_TH_PROTO, __VA_ARGS__)); \
  long shim_##name (_FOR_EACH_PAIR(_TH_PROTO, __VA_ARGS__)) \
  SHIM_CALL(name, sysnum, _FOR_EACH_PAIR(_TH_ARG, __VA_ARGS__));

/*
 * end CREATE_SHIMS macros
 */

#endif
