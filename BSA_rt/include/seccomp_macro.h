#include "config.h"

#define SECCOMP_DENY_SYSCALL(syscall) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_##syscall, 0, 1), \
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (0 &  SECCOMP_RET_DATA)), 


#ifdef SECCOMP_DENY_read
	SECCOMP_DENY_SYSCALL(read)
#endif
#ifdef SECCOMP_DENY_write
	SECCOMP_DENY_SYSCALL(write)
#endif
#ifdef SECCOMP_DENY_open
	SECCOMP_DENY_SYSCALL(open)
#endif
#ifdef SECCOMP_DENY_close
	SECCOMP_DENY_SYSCALL(close)
#endif
#ifdef SECCOMP_DENY_stat
	SECCOMP_DENY_SYSCALL(stat)
#endif
#ifdef SECCOMP_DENY_fstat
	SECCOMP_DENY_SYSCALL(fstat)
#endif
#ifdef SECCOMP_DENY_lstat
	SECCOMP_DENY_SYSCALL(lstat)
#endif
#ifdef SECCOMP_DENY_poll
	SECCOMP_DENY_SYSCALL(poll)
#endif
#ifdef SECCOMP_DENY_lseek
	SECCOMP_DENY_SYSCALL(lseek)
#endif
#ifdef SECCOMP_DENY_mmap
	SECCOMP_DENY_SYSCALL(mmap)
#endif
#ifdef SECCOMP_DENY_mprotect
	SECCOMP_DENY_SYSCALL(mprotect)
#endif
#ifdef SECCOMP_DENY_munmap
	SECCOMP_DENY_SYSCALL(munmap)
#endif
#ifdef SECCOMP_DENY_brk
	SECCOMP_DENY_SYSCALL(brk)
#endif
#ifdef SECCOMP_DENY_rt_sigaction
	SECCOMP_DENY_SYSCALL(rt_sigaction)
#endif
#ifdef SECCOMP_DENY_rt_sigprocmask
	SECCOMP_DENY_SYSCALL(rt_sigprocmask)
#endif
#ifdef SECCOMP_DENY_rt_sigreturn
	SECCOMP_DENY_SYSCALL(rt_sigreturn)
#endif
#ifdef SECCOMP_DENY_ioctl
	SECCOMP_DENY_SYSCALL(ioctl)
#endif
#ifdef SECCOMP_DENY_pread64
	SECCOMP_DENY_SYSCALL(pread64)
#endif
#ifdef SECCOMP_DENY_pwrite64
	SECCOMP_DENY_SYSCALL(pwrite64)
#endif
#ifdef SECCOMP_DENY_readv
	SECCOMP_DENY_SYSCALL(readv)
#endif
#ifdef SECCOMP_DENY_writev
	SECCOMP_DENY_SYSCALL(writev)
#endif
#ifdef SECCOMP_DENY_access
	SECCOMP_DENY_SYSCALL(access)
#endif
#ifdef SECCOMP_DENY_pipe
	SECCOMP_DENY_SYSCALL(pipe)
#endif
#ifdef SECCOMP_DENY_select
	SECCOMP_DENY_SYSCALL(select)
#endif
#ifdef SECCOMP_DENY_sched_yield
	SECCOMP_DENY_SYSCALL(sched_yield)
#endif
#ifdef SECCOMP_DENY_mremap
	SECCOMP_DENY_SYSCALL(mremap)
#endif
#ifdef SECCOMP_DENY_msync
	SECCOMP_DENY_SYSCALL(msync)
#endif
#ifdef SECCOMP_DENY_mincore
	SECCOMP_DENY_SYSCALL(mincore)
#endif
#ifdef SECCOMP_DENY_madvise
	SECCOMP_DENY_SYSCALL(madvise)
#endif
#ifdef SECCOMP_DENY_shmget
	SECCOMP_DENY_SYSCALL(shmget)
#endif
#ifdef SECCOMP_DENY_shmat
	SECCOMP_DENY_SYSCALL(shmat)
#endif
#ifdef SECCOMP_DENY_shmctl
	SECCOMP_DENY_SYSCALL(shmctl)
#endif
#ifdef SECCOMP_DENY_dup
	SECCOMP_DENY_SYSCALL(dup)
#endif
#ifdef SECCOMP_DENY_dup2
	SECCOMP_DENY_SYSCALL(dup2)
#endif
#ifdef SECCOMP_DENY_pause
	SECCOMP_DENY_SYSCALL(pause)
#endif
#ifdef SECCOMP_DENY_nanosleep
	SECCOMP_DENY_SYSCALL(nanosleep)
#endif
#ifdef SECCOMP_DENY_getitimer
	SECCOMP_DENY_SYSCALL(getitimer)
#endif
#ifdef SECCOMP_DENY_alarm
	SECCOMP_DENY_SYSCALL(alarm)
#endif
#ifdef SECCOMP_DENY_setitimer
	SECCOMP_DENY_SYSCALL(setitimer)
#endif
#ifdef SECCOMP_DENY_getpid
	SECCOMP_DENY_SYSCALL(getpid)
#endif
#ifdef SECCOMP_DENY_sendfile
	SECCOMP_DENY_SYSCALL(sendfile)
#endif
#ifdef SECCOMP_DENY_socket
	SECCOMP_DENY_SYSCALL(socket)
#endif
#ifdef SECCOMP_DENY_connect
	SECCOMP_DENY_SYSCALL(connect)
#endif
#ifdef SECCOMP_DENY_accept
	SECCOMP_DENY_SYSCALL(accept)
#endif
#ifdef SECCOMP_DENY_sendto
	SECCOMP_DENY_SYSCALL(sendto)
#endif
#ifdef SECCOMP_DENY_recvfrom
	SECCOMP_DENY_SYSCALL(recvfrom)
#endif
#ifdef SECCOMP_DENY_sendmsg
	SECCOMP_DENY_SYSCALL(sendmsg)
#endif
#ifdef SECCOMP_DENY_recvmsg
	SECCOMP_DENY_SYSCALL(recvmsg)
#endif
#ifdef SECCOMP_DENY_shutdown
	SECCOMP_DENY_SYSCALL(shutdown)
#endif
#ifdef SECCOMP_DENY_bind
	SECCOMP_DENY_SYSCALL(bind)
#endif
#ifdef SECCOMP_DENY_listen
	SECCOMP_DENY_SYSCALL(listen)
#endif
#ifdef SECCOMP_DENY_getsockname
	SECCOMP_DENY_SYSCALL(getsockname)
#endif
#ifdef SECCOMP_DENY_getpeername
	SECCOMP_DENY_SYSCALL(getpeername)
#endif
#ifdef SECCOMP_DENY_socketpair
	SECCOMP_DENY_SYSCALL(socketpair)
#endif
#ifdef SECCOMP_DENY_setsockopt
	SECCOMP_DENY_SYSCALL(setsockopt)
#endif
#ifdef SECCOMP_DENY_getsockopt
	SECCOMP_DENY_SYSCALL(getsockopt)
#endif
#ifdef SECCOMP_DENY_clone
	SECCOMP_DENY_SYSCALL(clone)
#endif
#ifdef SECCOMP_DENY_fork
	SECCOMP_DENY_SYSCALL(fork)
#endif
#ifdef SECCOMP_DENY_vfork
	SECCOMP_DENY_SYSCALL(vfork)
#endif
#ifdef SECCOMP_DENY_execve
	SECCOMP_DENY_SYSCALL(execve)
#endif
#ifdef SECCOMP_DENY_exit
	SECCOMP_DENY_SYSCALL(exit)
#endif
#ifdef SECCOMP_DENY_wait4
	SECCOMP_DENY_SYSCALL(wait4)
#endif
#ifdef SECCOMP_DENY_kill
	SECCOMP_DENY_SYSCALL(kill)
#endif
#ifdef SECCOMP_DENY_uname
	SECCOMP_DENY_SYSCALL(uname)
#endif
#ifdef SECCOMP_DENY_semget
	SECCOMP_DENY_SYSCALL(semget)
#endif
#ifdef SECCOMP_DENY_semop
	SECCOMP_DENY_SYSCALL(semop)
#endif
#ifdef SECCOMP_DENY_semctl
	SECCOMP_DENY_SYSCALL(semctl)
#endif
#ifdef SECCOMP_DENY_shmdt
	SECCOMP_DENY_SYSCALL(shmdt)
#endif
#ifdef SECCOMP_DENY_msgget
	SECCOMP_DENY_SYSCALL(msgget)
#endif
#ifdef SECCOMP_DENY_msgsnd
	SECCOMP_DENY_SYSCALL(msgsnd)
#endif
#ifdef SECCOMP_DENY_msgrcv
	SECCOMP_DENY_SYSCALL(msgrcv)
#endif
#ifdef SECCOMP_DENY_msgctl
	SECCOMP_DENY_SYSCALL(msgctl)
#endif
#ifdef SECCOMP_DENY_fcntl
	SECCOMP_DENY_SYSCALL(fcntl)
#endif
#ifdef SECCOMP_DENY_flock
	SECCOMP_DENY_SYSCALL(flock)
#endif
#ifdef SECCOMP_DENY_fsync
	SECCOMP_DENY_SYSCALL(fsync)
#endif
#ifdef SECCOMP_DENY_fdatasync
	SECCOMP_DENY_SYSCALL(fdatasync)
#endif
#ifdef SECCOMP_DENY_truncate
	SECCOMP_DENY_SYSCALL(truncate)
#endif
#ifdef SECCOMP_DENY_ftruncate
	SECCOMP_DENY_SYSCALL(ftruncate)
#endif
#ifdef SECCOMP_DENY_getdents
	SECCOMP_DENY_SYSCALL(getdents)
#endif
#ifdef SECCOMP_DENY_getcwd
	SECCOMP_DENY_SYSCALL(getcwd)
#endif
#ifdef SECCOMP_DENY_chdir
	SECCOMP_DENY_SYSCALL(chdir)
#endif
#ifdef SECCOMP_DENY_fchdir
	SECCOMP_DENY_SYSCALL(fchdir)
#endif
#ifdef SECCOMP_DENY_rename
	SECCOMP_DENY_SYSCALL(rename)
#endif
#ifdef SECCOMP_DENY_mkdir
	SECCOMP_DENY_SYSCALL(mkdir)
#endif
#ifdef SECCOMP_DENY_rmdir
	SECCOMP_DENY_SYSCALL(rmdir)
#endif
#ifdef SECCOMP_DENY_creat
	SECCOMP_DENY_SYSCALL(creat)
#endif
#ifdef SECCOMP_DENY_link
	SECCOMP_DENY_SYSCALL(link)
#endif
#ifdef SECCOMP_DENY_unlink
	SECCOMP_DENY_SYSCALL(unlink)
#endif
#ifdef SECCOMP_DENY_symlink
	SECCOMP_DENY_SYSCALL(symlink)
#endif
#ifdef SECCOMP_DENY_readlink
	SECCOMP_DENY_SYSCALL(readlink)
#endif
#ifdef SECCOMP_DENY_chmod
	SECCOMP_DENY_SYSCALL(chmod)
#endif
#ifdef SECCOMP_DENY_fchmod
	SECCOMP_DENY_SYSCALL(fchmod)
#endif
#ifdef SECCOMP_DENY_chown
	SECCOMP_DENY_SYSCALL(chown)
#endif
#ifdef SECCOMP_DENY_fchown
	SECCOMP_DENY_SYSCALL(fchown)
#endif
#ifdef SECCOMP_DENY_lchown
	SECCOMP_DENY_SYSCALL(lchown)
#endif
#ifdef SECCOMP_DENY_umask
	SECCOMP_DENY_SYSCALL(umask)
#endif
#ifdef SECCOMP_DENY_gettimeofday
	SECCOMP_DENY_SYSCALL(gettimeofday)
#endif
#ifdef SECCOMP_DENY_getrlimit
	SECCOMP_DENY_SYSCALL(getrlimit)
#endif
#ifdef SECCOMP_DENY_getrusage
	SECCOMP_DENY_SYSCALL(getrusage)
#endif
#ifdef SECCOMP_DENY_sysinfo
	SECCOMP_DENY_SYSCALL(sysinfo)
#endif
#ifdef SECCOMP_DENY_times
	SECCOMP_DENY_SYSCALL(times)
#endif
#ifdef SECCOMP_DENY_ptrace
	SECCOMP_DENY_SYSCALL(ptrace)
#endif
#ifdef SECCOMP_DENY_getuid
	SECCOMP_DENY_SYSCALL(getuid)
#endif
#ifdef SECCOMP_DENY_syslog
	SECCOMP_DENY_SYSCALL(syslog)
#endif
#ifdef SECCOMP_DENY_getgid
	SECCOMP_DENY_SYSCALL(getgid)
#endif
#ifdef SECCOMP_DENY_setuid
	SECCOMP_DENY_SYSCALL(setuid)
#endif
#ifdef SECCOMP_DENY_setgid
	SECCOMP_DENY_SYSCALL(setgid)
#endif
#ifdef SECCOMP_DENY_geteuid
	SECCOMP_DENY_SYSCALL(geteuid)
#endif
#ifdef SECCOMP_DENY_getegid
	SECCOMP_DENY_SYSCALL(getegid)
#endif
#ifdef SECCOMP_DENY_setpgid
	SECCOMP_DENY_SYSCALL(setpgid)
#endif
#ifdef SECCOMP_DENY_getppid
	SECCOMP_DENY_SYSCALL(getppid)
#endif
#ifdef SECCOMP_DENY_getpgrp
	SECCOMP_DENY_SYSCALL(getpgrp)
#endif
#ifdef SECCOMP_DENY_setsid
	SECCOMP_DENY_SYSCALL(setsid)
#endif
#ifdef SECCOMP_DENY_setreuid
	SECCOMP_DENY_SYSCALL(setreuid)
#endif
#ifdef SECCOMP_DENY_setregid
	SECCOMP_DENY_SYSCALL(setregid)
#endif
#ifdef SECCOMP_DENY_getgroups
	SECCOMP_DENY_SYSCALL(getgroups)
#endif
#ifdef SECCOMP_DENY_setgroups
	SECCOMP_DENY_SYSCALL(setgroups)
#endif
#ifdef SECCOMP_DENY_setresuid
	SECCOMP_DENY_SYSCALL(setresuid)
#endif
#ifdef SECCOMP_DENY_getresuid
	SECCOMP_DENY_SYSCALL(getresuid)
#endif
#ifdef SECCOMP_DENY_setresgid
	SECCOMP_DENY_SYSCALL(setresgid)
#endif
#ifdef SECCOMP_DENY_getresgid
	SECCOMP_DENY_SYSCALL(getresgid)
#endif
#ifdef SECCOMP_DENY_getpgid
	SECCOMP_DENY_SYSCALL(getpgid)
#endif
#ifdef SECCOMP_DENY_setfsuid
	SECCOMP_DENY_SYSCALL(setfsuid)
#endif
#ifdef SECCOMP_DENY_setfsgid
	SECCOMP_DENY_SYSCALL(setfsgid)
#endif
#ifdef SECCOMP_DENY_getsid
	SECCOMP_DENY_SYSCALL(getsid)
#endif
#ifdef SECCOMP_DENY_capget
	SECCOMP_DENY_SYSCALL(capget)
#endif
#ifdef SECCOMP_DENY_capset
	SECCOMP_DENY_SYSCALL(capset)
#endif
#ifdef SECCOMP_DENY_rt_sigpending
	SECCOMP_DENY_SYSCALL(rt_sigpending)
#endif
#ifdef SECCOMP_DENY_rt_sigtimedwait
	SECCOMP_DENY_SYSCALL(rt_sigtimedwait)
#endif
#ifdef SECCOMP_DENY_rt_sigqueueinfo
	SECCOMP_DENY_SYSCALL(rt_sigqueueinfo)
#endif
#ifdef SECCOMP_DENY_rt_sigsuspend
	SECCOMP_DENY_SYSCALL(rt_sigsuspend)
#endif
#ifdef SECCOMP_DENY_sigaltstack
	SECCOMP_DENY_SYSCALL(sigaltstack)
#endif
#ifdef SECCOMP_DENY_utime
	SECCOMP_DENY_SYSCALL(utime)
#endif
#ifdef SECCOMP_DENY_mknod
	SECCOMP_DENY_SYSCALL(mknod)
#endif
#ifdef SECCOMP_DENY_uselib
	SECCOMP_DENY_SYSCALL(uselib)
#endif
#ifdef SECCOMP_DENY_personality
	SECCOMP_DENY_SYSCALL(personality)
#endif
#ifdef SECCOMP_DENY_ustat
	SECCOMP_DENY_SYSCALL(ustat)
#endif
#ifdef SECCOMP_DENY_statfs
	SECCOMP_DENY_SYSCALL(statfs)
#endif
#ifdef SECCOMP_DENY_fstatfs
	SECCOMP_DENY_SYSCALL(fstatfs)
#endif
#ifdef SECCOMP_DENY_sysfs
	SECCOMP_DENY_SYSCALL(sysfs)
#endif
#ifdef SECCOMP_DENY_getpriority
	SECCOMP_DENY_SYSCALL(getpriority)
#endif
#ifdef SECCOMP_DENY_setpriority
	SECCOMP_DENY_SYSCALL(setpriority)
#endif
#ifdef SECCOMP_DENY_sched_setparam
	SECCOMP_DENY_SYSCALL(sched_setparam)
#endif
#ifdef SECCOMP_DENY_sched_getparam
	SECCOMP_DENY_SYSCALL(sched_getparam)
#endif
#ifdef SECCOMP_DENY_sched_setscheduler
	SECCOMP_DENY_SYSCALL(sched_setscheduler)
#endif
#ifdef SECCOMP_DENY_sched_getscheduler
	SECCOMP_DENY_SYSCALL(sched_getscheduler)
#endif
#ifdef SECCOMP_DENY_sched_get_priority_max
	SECCOMP_DENY_SYSCALL(sched_get_priority_max)
#endif
#ifdef SECCOMP_DENY_sched_get_priority_min
	SECCOMP_DENY_SYSCALL(sched_get_priority_min)
#endif
#ifdef SECCOMP_DENY_sched_rr_get_interval
	SECCOMP_DENY_SYSCALL(sched_rr_get_interval)
#endif
#ifdef SECCOMP_DENY_mlock
	SECCOMP_DENY_SYSCALL(mlock)
#endif
#ifdef SECCOMP_DENY_munlock
	SECCOMP_DENY_SYSCALL(munlock)
#endif
#ifdef SECCOMP_DENY_mlockall
	SECCOMP_DENY_SYSCALL(mlockall)
#endif
#ifdef SECCOMP_DENY_munlockall
	SECCOMP_DENY_SYSCALL(munlockall)
#endif
#ifdef SECCOMP_DENY_vhangup
	SECCOMP_DENY_SYSCALL(vhangup)
#endif
#ifdef SECCOMP_DENY_modify_ldt
	SECCOMP_DENY_SYSCALL(modify_ldt)
#endif
#ifdef SECCOMP_DENY_pivot_root
	SECCOMP_DENY_SYSCALL(pivot_root)
#endif
#ifdef SECCOMP_DENY__sysctl
	SECCOMP_DENY_SYSCALL(_sysctl)
#endif
#ifdef SECCOMP_DENY_prctl
	SECCOMP_DENY_SYSCALL(prctl)
#endif
#ifdef SECCOMP_DENY_arch_prctl
	SECCOMP_DENY_SYSCALL(arch_prctl)
#endif
#ifdef SECCOMP_DENY_adjtimex
	SECCOMP_DENY_SYSCALL(adjtimex)
#endif
#ifdef SECCOMP_DENY_setrlimit
	SECCOMP_DENY_SYSCALL(setrlimit)
#endif
#ifdef SECCOMP_DENY_chroot
	SECCOMP_DENY_SYSCALL(chroot)
#endif
#ifdef SECCOMP_DENY_sync
	SECCOMP_DENY_SYSCALL(sync)
#endif
#ifdef SECCOMP_DENY_acct
	SECCOMP_DENY_SYSCALL(acct)
#endif
#ifdef SECCOMP_DENY_settimeofday
	SECCOMP_DENY_SYSCALL(settimeofday)
#endif
#ifdef SECCOMP_DENY_mount
	SECCOMP_DENY_SYSCALL(mount)
#endif
#ifdef SECCOMP_DENY_umount2
	SECCOMP_DENY_SYSCALL(umount2)
#endif
#ifdef SECCOMP_DENY_swapon
	SECCOMP_DENY_SYSCALL(swapon)
#endif
#ifdef SECCOMP_DENY_swapoff
	SECCOMP_DENY_SYSCALL(swapoff)
#endif
#ifdef SECCOMP_DENY_reboot
	SECCOMP_DENY_SYSCALL(reboot)
#endif
#ifdef SECCOMP_DENY_sethostname
	SECCOMP_DENY_SYSCALL(sethostname)
#endif
#ifdef SECCOMP_DENY_setdomainname
	SECCOMP_DENY_SYSCALL(setdomainname)
#endif
#ifdef SECCOMP_DENY_iopl
	SECCOMP_DENY_SYSCALL(iopl)
#endif
#ifdef SECCOMP_DENY_ioperm
	SECCOMP_DENY_SYSCALL(ioperm)
#endif
#ifdef SECCOMP_DENY_create_module
	SECCOMP_DENY_SYSCALL(create_module)
#endif
#ifdef SECCOMP_DENY_init_module
	SECCOMP_DENY_SYSCALL(init_module)
#endif
#ifdef SECCOMP_DENY_delete_module
	SECCOMP_DENY_SYSCALL(delete_module)
#endif
#ifdef SECCOMP_DENY_get_kernel_syms
	SECCOMP_DENY_SYSCALL(get_kernel_syms)
#endif
#ifdef SECCOMP_DENY_query_module
	SECCOMP_DENY_SYSCALL(query_module)
#endif
#ifdef SECCOMP_DENY_quotactl
	SECCOMP_DENY_SYSCALL(quotactl)
#endif
#ifdef SECCOMP_DENY_nfsservctl
	SECCOMP_DENY_SYSCALL(nfsservctl)
#endif
#ifdef SECCOMP_DENY_getpmsg
	SECCOMP_DENY_SYSCALL(getpmsg)
#endif
#ifdef SECCOMP_DENY_putpmsg
	SECCOMP_DENY_SYSCALL(putpmsg)
#endif
#ifdef SECCOMP_DENY_afs_syscall
	SECCOMP_DENY_SYSCALL(afs_syscall)
#endif
#ifdef SECCOMP_DENY_tuxcall
	SECCOMP_DENY_SYSCALL(tuxcall)
#endif
#ifdef SECCOMP_DENY_security
	SECCOMP_DENY_SYSCALL(security)
#endif
#ifdef SECCOMP_DENY_gettid
	SECCOMP_DENY_SYSCALL(gettid)
#endif
#ifdef SECCOMP_DENY_readahead
	SECCOMP_DENY_SYSCALL(readahead)
#endif
#ifdef SECCOMP_DENY_setxattr
	SECCOMP_DENY_SYSCALL(setxattr)
#endif
#ifdef SECCOMP_DENY_lsetxattr
	SECCOMP_DENY_SYSCALL(lsetxattr)
#endif
#ifdef SECCOMP_DENY_fsetxattr
	SECCOMP_DENY_SYSCALL(fsetxattr)
#endif
#ifdef SECCOMP_DENY_getxattr
	SECCOMP_DENY_SYSCALL(getxattr)
#endif
#ifdef SECCOMP_DENY_lgetxattr
	SECCOMP_DENY_SYSCALL(lgetxattr)
#endif
#ifdef SECCOMP_DENY_fgetxattr
	SECCOMP_DENY_SYSCALL(fgetxattr)
#endif
#ifdef SECCOMP_DENY_listxattr
	SECCOMP_DENY_SYSCALL(listxattr)
#endif
#ifdef SECCOMP_DENY_llistxattr
	SECCOMP_DENY_SYSCALL(llistxattr)
#endif
#ifdef SECCOMP_DENY_flistxattr
	SECCOMP_DENY_SYSCALL(flistxattr)
#endif
#ifdef SECCOMP_DENY_removexattr
	SECCOMP_DENY_SYSCALL(removexattr)
#endif
#ifdef SECCOMP_DENY_lremovexattr
	SECCOMP_DENY_SYSCALL(lremovexattr)
#endif
#ifdef SECCOMP_DENY_fremovexattr
	SECCOMP_DENY_SYSCALL(fremovexattr)
#endif
#ifdef SECCOMP_DENY_tkill
	SECCOMP_DENY_SYSCALL(tkill)
#endif
#ifdef SECCOMP_DENY_time
	SECCOMP_DENY_SYSCALL(time)
#endif
#ifdef SECCOMP_DENY_futex
	SECCOMP_DENY_SYSCALL(futex)
#endif
#ifdef SECCOMP_DENY_sched_setaffinity
	SECCOMP_DENY_SYSCALL(sched_setaffinity)
#endif
#ifdef SECCOMP_DENY_sched_getaffinity
	SECCOMP_DENY_SYSCALL(sched_getaffinity)
#endif
#ifdef SECCOMP_DENY_set_thread_area
	SECCOMP_DENY_SYSCALL(set_thread_area)
#endif
#ifdef SECCOMP_DENY_io_setup
	SECCOMP_DENY_SYSCALL(io_setup)
#endif
#ifdef SECCOMP_DENY_io_destroy
	SECCOMP_DENY_SYSCALL(io_destroy)
#endif
#ifdef SECCOMP_DENY_io_getevents
	SECCOMP_DENY_SYSCALL(io_getevents)
#endif
#ifdef SECCOMP_DENY_io_submit
	SECCOMP_DENY_SYSCALL(io_submit)
#endif
#ifdef SECCOMP_DENY_io_cancel
	SECCOMP_DENY_SYSCALL(io_cancel)
#endif
#ifdef SECCOMP_DENY_get_thread_area
	SECCOMP_DENY_SYSCALL(get_thread_area)
#endif
#ifdef SECCOMP_DENY_lookup_dcookie
	SECCOMP_DENY_SYSCALL(lookup_dcookie)
#endif
#ifdef SECCOMP_DENY_epoll_create
	SECCOMP_DENY_SYSCALL(epoll_create)
#endif
#ifdef SECCOMP_DENY_epoll_ctl_old
	SECCOMP_DENY_SYSCALL(epoll_ctl_old)
#endif
#ifdef SECCOMP_DENY_epoll_wait_old
	SECCOMP_DENY_SYSCALL(epoll_wait_old)
#endif
#ifdef SECCOMP_DENY_remap_file_pages
	SECCOMP_DENY_SYSCALL(remap_file_pages)
#endif
#ifdef SECCOMP_DENY_getdents64
	SECCOMP_DENY_SYSCALL(getdents64)
#endif
#ifdef SECCOMP_DENY_set_tid_address
	SECCOMP_DENY_SYSCALL(set_tid_address)
#endif
#ifdef SECCOMP_DENY_restart_syscall
	SECCOMP_DENY_SYSCALL(restart_syscall)
#endif
#ifdef SECCOMP_DENY_semtimedop
	SECCOMP_DENY_SYSCALL(semtimedop)
#endif
#ifdef SECCOMP_DENY_fadvise64
	SECCOMP_DENY_SYSCALL(fadvise64)
#endif
#ifdef SECCOMP_DENY_timer_create
	SECCOMP_DENY_SYSCALL(timer_create)
#endif
#ifdef SECCOMP_DENY_timer_settime
	SECCOMP_DENY_SYSCALL(timer_settime)
#endif
#ifdef SECCOMP_DENY_timer_gettime
	SECCOMP_DENY_SYSCALL(timer_gettime)
#endif
#ifdef SECCOMP_DENY_timer_getoverrun
	SECCOMP_DENY_SYSCALL(timer_getoverrun)
#endif
#ifdef SECCOMP_DENY_timer_delete
	SECCOMP_DENY_SYSCALL(timer_delete)
#endif
#ifdef SECCOMP_DENY_clock_settime
	SECCOMP_DENY_SYSCALL(clock_settime)
#endif
#ifdef SECCOMP_DENY_clock_gettime
	SECCOMP_DENY_SYSCALL(clock_gettime)
#endif
#ifdef SECCOMP_DENY_clock_getres
	SECCOMP_DENY_SYSCALL(clock_getres)
#endif
#ifdef SECCOMP_DENY_clock_nanosleep
	SECCOMP_DENY_SYSCALL(clock_nanosleep)
#endif
#ifdef SECCOMP_DENY_exit_group
	SECCOMP_DENY_SYSCALL(exit_group)
#endif
#ifdef SECCOMP_DENY_epoll_wait
	SECCOMP_DENY_SYSCALL(epoll_wait)
#endif
#ifdef SECCOMP_DENY_epoll_ctl
	SECCOMP_DENY_SYSCALL(epoll_ctl)
#endif
#ifdef SECCOMP_DENY_tgkill
	SECCOMP_DENY_SYSCALL(tgkill)
#endif
#ifdef SECCOMP_DENY_utimes
	SECCOMP_DENY_SYSCALL(utimes)
#endif
#ifdef SECCOMP_DENY_vserver
	SECCOMP_DENY_SYSCALL(vserver)
#endif
#ifdef SECCOMP_DENY_mbind
	SECCOMP_DENY_SYSCALL(mbind)
#endif
#ifdef SECCOMP_DENY_set_mempolicy
	SECCOMP_DENY_SYSCALL(set_mempolicy)
#endif
#ifdef SECCOMP_DENY_get_mempolicy
	SECCOMP_DENY_SYSCALL(get_mempolicy)
#endif
#ifdef SECCOMP_DENY_mq_open
	SECCOMP_DENY_SYSCALL(mq_open)
#endif
#ifdef SECCOMP_DENY_mq_unlink
	SECCOMP_DENY_SYSCALL(mq_unlink)
#endif
#ifdef SECCOMP_DENY_mq_timedsend
	SECCOMP_DENY_SYSCALL(mq_timedsend)
#endif
#ifdef SECCOMP_DENY_mq_timedreceive
	SECCOMP_DENY_SYSCALL(mq_timedreceive)
#endif
#ifdef SECCOMP_DENY_mq_notify
	SECCOMP_DENY_SYSCALL(mq_notify)
#endif
#ifdef SECCOMP_DENY_mq_getsetattr
	SECCOMP_DENY_SYSCALL(mq_getsetattr)
#endif
#ifdef SECCOMP_DENY_kexec_load
	SECCOMP_DENY_SYSCALL(kexec_load)
#endif
#ifdef SECCOMP_DENY_waitid
	SECCOMP_DENY_SYSCALL(waitid)
#endif
#ifdef SECCOMP_DENY_add_key
	SECCOMP_DENY_SYSCALL(add_key)
#endif
#ifdef SECCOMP_DENY_request_key
	SECCOMP_DENY_SYSCALL(request_key)
#endif
#ifdef SECCOMP_DENY_keyctl
	SECCOMP_DENY_SYSCALL(keyctl)
#endif
#ifdef SECCOMP_DENY_ioprio_set
	SECCOMP_DENY_SYSCALL(ioprio_set)
#endif
#ifdef SECCOMP_DENY_ioprio_get
	SECCOMP_DENY_SYSCALL(ioprio_get)
#endif
#ifdef SECCOMP_DENY_inotify_init
	SECCOMP_DENY_SYSCALL(inotify_init)
#endif
#ifdef SECCOMP_DENY_inotify_add_watch
	SECCOMP_DENY_SYSCALL(inotify_add_watch)
#endif
#ifdef SECCOMP_DENY_inotify_rm_watch
	SECCOMP_DENY_SYSCALL(inotify_rm_watch)
#endif
#ifdef SECCOMP_DENY_migrate_pages
	SECCOMP_DENY_SYSCALL(migrate_pages)
#endif
#ifdef SECCOMP_DENY_openat
	SECCOMP_DENY_SYSCALL(openat)
#endif
#ifdef SECCOMP_DENY_mkdirat
	SECCOMP_DENY_SYSCALL(mkdirat)
#endif
#ifdef SECCOMP_DENY_mknodat
	SECCOMP_DENY_SYSCALL(mknodat)
#endif
#ifdef SECCOMP_DENY_fchownat
	SECCOMP_DENY_SYSCALL(fchownat)
#endif
#ifdef SECCOMP_DENY_futimesat
	SECCOMP_DENY_SYSCALL(futimesat)
#endif
#ifdef SECCOMP_DENY_newfstatat
	SECCOMP_DENY_SYSCALL(newfstatat)
#endif
#ifdef SECCOMP_DENY_unlinkat
	SECCOMP_DENY_SYSCALL(unlinkat)
#endif
#ifdef SECCOMP_DENY_renameat
	SECCOMP_DENY_SYSCALL(renameat)
#endif
#ifdef SECCOMP_DENY_linkat
	SECCOMP_DENY_SYSCALL(linkat)
#endif
#ifdef SECCOMP_DENY_symlinkat
	SECCOMP_DENY_SYSCALL(symlinkat)
#endif
#ifdef SECCOMP_DENY_readlinkat
	SECCOMP_DENY_SYSCALL(readlinkat)
#endif
#ifdef SECCOMP_DENY_fchmodat
	SECCOMP_DENY_SYSCALL(fchmodat)
#endif
#ifdef SECCOMP_DENY_faccessat
	SECCOMP_DENY_SYSCALL(faccessat)
#endif
#ifdef SECCOMP_DENY_pselect6
	SECCOMP_DENY_SYSCALL(pselect6)
#endif
#ifdef SECCOMP_DENY_ppoll
	SECCOMP_DENY_SYSCALL(ppoll)
#endif
#ifdef SECCOMP_DENY_unshare
	SECCOMP_DENY_SYSCALL(unshare)
#endif
#ifdef SECCOMP_DENY_set_robust_list
	SECCOMP_DENY_SYSCALL(set_robust_list)
#endif
#ifdef SECCOMP_DENY_get_robust_list
	SECCOMP_DENY_SYSCALL(get_robust_list)
#endif
#ifdef SECCOMP_DENY_splice
	SECCOMP_DENY_SYSCALL(splice)
#endif
#ifdef SECCOMP_DENY_tee
	SECCOMP_DENY_SYSCALL(tee)
#endif
#ifdef SECCOMP_DENY_sync_file_range
	SECCOMP_DENY_SYSCALL(sync_file_range)
#endif
#ifdef SECCOMP_DENY_vmsplice
	SECCOMP_DENY_SYSCALL(vmsplice)
#endif
#ifdef SECCOMP_DENY_move_pages
	SECCOMP_DENY_SYSCALL(move_pages)
#endif
#ifdef SECCOMP_DENY_utimensat
	SECCOMP_DENY_SYSCALL(utimensat)
#endif
#ifdef SECCOMP_DENY_epoll_pwait
	SECCOMP_DENY_SYSCALL(epoll_pwait)
#endif
#ifdef SECCOMP_DENY_signalfd
	SECCOMP_DENY_SYSCALL(signalfd)
#endif
#ifdef SECCOMP_DENY_timerfd_create
	SECCOMP_DENY_SYSCALL(timerfd_create)
#endif
#ifdef SECCOMP_DENY_eventfd
	SECCOMP_DENY_SYSCALL(eventfd)
#endif
#ifdef SECCOMP_DENY_fallocate
	SECCOMP_DENY_SYSCALL(fallocate)
#endif
#ifdef SECCOMP_DENY_timerfd_settime
	SECCOMP_DENY_SYSCALL(timerfd_settime)
#endif
#ifdef SECCOMP_DENY_timerfd_gettime
	SECCOMP_DENY_SYSCALL(timerfd_gettime)
#endif
#ifdef SECCOMP_DENY_accept4
	SECCOMP_DENY_SYSCALL(accept4)
#endif
#ifdef SECCOMP_DENY_signalfd4
	SECCOMP_DENY_SYSCALL(signalfd4)
#endif
#ifdef SECCOMP_DENY_eventfd2
	SECCOMP_DENY_SYSCALL(eventfd2)
#endif
#ifdef SECCOMP_DENY_epoll_create1
	SECCOMP_DENY_SYSCALL(epoll_create1)
#endif
#ifdef SECCOMP_DENY_dup3
	SECCOMP_DENY_SYSCALL(dup3)
#endif
#ifdef SECCOMP_DENY_pipe2
	SECCOMP_DENY_SYSCALL(pipe2)
#endif
#ifdef SECCOMP_DENY_inotify_init1
	SECCOMP_DENY_SYSCALL(inotify_init1)
#endif
#ifdef SECCOMP_DENY_preadv
	SECCOMP_DENY_SYSCALL(preadv)
#endif
#ifdef SECCOMP_DENY_pwritev
	SECCOMP_DENY_SYSCALL(pwritev)
#endif
#ifdef SECCOMP_DENY_rt_tgsigqueueinfo
	SECCOMP_DENY_SYSCALL(rt_tgsigqueueinfo)
#endif
#ifdef SECCOMP_DENY_perf_event_open
	SECCOMP_DENY_SYSCALL(perf_event_open)
#endif
#ifdef SECCOMP_DENY_recvmmsg
	SECCOMP_DENY_SYSCALL(recvmmsg)
#endif
#ifdef SECCOMP_DENY_fanotify_init
	SECCOMP_DENY_SYSCALL(fanotify_init)
#endif
#ifdef SECCOMP_DENY_fanotify_mark
	SECCOMP_DENY_SYSCALL(fanotify_mark)
#endif
#ifdef SECCOMP_DENY_prlimit64
	SECCOMP_DENY_SYSCALL(prlimit64)
#endif
#ifdef SECCOMP_DENY_name_to_handle_at
	SECCOMP_DENY_SYSCALL(name_to_handle_at)
#endif
#ifdef SECCOMP_DENY_open_by_handle_at
	SECCOMP_DENY_SYSCALL(open_by_handle_at)
#endif
#ifdef SECCOMP_DENY_clock_adjtime
	SECCOMP_DENY_SYSCALL(clock_adjtime)
#endif
#ifdef SECCOMP_DENY_syncfs
	SECCOMP_DENY_SYSCALL(syncfs)
#endif
#ifdef SECCOMP_DENY_sendmmsg
	SECCOMP_DENY_SYSCALL(sendmmsg)
#endif
#ifdef SECCOMP_DENY_setns
	SECCOMP_DENY_SYSCALL(setns)
#endif
#ifdef SECCOMP_DENY_getcpu
	SECCOMP_DENY_SYSCALL(getcpu)
#endif
#ifdef SECCOMP_DENY_process_vm_readv
	SECCOMP_DENY_SYSCALL(process_vm_readv)
#endif
#ifdef SECCOMP_DENY_process_vm_writev
	SECCOMP_DENY_SYSCALL(process_vm_writev)
#endif
#ifdef SECCOMP_DENY_kcmp
	SECCOMP_DENY_SYSCALL(kcmp)
#endif
#ifdef SECCOMP_DENY_finit_module
	SECCOMP_DENY_SYSCALL(finit_module)
#endif
#ifdef SECCOMP_DENY_sched_setattr
	SECCOMP_DENY_SYSCALL(sched_setattr)
#endif
#ifdef SECCOMP_DENY_sched_getattr
	SECCOMP_DENY_SYSCALL(sched_getattr)
#endif
#ifdef SECCOMP_DENY_renameat2
	SECCOMP_DENY_SYSCALL(renameat2)
#endif
#ifdef SECCOMP_DENY_seccomp
	SECCOMP_DENY_SYSCALL(seccomp)
#endif
#ifdef SECCOMP_DENY_getrandom
	SECCOMP_DENY_SYSCALL(getrandom)
#endif
#ifdef SECCOMP_DENY_memfd_create
	SECCOMP_DENY_SYSCALL(memfd_create)
#endif
#ifdef SECCOMP_DENY_kexec_file_load
	SECCOMP_DENY_SYSCALL(kexec_file_load)
#endif
#ifdef SECCOMP_DENY_bpf
	SECCOMP_DENY_SYSCALL(bpf)
#endif
