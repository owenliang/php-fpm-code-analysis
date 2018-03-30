# PHP-FPM源码分析
## 入口文件

```
fpm/fpm/fpm_main.c


int main(int argc, char *argv[]) {

 ...
 ...

	// 初始化
	if (0 > fpm_init(argc, argv, fpm_config ? fpm_config : CGIG(fpm_config), fpm_prefix, fpm_pid, test_conf, php_allow_to_run_as_root, force_daemon, force_stderr)) {

		if (fpm_globals.send_config_pipe[1]) {
			int writeval = 0;
			zlog(ZLOG_DEBUG, "Sending \"0\" (error) to parent via fd=%d", fpm_globals.send_config_pipe[1]);
			zend_quiet_write(fpm_globals.send_config_pipe[1], &writeval, sizeof(writeval));
			close(fpm_globals.send_config_pipe[1]);
		}
		return FPM_EXIT_CONFIG;
	}

	if (fpm_globals.send_config_pipe[1]) {
		int writeval = 1;
		zlog(ZLOG_DEBUG, "Sending \"1\" (OK) to parent via fd=%d", fpm_globals.send_config_pipe[1]);
		zend_quiet_write(fpm_globals.send_config_pipe[1], &writeval, sizeof(writeval));
		close(fpm_globals.send_config_pipe[1]);
	}
	fpm_is_running = 1;

	// 这里父进程创建监听，进入自己的循环
	fcgi_fd = fpm_run(&max_requests); // fcgi_id就是监听socket

	// 子进程继续向下执行
	parent = 0;
```

## 初始化阶段

```
fpm/fpm/fpm.c


int fpm_init(int argc, char **argv, char *config, char *prefix, char *pid, int test_conf, int run_as_root, int force_daemon, int force_stderr) /* {{{ */
{
	if (0 > fpm_php_init_main()           ||
	    0 > fpm_stdio_init_main()         ||
	    0 > fpm_conf_init_main(test_conf, force_daemon) ||
	    0 > fpm_unix_init_main()          ||
	    0 > fpm_scoreboard_init_main()    ||
	    0 > fpm_pctl_init_main()          ||
	    0 > fpm_env_init_main()           ||
	    0 > fpm_signals_init_main()       ||
	    0 > fpm_children_init_main()      ||
	    0 > fpm_sockets_init_main()       ||
	    0 > fpm_worker_pool_init_main()   ||
	    0 > fpm_event_init_main()) {

		if (fpm_globals.test_successful) {
			exit(FPM_EXIT_OK);
		} else {
			zlog(ZLOG_ERROR, "FPM initialization failed");
			return -1;
		}
	}
```

初始化一些程序结构：配置、记分板、工作池（监听套接字，子进程管理）、事件循环...在此不做具体展开。

关键点就是创建了监听socket，后续子进程需要继承并监听。

## 启动阶段

 
### 整体流程

```

fpm/fpm/fpm.c


int fpm_run(int *max_requests) /* {{{ */
{
	struct fpm_worker_pool_s *wp;

	/* create initial children in all pools */

	// 所有的池子
	for (wp = fpm_worker_all_pools; wp; wp = wp->next) {
		int is_parent;

		is_parent = fpm_children_create_initial(wp);

		if (!is_parent) {
			goto run_child;
		}

		/* handle error */
		if (is_parent == 2) { // 创建子进程失败
			fpm_pctl(FPM_PCTL_STATE_TERMINATING, FPM_PCTL_ACTION_SET);
			fpm_event_loop(1);
		}
	}

	/* run event loop forever */

	// 父进程循环
	fpm_event_loop(0);

	// 子进程继续向下执行
run_child: /* only workers reach this point */

	fpm_cleanups_run(FPM_CLEANUP_CHILD);

	*max_requests = fpm_globals.max_requests;
	return fpm_globals.listening_socket;
}

```

### 初始化池子

对于每个池子（php-fpm.conf里配置的work pool），调用fpm_children_create_initial初始化若干子进程。

因为work pool有不同的进程管理策略，所以初始化进程的数量和方式各有差异。

```

fpm/fpm/fpm_children.c


int fpm_children_create_initial(struct fpm_worker_pool_s *wp) /* {{{ */
{
	// 按需分配的进程管理模式，实际上是父进程监听listen socket可读则认为可能需要更多的子进程来处理请求
	if (wp->config->pm == PM_STYLE_ONDEMAND) {
		wp->ondemand_event = (struct fpm_event_s *)malloc(sizeof(struct fpm_event_s));

		if (!wp->ondemand_event) {
			zlog(ZLOG_ERROR, "[pool %s] unable to malloc the ondemand socket event", wp->config->name);
			// FIXME handle crash
			return 1;
		}

		memset(wp->ondemand_event, 0, sizeof(struct fpm_event_s));
		fpm_event_set(wp->ondemand_event, wp->listening_socket, FPM_EV_READ | FPM_EV_EDGE, fpm_pctl_on_socket_accept, wp);
		wp->socket_event_set = 1;
		fpm_event_add(wp->ondemand_event, 0);

		return 1;
	}

	// 其他进程管理模式直接初始化，比如static模式直接拉起指定数量的子进程，dynamic模式拉起最小数量的子进程
	return fpm_children_make(wp, 0 /* not in event loop yet */, 0, 1);
}

```

### 创建子进程

fpm_children_make用于为池子扩容子进程数量，初始化阶段in_event_loop传0，从而只启动有限数量的子进程，相关策略在代码中有注释说明。

```
fpm/fpm/fpm_children.c


	// 创建N个子进程
int fpm_children_make(struct fpm_worker_pool_s *wp, int in_event_loop, int nb_to_spawn, int is_debug) /* {{{ */
{
	pid_t pid;
	struct fpm_child_s *child;
	int max;
	static int warned = 0;

	if (wp->config->pm == PM_STYLE_DYNAMIC) {
		if (!in_event_loop) { /* starting */
			max = wp->config->pm_start_servers;
		} else {
			max = wp->running_children + nb_to_spawn;
		}
	} else if (wp->config->pm == PM_STYLE_ONDEMAND) {
		if (!in_event_loop) { /* starting */
			max = 0; /* do not create any child at startup */
		} else {
			max = wp->running_children + nb_to_spawn;
		}
	} else { /* PM_STYLE_STATIC */
		max = wp->config->pm_max_children;
	}

	/*
	 * fork children while:
	 *   - fpm_pctl_can_spawn_children : FPM is running in a NORMAL state (aka not restart, stop or reload)
	 *   - wp->running_children < max  : there is less than the max process for the current pool
	 *   - (fpm_global_config.process_max < 1 || fpm_globals.running_children < fpm_global_config.process_max):
	 *     if fpm_global_config.process_max is set, FPM has not fork this number of processes (globaly)
	 */
	while (fpm_pctl_can_spawn_children() && wp->running_children < max && (fpm_global_config.process_max < 1 || fpm_globals.running_children < fpm_global_config.process_max)) {

		warned = 0;

		// 创建一个child对象，分配对应的记分板槽
		child = fpm_resources_prepare(wp);

		if (!child) {
			return 2;
		}

		pid = fork();

		switch (pid) {

			case 0 : // 子进程
				fpm_child_resources_use(child);
				fpm_globals.is_child = 1;
				fpm_child_init(wp);
				return 0;

			case -1 :
				zlog(ZLOG_SYSERROR, "fork() failed");

				fpm_resources_discard(child);
				return 2;

			default :
				// 父进程
				child->pid = pid;
				fpm_clock_get(&child->started);
				fpm_parent_resources_use(child);

				zlog(is_debug ? ZLOG_DEBUG : ZLOG_NOTICE, "[pool %s] child %d started", wp->config->name, (int) pid);
		}

	}

	if (!warned && fpm_global_config.process_max > 0 && fpm_globals.running_children >= fpm_global_config.process_max) {
               if (wp->running_children < max) {
                       warned = 1;
                       zlog(ZLOG_WARNING, "The maximum number of processes has been reached. Please review your configuration and consider raising 'process.max'");
               }
	}

	return 1; /* we are done */
}
```

### 准备创建子进程
 
创建子进程，需要在父进程关联一些数据结构记录其信息。

另外，需要创建一个Pipe，子进程会把自己标准输出和错误输出定向到pipe[1]，这样父进程就可以捕获子进程的输出了。

其中fpm_resources_prepare就是这样一个函数：

```

fpm/fpm/fpm_children.c


static struct fpm_child_s *fpm_resources_prepare(struct fpm_worker_pool_s *wp) /* {{{ */
{
	struct fpm_child_s *c;

	c = fpm_child_alloc();

	if (!c) {
		zlog(ZLOG_ERROR, "[pool %s] unable to malloc new child", wp->config->name);
		return 0;
	}

	c->wp = wp;
	c->fd_stdout = -1; c->fd_stderr = -1;

	if (0 > fpm_stdio_prepare_pipes(c)) {
		fpm_child_free(c);
		return 0;
	}

	if (0 > fpm_scoreboard_proc_alloc(wp->scoreboard, &c->scoreboard_i)) {
		fpm_stdio_discard_pipes(c);
		fpm_child_free(c);
		return 0;
	}

	return c;
}

```

### 共享内存 记分板

上面代码还分配了一个scoreboard记分板，这是PHP-FPM进行进程管理非常关键的组件。

每个池子都有一个scoreboard对象，里面为每个子进程准备了一个scoreboard_proc对象。

scoreboard和scoreboard_proc对象在父进程中从共享内存里分配，在父子进程间共享访问，通过atomic原子变量实现spinlock自旋锁，确保多进程并发访问的安全性。

```
fpm/fpm/fpm_scoreboard.h


	//  每个子进程有一个小记分板
struct fpm_scoreboard_proc_s {
	union {
		atomic_t lock; // 保护该对象的自旋锁
		char dummy[16];
	};
	int used;
	time_t start_epoch;
	pid_t pid;
	unsigned long requests;
	enum fpm_request_stage_e request_stage;
	struct timeval accepted;
	struct timeval duration;
	time_t accepted_epoch;
	struct timeval tv;
	char request_uri[128];
	char query_string[512];
	char request_method[16];
	size_t content_length; /* used with POST only */
	char script_filename[256];
	char auth_user[32];
#ifdef HAVE_TIMES
	struct tms cpu_accepted;
	struct timeval cpu_duration;
	struct tms last_request_cpu;
	struct timeval last_request_cpu_duration;
#endif
	size_t memory;
};

	// 每个池子一个大记分板
struct fpm_scoreboard_s {
	union {
		atomic_t lock; // 保护大记分板的自旋锁
		char dummy[16];
	};
	char pool[32];
	int pm;
	time_t start_epoch;
	int idle;
	int active;
	int active_max;
	unsigned long int requests;
	unsigned int max_children_reached;
	int lq;
	int lq_max;
	unsigned int lq_len;
	unsigned int nprocs;
	int free_proc;
	unsigned long int slow_rq;
	struct fpm_scoreboard_proc_s *procs[]; // 池子内每个进程有一个小记分板
};

```

还记得本文最开始初始化中的fpm_scoreboard_init_main吗？

```
fpm/fpm/fpm_scoreboard.c


int fpm_scoreboard_init_main() /* {{{ */
{
	struct fpm_worker_pool_s *wp;
	unsigned int i;

#ifdef HAVE_TIMES
#if (defined(HAVE_SYSCONF) && defined(_SC_CLK_TCK))
	fpm_scoreboard_tick = sysconf(_SC_CLK_TCK);
#else /* _SC_CLK_TCK */
#ifdef HZ
	fpm_scoreboard_tick = HZ;
#else /* HZ */
	fpm_scoreboard_tick = 100;
#endif /* HZ */
#endif /* _SC_CLK_TCK */
	zlog(ZLOG_DEBUG, "got clock tick '%.0f'", fpm_scoreboard_tick);
#endif /* HAVE_TIMES */


	for (wp = fpm_worker_all_pools; wp; wp = wp->next) {
		size_t scoreboard_size, scoreboard_nprocs_size;
		void *shm_mem;

		if (wp->config->pm_max_children < 1) {
			zlog(ZLOG_ERROR, "[pool %s] Unable to create scoreboard SHM because max_client is not set", wp->config->name);
			return -1;
		}

		if (wp->scoreboard) {
			zlog(ZLOG_ERROR, "[pool %s] Unable to create scoreboard SHM because it already exists", wp->config->name);
			return -1;
		}

		scoreboard_size        = sizeof(struct fpm_scoreboard_s) + (wp->config->pm_max_children) * sizeof(struct fpm_scoreboard_proc_s *);
		scoreboard_nprocs_size = sizeof(struct fpm_scoreboard_proc_s) * wp->config->pm_max_children;
		shm_mem                = fpm_shm_alloc(scoreboard_size + scoreboard_nprocs_size);

		if (!shm_mem) {
			return -1;
		}
		wp->scoreboard         = shm_mem;
		wp->scoreboard->nprocs = wp->config->pm_max_children;
		shm_mem               += scoreboard_size;

		for (i = 0; i < wp->scoreboard->nprocs; i++, shm_mem += sizeof(struct fpm_scoreboard_proc_s)) {
			wp->scoreboard->procs[i] = shm_mem;
		}

		wp->scoreboard->pm          = wp->config->pm;
		wp->scoreboard->start_epoch = time(NULL);
		strlcpy(wp->scoreboard->pool, wp->config->name, sizeof(wp->scoreboard->pool));
	}
	return 0;
}
```

可见，FPM为每个池子，一次性分配了足够最多子进程用的记分板内存空间，而且是通过共享内存分配的，这样子进程可以和父进程共享这块信息：

```
fpm/fpm/fpm_shm.c


void *fpm_shm_alloc(size_t size) /* {{{ */
{
	void *mem;

	mem = mmap(0, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);

#ifdef MAP_FAILED
	if (mem == MAP_FAILED) {
		zlog(ZLOG_SYSERROR, "unable to allocate %zu bytes in shared memory: %s", size, strerror(errno));
		return NULL;
	}
#endif

	if (!mem) {
		zlog(ZLOG_SYSERROR, "unable to allocate %zu bytes in shared memory", size);
		return NULL;
	}

	fpm_shm_size += size;
	return mem;
}
```

通过mmap的MAP_ANONY|MAP_SHARED做匿名共享内存。

至于多进程访问的安全性，是依靠atomic_t原子变量与atomic_cmp_set这样的原子操作实现了自旋锁，整个函数是内联的：

```
fpm/fpm/fpm_atomic.h


static inline int fpm_spinlock(atomic_t *lock, int try_once) /* {{{ */
{
	if (try_once) {
		return atomic_cmp_set(lock, 0, 1) ? 1 : 0;
	}

	for (;;) {

		if (atomic_cmp_set(lock, 0, 1)) {
			break;
		}

		sched_yield();
	}

	return 1;
}

```

sched_yield是为了让出CPU，避免空转等锁对CPU占用过高。

## 执行阶段


### 子进程进入阻塞循环

fpm_children_create_initial函数返回0表示子进程，则返回到fpm_run的调用处，也就是main函数里。

```
fpm/fpm/fpm_main.c


	zend_first_try {
		// accept监听套接字，获得一个连接socket
		while (EXPECTED(fcgi_accept_request(request) >= 0)) {
			char *primary_script = NULL;
			request_body_fd = -1;
			SG(server_context) = (void *) request;
			init_request_info();

			fpm_request_info();

			// 初始化PHP执行环境

			....
			
			...
```

子进程是阻塞循环，同一时刻只能处理一个连接。

关于PHP解释器如何初始化环境属于另外一个话题，下面是关键代码：

```
fpm/fpm/fpm_main.c

	// 打开PHP文件
			/* path_translated exists, we can continue ! */
			if (UNEXPECTED(php_fopen_primary_script(&file_handle) == FAILURE)) {
				zend_try {
					zlog(ZLOG_ERROR, "Unable to open primary script: %s (%s)", primary_script, strerror(errno));
					if (errno == EACCES) {
						SG(sapi_headers).http_response_code = 403;
						PUTS("Access denied.\n");
					} else {
						SG(sapi_headers).http_response_code = 404;
						PUTS("No input file specified.\n");
					}
				} zend_catch {
				} zend_end_try();
				/* we want to serve more requests if this is fastcgi
				 * so cleanup and continue, request shutdown is
				 * handled later */

				goto fastcgi_request_done;
			}

			// 在共享内存里更新记分板信息， 也就是request开始处理的时间之类的
			fpm_request_executing();

			// 执行PHP脚本
			php_execute_script(&file_handle);

```

要执行PHP文件首先要找到对应的文件，然后加载一下，最后交给php_execute_script来解释执行。

在执行前有一个很重要的操作，是更新记分板信息，主要是记录该子进程什么时候开始处理的请求，请求的一些基本信息是什么。

这些信息对于父进程很重要，父进程根据记分板里的信息就可以知道子进程的运行情况。

```
fpm/fpm/fpm_request.c


void fpm_request_executing() /* {{{ */
{
	struct fpm_scoreboard_proc_s *proc;
	struct timeval now;

	fpm_clock_get(&now);

	proc = fpm_scoreboard_proc_acquire(NULL, -1, 0);
	if (proc == NULL) {
		zlog(ZLOG_WARNING, "failed to acquire proc scoreboard");
		return;
	}

	proc->request_stage = FPM_REQUEST_EXECUTING;
	proc->tv = now;
	fpm_scoreboard_proc_release(proc);
}
```

先获得该进程记分板对象的锁，然后更新状态为执行中，时间点是now，然后释放锁。

因为记分板是共享内存的，父进程是可以随时去查看的。

```
fpm/fpm/fpm_main.c


			// 记分板更新请求结束
			fpm_request_end();
			fpm_log_write(NULL);

			efree(SG(request_info).path_translated);
			SG(request_info).path_translated = NULL;

			// 清理PHP执行环境的东西
			php_request_shutdown((void *) 0);

			// 连续处理request超过一定数量，进程退出
			requests++;
			if (UNEXPECTED(max_requests && (requests == max_requests))) {
				fcgi_request_set_keep(request, 0);
				fcgi_finish_request(request, 0);
				break;
			}

```

当PHP脚本执行完成后，需要fpm_request_end更新记分板请求结束，做一些状态更新，就不展开了。

php_request_shutdown清理PHP执行环境，不需要展开。

下面是判断该子进程已经累计处理的请求数量，超过配置的阀值就会break退出accept loop，退出main函数结束自己的生命。这个配置项我们一般都会使用，主要是防止扩展或者PHP自身有内存泄露之类的BUG，所以定期退出一下。

### 父进程进入事件循环

fpm_children_create_initial函数在初始化子进程后，父进程返回1，然后进入事件循环。

通常linux事件循环基于epoll实现，这里调用fpm_event_loop函数进入循环。

父进程循环主要是在对子进程进行管理，比如关闭空闲的子进程，或者启动更多的子进程。

另外一方面也需要监听来自命令行管理员的一些信号，比如重新加载配置，重新启动进程等。

```
fpm/fpm/fpm_event.c


// master事件循环
void fpm_event_loop(int err) /* {{{ */
{
	static struct fpm_event_s signal_fd_event;

	/* sanity check */
	if (fpm_globals.parent_pid != getpid()) {
		return;
	}

	// 有个pipe注册到event loop上，每次有信号触发就会写到pipe
	fpm_event_set(&signal_fd_event, fpm_signals_get_fd(), FPM_EV_READ, &fpm_got_signal, NULL);
	fpm_event_add(&signal_fd_event, 0);

	/* add timers */
	if (fpm_globals.heartbeat > 0) {

		// 创建定时器，周期性检查子进程是否执行过慢，或者超时，杀死超时进程
		fpm_pctl_heartbeat(NULL, 0, NULL);
	}

	if (!err) {

		// 创建定时器，周期性根据策略，缩减或者扩增子进程
		fpm_pctl_perform_idle_server_maintenance_heartbeat(NULL, 0, NULL);

		zlog(ZLOG_DEBUG, "%zu bytes have been reserved in SHM", fpm_shm_get_size_allocated());
		zlog(ZLOG_NOTICE, "ready to handle connections");

#ifdef HAVE_SYSTEMD
		fpm_systemd_heartbeat(NULL, 0, NULL);
#endif
	}
	
	...
	...

```

在正式进入事件循环之前，会先对信号处理做一些筹备。

因为管理员可以命令行向php-fpm发送控制信号（kill -xxx），另外子进程退出会向父进程发送SIGCHLD信号，主要就是这两个行为。

这里fpm_event_set,fpm_event_add都是在操作epoll，就不展开说明了。

php-fpm在初始化时就分配了一个unix socket pair，这里把socket[0]注册在epoll上监听，socket读事件的回调函数是fpm_got_signal。

php-fpm在初始化阶段就注册了信号处理函数，当fpm父进程收到信号后不会直接处理信号，而是将信号标识写入到socket[1]里，这样就会触发epoll监听到事件。

### 信号处理函数

fpm在初始化时这样注册了信号处理函数：
```
fpm/fpm/fpm_signals.c


	// 父进程的信号处理注册
int fpm_signals_init_main() /* {{{ */
{
	struct sigaction act;

	// 创建一对双向双工unix socket pair

	if (0 > socketpair(AF_UNIX, SOCK_STREAM, 0, sp)) {
		zlog(ZLOG_SYSERROR, "failed to init signals: socketpair()");
		return -1;
	}

	if (0 > fd_set_blocked(sp[0], 0) || 0 > fd_set_blocked(sp[1], 0)) {
		zlog(ZLOG_SYSERROR, "failed to init signals: fd_set_blocked()");
		return -1;
	}

	if (0 > fcntl(sp[0], F_SETFD, FD_CLOEXEC) || 0 > fcntl(sp[1], F_SETFD, FD_CLOEXEC)) {
		zlog(ZLOG_SYSERROR, "falied to init signals: fcntl(F_SETFD, FD_CLOEXEC)");
		return -1;
	}

	memset(&act, 0, sizeof(act));
	act.sa_handler = sig_handler; // 收到信号，就写到unix socket里，触发主事件循环进一步处理
	sigfillset(&act.sa_mask);

	// 来自命令行的杀死信号，来自子进程的退出信号都是重点
	if (0 > sigaction(SIGTERM,  &act, 0) ||
	    0 > sigaction(SIGINT,   &act, 0) ||
	    0 > sigaction(SIGUSR1,  &act, 0) ||
	    0 > sigaction(SIGUSR2,  &act, 0) ||
	    0 > sigaction(SIGCHLD,  &act, 0) ||
	    0 > sigaction(SIGQUIT,  &act, 0)) {

		zlog(ZLOG_SYSERROR, "failed to init signals: sigaction()");
		return -1;
	}
	return 0;
}
```

它首先创建了之前说的unix socket pair用来作为信号处理函数与epoll之间的通讯机制。

之后它注册了SIGTERM,SIGINT,SIGUSR1,SIGCHLD...等等信号处理函数到同一个方法：sig_handler。


```
fpm/fpm/fpm_signals.c


static void sig_handler(int signo) /* {{{ */
{
	static const char sig_chars[NSIG + 1] = {
		[SIGTERM] = 'T',
		[SIGINT]  = 'I',
		[SIGUSR1] = '1',
		[SIGUSR2] = '2',
		[SIGQUIT] = 'Q',
		[SIGCHLD] = 'C'
	};
	char s;
	int saved_errno;

	if (fpm_globals.parent_pid != getpid()) {
		/* prevent a signal race condition when child process
			have not set up it's own signal handler yet */
		return;
	}

	saved_errno = errno;
	s = sig_chars[signo];
	zend_quiet_write(sp[1], &s, sizeof(s)); // 写入信号对应的标识
	errno = saved_errno;
}
```

该函数根据信号的类型映射到一个1字节的内部信号标识，然后写入到socket[1]里。

这一步其实有点问题在于，万一socket写满了呢？ 这里并没有关注这个问题，因为一般fpm是足够快的可以处理socket里的事件的。

### 处理信号事件

当socket[1]写入事件标识后，epoll回调到注册的函数fpm_got_signal中。



```
fpm/fpm/fpm_events.c


	// 有信号发来时的事件回调函数
static void fpm_got_signal(struct fpm_event_s *ev, short which, void *arg) /* {{{ */
{
	char c;
	int res, ret;
	int fd = ev->fd;

	do {
		do {
			res = read(fd, &c, 1);
		} while (res == -1 && errno == EINTR);

		if (res <= 0) {
			if (res < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
				zlog(ZLOG_SYSERROR, "unable to read from the signal pipe");
			}
			return;
		}

		switch (c) {

			// 收到子进程的退出信号
			case 'C' :                  /* SIGCHLD */
				zlog(ZLOG_DEBUG, "received SIGCHLD");
				fpm_children_bury();
				break;
			case 'I' :                  /* SIGINT  */
				zlog(ZLOG_DEBUG, "received SIGINT");
				zlog(ZLOG_NOTICE, "Terminating ...");
				fpm_pctl(FPM_PCTL_STATE_TERMINATING, FPM_PCTL_ACTION_SET);
				break;
			case 'T' :                  /* SIGTERM */
				zlog(ZLOG_DEBUG, "received SIGTERM");
				zlog(ZLOG_NOTICE, "Terminating ...");
				fpm_pctl(FPM_PCTL_STATE_TERMINATING, FPM_PCTL_ACTION_SET);
				break;
			case 'Q' :                  /* SIGQUIT */
				zlog(ZLOG_DEBUG, "received SIGQUIT");
				zlog(ZLOG_NOTICE, "Finishing ...");
				fpm_pctl(FPM_PCTL_STATE_FINISHING, FPM_PCTL_ACTION_SET);
				break;
			case '1' :                  /* SIGUSR1 */
				zlog(ZLOG_DEBUG, "received SIGUSR1");
				if (0 == fpm_stdio_open_error_log(1)) {
					zlog(ZLOG_NOTICE, "error log file re-opened");
				} else {
					zlog(ZLOG_ERROR, "unable to re-opened error log file");
				}

				ret = fpm_log_open(1);
				if (ret == 0) {
					zlog(ZLOG_NOTICE, "access log file re-opened");
				} else if (ret == -1) {
					zlog(ZLOG_ERROR, "unable to re-opened access log file");
				}
				/* else no access log are set */

				break;
			case '2' :                  /* SIGUSR2 */
				zlog(ZLOG_DEBUG, "received SIGUSR2");
				zlog(ZLOG_NOTICE, "Reloading in progress ...");
				fpm_pctl(FPM_PCTL_STATE_RELOADING, FPM_PCTL_ACTION_SET);
				break;
		}

		if (fpm_globals.is_child) {
			break;
		}
	} while (1);
	return;
}

```

该函数对不同的信号做不同的响应。

例如SIGINT/SIGTERM/SIGQUIT都是来自命令行发来的退出信号，需要清理子进程然后退出，这个细节不是很重要，就不展开了。

重点在于SIGCHLD信号的处理，它表示子进程退出了或者暂停了，对父进程的子进程管理非常重要。

### 处理子进程事件

fpm_children_bury()用于处理子进程事件，它一方面要waitpid回收子进程的资源，防止出现僵尸进程；另一方面是更新进程管理的状态，因为少了一个子进程，后续进程管理策略就可能新建子进程。

```
fpm/fpm/fpm_children.c


这里循环回收退出的子进程资源，一直循环到没有更多子进程可以回收为止：

void fpm_children_bury() /* {{{ */
{
	int status;
	pid_t pid;
	struct fpm_child_s *child;

	// 循环回收子进程资源，直到没有更多
	while ( (pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
		char buf[128];
		int severity = ZLOG_NOTICE;
		int restart_child = 1;

		// 根据子进程PID找到对应的child对象
		child = fpm_child_find(pid);


```

根据waitpid返回的子进程pid，就可以找到对应的child对象，里面维护了描述子进程的一些信息，由父进程管理。

当收到SIGCHLD信号时，我们可以根据waitpid第二个status参数获知进程是如何退出的。

### 子进程正常退出

```
fpm/fpm/fpm_children.c


		if (WIFEXITED(status)) { // 正常退出

			snprintf(buf, sizeof(buf), "with code %d", WEXITSTATUS(status));

			/* if it's been killed because of dynamic process management
			 * don't restart it automaticaly
			 */
			if (child && child->idle_kill) {
				restart_child = 0;
			}

			if (WEXITSTATUS(status) != FPM_EXIT_OK) {
				severity = ZLOG_WARNING;
			}

		} 
		
```

如果是正常退出，那么说明子进程是通过main函数return或者exit方法退出的。

这种情况下，其实还需要区分是子进程自己主动退出的，还是父进程让它退出的。

所以child->idle_kill做了一次判断，因为父进程若主动杀死子进程，那么会先在child对象里做一下idle_kill的标记再向子进程发送杀死信号。

这个判定决定了是否要立即重启子进程，若不是父进程责令其退出，那么就是意外退出，需要立即拉起。

### 子进程被信号杀死

这个场景非常类似于正常退出，当进程收到某些信号时默认的行为就是退出，比如SIGKILL强制杀死，SIGSEGV段错误，SIGBUS总线错误，SIGQUIT退出 等等..

这种情况下会区分一下是否是段错误等严重错误，一般预示着PHP内核或者扩展代码有问题导致coredump。

```
fpm/fpm/fpm_children.c


else if (WIFSIGNALED(status)) { // 被信号杀死
			const char *signame = fpm_signal_names[WTERMSIG(status)];
			const char *have_core = WCOREDUMP(status) ? " - core dumped" : "";

			if (signame == NULL) {
				signame = "";
			}

			snprintf(buf, sizeof(buf), "on signal %d (%s%s)", WTERMSIG(status), signame, have_core);

			/* if it's been killed because of dynamic process management
			 * don't restart it automaticaly
			 */
			if (child && child->idle_kill && WTERMSIG(status) == SIGQUIT) {
				restart_child = 0;
			}

			if (WTERMSIG(status) != SIGQUIT) { /* possible request loss */
				severity = ZLOG_WARNING;
			}
		}
```

### 子进程暂停

子进程收到SIGSTOP信号就会暂停执行，此时父进程会收到SIGCHLD信号，并且status中标识了子进程是STOP状态。


```
fpm/fpm/fpm_children.c


else if (WIFSTOPPED(status)) {	// slowlog时ptrace子进程，导致子进程STOP暂停

			zlog(ZLOG_NOTICE, "child %d stopped for tracing", (int) pid);

			if (child && child->tracer) {
				// 获取子进程的信息，打印到slowlog日志，然后恢复子进程
				child->tracer(child);
			}

			continue;
		}
		
```

那么谁会给子进程发送STOP信号呢？ 这里先简单提一下，就是当父进程发现子进程处理一个请求超时后，就会调用ptrace去attach到子进程，这个操作就会导致子进程STOP。

一旦ptrace导致子进程STOP，那么父进程就会收到SIGCHLD，从而进入上述逻辑分支。

父进程要做的，就是利用ptrace的其他能力，直接去访问子进程的地址空间，获取一些堆栈信息，从而获知子进程到底卡在哪里。

而上述所说的ptrace逻辑，实际上就是为了打印slowlog，也就是当父进程发现子进程执行慢，就利用ptrace去抓子进程的栈空间，从而打印出一个调用栈到slowlog日志文件中，帮助我们分析问题，这个原理和gdb调试程序是类似的。

当然，child->tracer除了利用Ptrace去抓子进程的堆栈之后，会向子进程发送一个SIGCONT信号，让子进程恢复运行，相关代码在后面会提及。

### 回收子进程资源

如果子进程是退出而不是暂停了，那么就要在父进程里清理相关的进程信息与资源。

```
fpm/fpm/fpm_children.c


	// 子进程退出，那么清理父进程里关联的各种内存
		if (child) {
			struct fpm_worker_pool_s *wp = child->wp;
			struct timeval tv1, tv2;

			fpm_child_unlink(child);

			fpm_scoreboard_proc_free(wp->scoreboard, child->scoreboard_i);

			fpm_clock_get(&tv1);

			timersub(&tv1, &child->started, &tv2);
```

例如上述清理了记分板资源，等等...

### 严重错误重启自身

```
fpm/fpm/fpm_children.c


			if (last_faults && (WTERMSIG(status) == SIGSEGV || WTERMSIG(status) == SIGBUS)) {
				time_t now = tv1.tv_sec;
				int restart_condition = 1;
				int i;

				last_faults[fault++] = now;

				if (fault == fpm_global_config.emergency_restart_threshold) {
					fault = 0;
				}

				for (i = 0; i < fpm_global_config.emergency_restart_threshold; i++) {
					if (now - last_faults[i] > fpm_global_config.emergency_restart_interval) {
						restart_condition = 0;
						break;
					}
				}

				// COREDUMP太多，决定重启php-fpm，也就是直接execv执行php-fpm自身
				if (restart_condition) {

					zlog(ZLOG_WARNING, "failed processes threshold (%d in %d sec) is reached, initiating reload", fpm_global_config.emergency_restart_threshold, fpm_global_config.emergency_restart_interval);

					fpm_pctl(FPM_PCTL_STATE_RELOADING, FPM_PCTL_ACTION_SET);
				}
			}

			// 有一些子进程退出场景，是需要立即重新拉起新的子进程的
			if (restart_child) {
				fpm_children_make(wp, 1 /* in event loop */, 1, 0);

				if (fpm_globals.is_child) {
					break;
				}
			}
```

紧接着，如果一段时间内段错误等严重致命问题连续出现，那么可能PHP-FPM已经因为某些程序bug原因写坏了内存，进入了一种万劫不复的状态。

此时，满足了restart_condition=1，那么就会标记PHP-FPM进程为RELOADING状态，也就是准备重启PHP-FPM自己。

重启的方法就是定时器检测到php-fpm状态为reloading，那么直接execv再次执行php-fpm二进制即可：

```
fpm/fpm/fpm_process_ctl.c


static void fpm_pctl_exec() /* {{{ */
{

	zlog(ZLOG_NOTICE, "reloading: execvp(\"%s\", {\"%s\""
			"%s%s%s" "%s%s%s" "%s%s%s" "%s%s%s" "%s%s%s"
			"%s%s%s" "%s%s%s" "%s%s%s" "%s%s%s" "%s%s%s"
		"})",
		saved_argv[0], saved_argv[0],
		optional_arg(1),
		optional_arg(2),
		optional_arg(3),
		optional_arg(4),
		optional_arg(5),
		optional_arg(6),
		optional_arg(7),
		optional_arg(8),
		optional_arg(9),
		optional_arg(10)
	);

	fpm_cleanups_run(FPM_CLEANUP_PARENT_EXEC);
	execvp(saved_argv[0], saved_argv);
	zlog(ZLOG_SYSERROR, "failed to reload: execvp() failed");
	exit(FPM_EXIT_SOFTWARE);
}
```

另外，如果此前判定子进程是异常退出，那么restart_child=1，则会立即拉起一个新进程补充起来。

### 定时器 -- 子进程健康检查

对于已经创建的子进程，父进程会在事件循环中创建一个定时器，定时的进行全量的扫描。

目标是发现执行过慢的请求，进行对应的处理。

```
fpm/fpm/fpm_events.c


// master事件循环
void fpm_event_loop(int err) /* {{{ */
{
	...
	
	...
	
	
	/* add timers */
	if (fpm_globals.heartbeat > 0) {

		// 创建定时器，周期性检查子进程是否执行过慢，或者超时，杀死超时进程
		fpm_pctl_heartbeat(NULL, 0, NULL);
	}
	
	
	if (!err) {

		// 创建定时器，周期性根据策略，缩减或者扩增子进程
		fpm_pctl_perform_idle_server_maintenance_heartbeat(NULL, 0, NULL);

		zlog(ZLOG_DEBUG, "%zu bytes have been reserved in SHM", fpm_shm_get_size_allocated());
		zlog(ZLOG_NOTICE, "ready to handle connections");

#ifdef HAVE_SYSTEMD
		fpm_systemd_heartbeat(NULL, 0, NULL);
#endif
	}

```

这里创建了两个定时器，先说第一个定时器fpm_pctl_heartbeat。

```
fpm/fpm/fpm_process_ctl.c


	// 心跳处理函数,
void fpm_pctl_heartbeat(struct fpm_event_s *ev, short which, void *arg) /* {{{ */
{
	static struct fpm_event_s heartbeat;
	struct timeval now;

	if (fpm_globals.parent_pid != getpid()) {
		return; /* sanity check */
	}

	// 如果是心跳回调事件, 那么进入处理流程
	if (which == FPM_EV_TIMEOUT) {
		fpm_clock_get(&now);
		fpm_pctl_check_request_timeout(&now);
		return;
	}

	/* ensure heartbeat is not lower than FPM_PCTL_MIN_HEARTBEAT */
	// 心跳间隔
	fpm_globals.heartbeat = MAX(fpm_globals.heartbeat, FPM_PCTL_MIN_HEARTBEAT);

	/* first call without setting to initialize the timer */
	// 初始只注册一次定时器
	zlog(ZLOG_DEBUG, "heartbeat have been set up with a timeout of %dms", fpm_globals.heartbeat);
	fpm_event_set_timer(&heartbeat, FPM_EV_PERSIST, &fpm_pctl_heartbeat, NULL);
	fpm_event_add(&heartbeat, fpm_globals.heartbeat);
}
```

该函数既是定时器的回调函数，也是定时器的初始化注册函数。

当定时器回调时，会进入if (which == FPM_EV_TIMEOUT)分支执行逻辑；否则就是第一次注册定时器。

进程检测算法在fpm_pctl_check_request_timeout中实现：

```
fpm/fpm/fpm_process_ctl.c


static void fpm_pctl_check_request_timeout(struct timeval *now) /* {{{ */
{
	struct fpm_worker_pool_s *wp;

	// 检查每个池子
	for (wp = fpm_worker_all_pools; wp; wp = wp->next) {
		int terminate_timeout = wp->config->request_terminate_timeout;
		int slowlog_timeout = wp->config->request_slowlog_timeout;
		struct fpm_child_s *child;

		// 每个池子内所有子进程
		if (terminate_timeout || slowlog_timeout) {
			for (child = wp->children; child; child = child->next) {

				// 检查是否请求处理超时
				fpm_request_check_timed_out(child, now, terminate_timeout, slowlog_timeout);
			}
		}
	}
}
```

逻辑上就是遍历所有池子里的所有子进程，逐一调用fpm_request_check_time_out方法检查：

```
fpm/fpm/fpm_request.c


void fpm_request_check_timed_out(struct fpm_child_s *child, struct timeval *now, int terminate_timeout, int slowlog_timeout) /* {{{ */
{
	struct fpm_scoreboard_proc_s proc, *proc_p;

	// 获得子进程的记分板
	proc_p = fpm_scoreboard_proc_acquire(child->wp->scoreboard, child->scoreboard_i, 1);
	if (!proc_p) {
		zlog(ZLOG_WARNING, "failed to acquire scoreboard");
		return;
	}

	// 拷贝一份当前信息
	proc = *proc_p;

	// 释放子进程记分板
	fpm_scoreboard_proc_release(proc_p);

#if HAVE_FPM_TRACE
	if (child->slow_logged.tv_sec) {
		if (child->slow_logged.tv_sec != proc.accepted.tv_sec || child->slow_logged.tv_usec != proc.accepted.tv_usec) {
			child->slow_logged.tv_sec = 0;
			child->slow_logged.tv_usec = 0;
		}
	}
#endif

	// 检查子进程是否存在超时问题
	if (proc.request_stage > FPM_REQUEST_ACCEPTING && proc.request_stage < FPM_REQUEST_END) {
		char purified_script_filename[sizeof(proc.script_filename)];
		struct timeval tv;

		// 当前时间减去连接接收时间
		timersub(now, &proc.accepted, &tv);

#if HAVE_FPM_TRACE

		// 检查是否执行时间触发slow log阀值
		if (child->slow_logged.tv_sec == 0 && slowlog_timeout &&
				proc.request_stage == FPM_REQUEST_EXECUTING && tv.tv_sec >= slowlog_timeout) {

			str_purify_filename(purified_script_filename, proc.script_filename, sizeof(proc.script_filename));

			child->slow_logged = proc.accepted;
			child->tracer = fpm_php_trace; // 当收到子进程的SIGSTOP信号后，需要通过fpm_php_trace函数来获取子进程的栈信息

			// 这里attach到子进程上，目的是获取子进程的PHP栈，需要等待子进程发出SIGSTOP信号
			fpm_trace_signal(child->pid);

			zlog(ZLOG_WARNING, "[pool %s] child %d, script '%s' (request: \"%s %s%s%s\") executing too slow (%d.%06d sec), logging",
				child->wp->config->name, (int) child->pid, purified_script_filename, proc.request_method, proc.request_uri,
				(proc.query_string[0] ? "?" : ""), proc.query_string,
				(int) tv.tv_sec, (int) tv.tv_usec);
		}
		else
#endif
        // 是否执行超时
		if (terminate_timeout && tv.tv_sec >= terminate_timeout) {
			str_purify_filename(purified_script_filename, proc.script_filename, sizeof(proc.script_filename));

			// 给子进程发SIGTERM信号杀死
			fpm_pctl_kill(child->pid, FPM_PCTL_TERM);

			zlog(ZLOG_WARNING, "[pool %s] child %d, script '%s' (request: \"%s %s%s%s\") execution timed out (%d.%06d sec), terminating",
				child->wp->config->name, (int) child->pid, purified_script_filename, proc.request_method, proc.request_uri,
				(proc.query_string[0] ? "?" : ""), proc.query_string,
				(int) tv.tv_sec, (int) tv.tv_usec);
		}
	}
}
```

首先要加锁获取该子进程记分板信息的一份拷贝，然后就释放掉锁，进入检查环节。

记分板里记录了子进程当前的状态，如果>ACCEPTING && < REQUEST_END表示正在处理请求，那么就可以检查这个进程是不是处理请求花费了太久的时间。

首先是判断子进程请求处理事件是否超过slowlog的阀值，那么就会调用fpm_trace_signal去attach到子进程上，内部就是调用ptrace而已。

这里注意child->trace之前提到过，它具体实现在fpm_php_trace中，当父进程收到SIGCHLD并且子进程是STOP状态就会回调child->trace方法，从而从ptrace中抓取子进程的堆栈信息，这里就不展开了。

接下来检测了一下请求花费时间是否过长，这种情况属于极端异常，父进程的做法就是杀死子进程，这是通过发送SIGTERM信号实现的。在发送信号前并没有标记child->idle_kill，说明子进程死后父进程希望可以立即拉起来，因为子进程只是BUG卡住了之类的。

### 定时器 -- 子进程伸缩管理

前一个定时检查运行中的子进程状态，而该定时器fpm_pctl_perform_idle_server_maintenance_heartbeat是判断是否有必要新增子进程，或者杀死过多的空闲子进程。

```
fpm/fpm/fpm_process_ctl.c


// 定时器，子进程空闲杀死/新增的检查逻辑
void fpm_pctl_perform_idle_server_maintenance_heartbeat(struct fpm_event_s *ev, short which, void *arg) /* {{{ */
{
	static struct fpm_event_s heartbeat;
	struct timeval now;

	if (fpm_globals.parent_pid != getpid()) {
		return; /* sanity check */
	}

	if (which == FPM_EV_TIMEOUT) {
		fpm_clock_get(&now);
		if (fpm_pctl_can_spawn_children()) {
			fpm_pctl_perform_idle_server_maintenance(&now);

			/* if it's a child, stop here without creating the next event
			 * this event is reserved to the master process
			 */
			if (fpm_globals.is_child) {
				return;
			}
		}
		return;
	}

	/* first call without setting which to initialize the timer */
	fpm_event_set_timer(&heartbeat, FPM_EV_PERSIST, &fpm_pctl_perform_idle_server_maintenance_heartbeat, NULL);
	fpm_event_add(&heartbeat, FPM_IDLE_SERVER_MAINTENANCE_HEARTBEAT);
}
```

每当定时器被回调进入到if (which == FPM_EV_TIMEOUT)，则调用fpm_pctl_perform_idle_server_maintenance方法进行逻辑处理。


```
fpm/fpm/fpm_process_ctl.c


static void fpm_pctl_perform_idle_server_maintenance(struct timeval *now) /* {{{ */
{
	struct fpm_worker_pool_s *wp;

	// 遍历每个池子
	for (wp = fpm_worker_all_pools; wp; wp = wp->next) {
		struct fpm_child_s *child;
		struct fpm_child_s *last_idle_child = NULL;
		int idle = 0;
		int active = 0;
		int children_to_fork;
		unsigned cur_lq = 0;

		if (wp->config == NULL) continue;

		// 遍历每个子进程
		for (child = wp->children; child; child = child->next) {
			//  如果子进程空闲（等待连接中）
			if (fpm_request_is_idle(child)) {
				// 找出闲的最久的子进程
				if (last_idle_child == NULL) {
					last_idle_child = child;
				} else {
					if (timercmp(&child->started, &last_idle_child->started, <)) {
						last_idle_child = child;
					}
				}
				idle++;
			} else {
				active++;
			}
		}

		/* update status structure for all PMs */
		// 获取一下TCP的连接握手队列有几个排队
		if (wp->listen_address_domain == FPM_AF_INET) {
			if (0 > fpm_socket_get_listening_queue(wp->listening_socket, &cur_lq, NULL)) {
				cur_lq = 0;
#if 0
			} else {
				if (cur_lq > 0) {
					if (!wp->warn_lq) {
						zlog(ZLOG_WARNING, "[pool %s] listening queue is not empty, #%d requests are waiting to be served, consider raising pm.max_children setting (%d)", wp->config->name, cur_lq, wp->config->pm_max_children);
						wp->warn_lq = 1;
					}
				} else {
					wp->warn_lq = 0;
				}
#endif
			}
		}

		// 把这次统计的各种信息，更新到池子的记分板上
		fpm_scoreboard_update(idle, active, cur_lq, -1, -1, -1, 0, FPM_SCOREBOARD_ACTION_SET, wp->scoreboard);

```

该函数外层也是遍历所有池子，对于每个池子进行统计。

主要是统计有多少个子进程在处理请求，有多个子进程空闲，并且找出空闲最久的那个子进程。

然后调用linux api获取了一下监听套接字listen socket的tcp握手队列的堆积长度，如果排队的比较多则预示着子进程不足，来不及处理更多的请求。

上述统计信息会被更新到池子对应的记分板上。

### 子进程管理策略 -- ON DEMAND

我们知道php-fpm有3种进程管理模型，on demand是按需分配，也就是初始化给池子里分配1个子进程，如果子进程来不及处理请求就再增加子进程。

```
fpm/fpm/fpm_process_ctl.c


		// 按需分配进程，所以如果有哪个子进程闲太久了，就干掉
		if (wp->config->pm == PM_STYLE_ONDEMAND) {
			struct timeval last, now;

			zlog(ZLOG_DEBUG, "[pool %s] currently %d active children, %d spare children", wp->config->name, active, idle);

			if (!last_idle_child) continue;

			// 闲最久的那个进程超过了空闲阀值，杀死
			fpm_request_last_activity(last_idle_child, &last);
			fpm_clock_get(&now);
			if (last.tv_sec < now.tv_sec - wp->config->pm_process_idle_timeout) {
				last_idle_child->idle_kill = 1;
				fpm_pctl_kill(last_idle_child->pid, FPM_PCTL_QUIT);
			}

			continue;
		}

```

因为之前统计出空闲最久的子进程是哪个，如果这个子进程处于空闲状态超过阀值，就给它发送SIGQUIT信号杀死它，这就是收缩过程，因为流量并不大，子进程也不忙。


### 子进程管理策略 -- STATIC

静态模式，也就是固定数量的子进程，这种情况下不需要进行子进程伸缩。

之前的健康检查定时器会在子进程退出后立即重新拉起，来保证子进程数量恒定不变。

```
fpm/fpm/fpm_process_ctl.c


		// 固定进程数的就此退出，不需要执行后续逻辑
		if (wp->config->pm != PM_STYLE_DYNAMIC) continue;

		zlog(ZLOG_DEBUG, "[pool %s] currently %d active children, %d spare children, %d running children. Spawning rate %d", wp->config->name, active, idle, wp->running_children, wp->idle_spawn_rate);

```

###  子进程管理策略 -- Dynamic

动态模式，这种配置指定了初始子进程数量，最小空闲进程数量，最大空闲进程数量，最多进程数量，是一种规则比较复杂，但资源控制比较优秀的方法。

```
fpm/fpm/fpm_process_ctl.c


		// 空闲进程数量大于了配置中的空闲最大值，那么干掉闲最久的进程
		if (idle > wp->config->pm_max_spare_servers && last_idle_child) {
			last_idle_child->idle_kill = 1;
			fpm_pctl_kill(last_idle_child->pid, FPM_PCTL_QUIT);
			wp->idle_spawn_rate = 1;
			continue;
		}
```

如果空闲的进程数量超过了最大空闲数量限制，就杀死最闲的那个。

```
fpm/fpm/fpm_process_ctl.c


		// 空闲进程数量小于配置中的空闲最小值
		if (idle < wp->config->pm_min_spare_servers) {

			// 孩子总数虽然超过了配置中的最大进程数量，但是因为空闲的进程数量不多，说明负载很高，只是打日志提示一下
			if (wp->running_children >= wp->config->pm_max_children) {
				if (!wp->warn_max_children) {
					fpm_scoreboard_update(0, 0, 0, 0, 0, 1, 0, FPM_SCOREBOARD_ACTION_INC, wp->scoreboard);
					zlog(ZLOG_WARNING, "[pool %s] server reached pm.max_children setting (%d), consider raising it", wp->config->name, wp->config->pm_max_children);
					wp->warn_max_children = 1;
				}
				wp->idle_spawn_rate = 1;
				continue;
			}

```

如果空闲进程数量小于最小空闲进程限制，说明目前流量比较大，没有充足的空闲进程响应更多请求。 

按照道理，此时应该增加更多子进程来缓解压力，但是如果进程总数量超过了最大进程数量的限制，那么是不能扩容的，此时只是打印一个日志警告而已。

```
fpm/fpm/fpm_process_ctl.c


	// 算一下要补充多少子进程
			children_to_fork = MIN(wp->idle_spawn_rate, wp->config->pm_min_spare_servers - idle);

			/* get sure it won't exceed max_children */
			children_to_fork = MIN(children_to_fork, wp->config->pm_max_children - wp->running_children);
			if (children_to_fork <= 0) {
				if (!wp->warn_max_children) {
					fpm_scoreboard_update(0, 0, 0, 0, 0, 1, 0, FPM_SCOREBOARD_ACTION_INC, wp->scoreboard);
					zlog(ZLOG_WARNING, "[pool %s] server reached pm.max_children setting (%d), consider raising it", wp->config->name, wp->config->pm_max_children);
					wp->warn_max_children = 1;
				}
				wp->idle_spawn_rate = 1;
				continue;
			}
			wp->warn_max_children = 0;

			// 拉起children_to_fork个子进程
			fpm_children_make(wp, 1, children_to_fork, 1);
```

相反，如果此时没有达到最大进程数量限制，那么就可以通过扩容子进程缓解压力。

这里做了一些规则计算，细节并不重要，总之可以新建的子进程数+现有进程数量不能超过总进程数限制。

最后调用fpm_children_make方法创建这些子进程，该函数之前已经讲过。

### 最后 -- 事件循环起来

php-fpm父进程负责子进程管理，通过信号的方式与子进程通讯，从而实现强控子进程的能力。

父进程采取了事件循环来同时实现多个逻辑的并发处理：监测子进程的标准输出、标准错误输出，监测信号，定时器。

当fpm主进程将一切准备就绪，包括1个信号管道，2个常规定时器准备就绪后，就会进入正式的epoll事件循环。

### 定时器的前置处理

```
fpm/fpm/fpm_events.c


while (1) {
		struct fpm_event_queue_s *q, *q2;
		struct timeval ms;
		struct timeval tmp;
		struct timeval now;
		unsigned long int timeout;
		int ret;

		/* sanity check */
		if (fpm_globals.parent_pid != getpid()) {
			return;
		}

		fpm_clock_get(&now);
		timerclear(&ms);

		/* search in the timeout queue for the next timer to trigger */

		// 找到最近一个要到期的定时器，作为event loop超时时间
		q = fpm_event_queue_timer;
		while (q) {
			if (!timerisset(&ms)) {
				ms = q->ev->timeout;
			} else {
				if (timercmp(&q->ev->timeout, &ms, <)) {
					ms = q->ev->timeout;
				}
			}
			q = q->next;
		}

		/* 1s timeout if none has been set */
		if (!timerisset(&ms) || timercmp(&ms, &now, <) || timercmp(&ms, &now, ==)) {
			timeout = 1000;
		} else {
			timersub(&ms, &now, &tmp);
			timeout = (tmp.tv_sec * 1000) + (tmp.tv_usec / 1000) + 1;
		}
```

所有的定时器串在一个fpm_event_queue_timer链表里，首先找到最近要到期的那个定时器，计算得到它距离现在还有多久会到期，保存在timeout里。

然后将timeout作为epoll的超时事件，这样避免epoll平时没有事件触发挂起，导致定时器无法处理。这个设计是任何一款异步网络框架都会涉及的，有相关经验同学不会觉得陌生。

### 调用epoll等待事件触发

```
fpm/fpm/fpm_events.c


		// 监听多个fd的事件循环, 回调fd的事件处理函数
		ret = module->wait(fpm_event_queue_fd, timeout);

		/* is a child, nothing to do here */
		if (ret == -2) {
			return;
		}
```

wait其实等价于调用epoll_wait，内部会根据发生事件的fd回调注册的函数，这里可能主要就是我们之前提到的信号unix socket pair，用于响应信号，包括子进程退出的信号。

### 定时器的执行

当fd的事件经过epoll_wait处理完成后，我们需要遍历所有定时器，查看哪些定时器过期需要执行，仅此而已。

超时的定时器需要调用fpm_event_fire回调当时注册的方法，也就是我们之前谈到的2个常规定时器。

因为上述2个定时都是常规定时器，所以如果ev->flags & FPM_EV_PERSIST非空，则表示这是一个常规定时器，需要重新注册到定时链表，等待下次调度。

```
// 遍历所有注册的定时器
		q = fpm_event_queue_timer;
		while (q) {
			fpm_clock_get(&now);
			if (q->ev) {

				// 到期的就回调
				if (timercmp(&now, &q->ev->timeout, >) || timercmp(&now, &q->ev->timeout, ==)) {

					// 回调用户函数
					fpm_event_fire(q->ev);

					/* sanity check */
					if (fpm_globals.parent_pid != getpid()) {
						return;
					}

					// 如果是持久化的定时器，那么再次注册回去等待下次触发
					if (q->ev->flags & FPM_EV_PERSIST) {
						fpm_event_set_timeout(q->ev, now);
					} else { /* delete the event */
						q2 = q;
						if (q->prev) {
							q->prev->next = q->next;
						}
						if (q->next) {
							q->next->prev = q->prev;
						}
						if (q == fpm_event_queue_timer) {
							fpm_event_queue_timer = q->next;
							if (fpm_event_queue_timer) {
								fpm_event_queue_timer->prev = NULL;
							}
						}
						q = q->next;
						free(q2);
						continue;
					}
				}
			}
			q = q->next;
		}
```

## 结束

PHP-FPM围绕进程管理设计实现，基于共享内存的记分板实现子进程状态检测，子进程采用阻塞模型，父进程基于信号控制子进程管理，整体设计保持简单纯粹。


