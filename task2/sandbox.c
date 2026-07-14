/*
 * sandbox.c
 * User-space malware analysis sandbox controller.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <time.h>
#include <errno.h>

#define TIME_LIMIT_SECONDS   5
#define CPU_LIMIT_SECONDS    3
#define POLL_INTERVAL_USEC   200000

static pid_t g_child_pid;
static atomic_int g_terminate_requested = 0;
static atomic_int g_child_exited = 0;
static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;
static FILE *g_logfile = NULL;

void safe_log(const char *fmt, ...) {
    pthread_mutex_lock(&g_log_lock);
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fflush(stdout);
    if (g_logfile) {
        va_start(args, fmt);
        vfprintf(g_logfile, fmt, args);
        va_end(args);
        fflush(g_logfile);
    }
    pthread_mutex_unlock(&g_log_lock);
}
double get_child_cpu_seconds(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return -1.0;

    char buf[512];
    if (!fgets(buf, sizeof(buf), fp)) { fclose(fp); return -1.0; }
    fclose(fp);

    char *rparen = strrchr(buf, ')');
    if (!rparen) return -1.0;

    unsigned long utime = 0, stime = 0;
    int rc = sscanf(rparen + 1,
        " %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu",
        &utime, &stime);
    if (rc != 2) return -1.0;

    long clk_tck = sysconf(_SC_CLK_TCK);
    return (double)(utime + stime) / (double)clk_tck;
}
void *timer_thread_fn(void *arg) {
    (void)arg;
    time_t start = time(NULL);
    safe_log("[sandbox] timer thread started, wall-clock limit = %d s\n", TIME_LIMIT_SECONDS);

    while (!atomic_load(&g_child_exited)) {
        time_t now = time(NULL);
        if (now - start >= TIME_LIMIT_SECONDS) {
            safe_log("[sandbox] TIME LIMIT EXCEEDED (%ld s elapsed) - requesting termination\n",
                     (long)(now - start));
            atomic_store(&g_terminate_requested, 1);
            break;
        }
        usleep(POLL_INTERVAL_USEC);
    }
    return NULL;
}

void *monitor_thread_fn(void *arg) {
    (void)arg;
    safe_log("[sandbox] monitor thread started, CPU limit = %d s\n", CPU_LIMIT_SECONDS);

    while (!atomic_load(&g_child_exited)) {
        double cpu = get_child_cpu_seconds(g_child_pid);
        if (cpu < 0) {
            break;
        }
        safe_log("[sandbox] monitor: child cpu time so far = %.2f s\n", cpu);
        if (cpu >= CPU_LIMIT_SECONDS) {
            safe_log("[sandbox] CPU LIMIT EXCEEDED (%.2f s) - requesting termination\n", cpu);
            atomic_store(&g_terminate_requested, 1);
            break;
        }
        usleep(POLL_INTERVAL_USEC);
    }
    return NULL;
}
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path-to-untrusted-binary>\n", argv[0]);
        return 1;
    }

    g_logfile = fopen("sandbox_run.log", "a");

    safe_log("[sandbox] ==== new run: target = %s ====\n", argv[1]);
    safe_log("[sandbox] parent pid=%d\n", getpid());

    pid_t pid = fork();
    if (pid < 0) {
        perror("[sandbox] fork failed");
        return 1;
    }

    if (pid == 0) {
        execl(argv[1], argv[1], (char *)NULL);
        perror("[sandbox-child] execve failed");
        _exit(127);
    }
g_child_pid = pid;
    safe_log("[sandbox] child pid=%d started\n", pid);

    pthread_t timer_tid, monitor_tid;
    pthread_create(&timer_tid, NULL, timer_thread_fn, NULL);
    pthread_create(&monitor_tid, NULL, monitor_thread_fn, NULL);

    int status;
    while (1) {
        pid_t r = waitpid(g_child_pid, &status, WNOHANG);
        if (r == g_child_pid) {
            atomic_store(&g_child_exited, 1);
            if (WIFEXITED(status)) {
                safe_log("[sandbox] child exited normally, code=%d\n", WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                safe_log("[sandbox] child terminated by signal %d (%s)\n",
                          WTERMSIG(status), strsignal(WTERMSIG(status)));
            }
            break;
        }

        if (atomic_load(&g_terminate_requested)) {
            safe_log("[sandbox] enforcing termination: sending SIGKILL to pid=%d\n", g_child_pid);
            kill(g_child_pid, SIGKILL);
            waitpid(g_child_pid, &status, 0);
            atomic_store(&g_child_exited, 1);
            if (WIFSIGNALED(status)) {
                safe_log("[sandbox] confirmed: child terminated by signal %d (%s)\n",
                          WTERMSIG(status), strsignal(WTERMSIG(status)));
            }
            break;
        }

        usleep(POLL_INTERVAL_USEC);
    }
pthread_join(timer_tid, NULL);
    pthread_join(monitor_tid, NULL);

    safe_log("[sandbox] ==== run complete ====\n\n");
    if (g_logfile) fclose(g_logfile);
    return 0;
}
