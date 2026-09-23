/*
 * scouter-agent: the launcher for Scouter's macOS background service.
 *
 * Why it exists
 * -------------
 * macOS decides whether a process may read privacy-protected data (Full Disk Access) by asking which
 * process is *responsible* for it. A launchd daemon is responsible for itself, and every process it
 * starts inherits that responsibility — the same reason granting Full Disk Access to Terminal covers
 * every script run inside Terminal.
 *
 * Without this launcher the service's responsible process is the Python interpreter, so Full Disk
 * Access had to be granted to Python.app, where it then extends to every Python script that
 * interpreter ever runs. This launcher stays alive as the parent and runs the agent as its child, so
 * the grant names "Scouter Agent" instead and Python itself no longer needs it.
 *
 * It must NOT exec the agent: after an exec the process *is* Python again, access is charged to
 * Python, and the whole point is lost. It remains the parent for the life of the service.
 *
 * Why it is deliberately inflexible
 * ---------------------------------
 * A launcher holding Full Disk Access that ran whatever it was given would be a privacy-control
 * bypass: local malware could register its own launchd job pointing at this binary and inherit the
 * grant. So it:
 *   - refuses to run unless it is root (a malicious per-user launchd job runs as that user);
 *   - never takes a program from its arguments — it only ever runs agent.py from its own install,
 *     and treats every argument it is given as a flag for the agent;
 *   - reads the interpreter path from a root-owned file, not the command line;
 *   - refuses unless its own executable, its install, agent.py and that file are root-owned and not
 *     writable by group or others, checked all the way up to /, so nobody can swap in their own code.
 *
 * Its exit status is the agent's own, so launchd's KeepAlive behaviour and the agent's deliberate exit
 * codes (78: port already in use) work exactly as if launchd had started the agent directly.
 */
#include <errno.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#define EXIT_NOPERM 77                 /* sysexits EX_NOPERM */
#define EXIT_CONFIG 78                 /* sysexits EX_CONFIG */
#define MAX_AGENT_ARGS 256

/* Where this executable must sit, relative to the agent's install directory. */
static const char LAYOUT[] = "/launcher/ScouterAgent.app/Contents/MacOS/scouter-agent";

static volatile sig_atomic_t g_child = 0;

static int die(int code, const char *fmt, ...) {
    va_list ap;
    fputs("scouter-agent: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    return code;
}

#ifdef SCOUTER_LAUNCHER_TEST
/* TEST BUILD ONLY. Ownership is compared with the invoking user instead of root, the root requirement
 * is lifted, and the walk up the directory tree stops at $SCOUTER_LAUNCHER_TEST_ROOT. Released
 * binaries are compiled without this, so none of it exists in them. */
static uid_t owner_required(void) { return getuid(); }
static const char *walk_stop(void) { return getenv("SCOUTER_LAUNCHER_TEST_ROOT"); }
#else
static uid_t owner_required(void) { return 0; }
static const char *walk_stop(void) { return NULL; }
#endif

/* Non-zero (an exit code) unless `path` is the expected kind, not a symlink, owned by the required
 * owner, and not writable by group or others. */
static int locked(const char *path, int want_dir) {
    struct stat st;
    if (lstat(path, &st) != 0)
        return die(EXIT_CONFIG, "%s: %s", path, strerror(errno));
    if (S_ISLNK(st.st_mode))
        return die(EXIT_CONFIG, "%s is a symbolic link; refusing", path);
    if (want_dir ? !S_ISDIR(st.st_mode) : !S_ISREG(st.st_mode))
        return die(EXIT_CONFIG, "%s is not a %s; refusing", path, want_dir ? "directory" : "regular file");
    if (st.st_uid != owner_required())
        return die(EXIT_CONFIG, "%s is owned by uid %u, not %u; refusing", path,
                   (unsigned)st.st_uid, (unsigned)owner_required());
    if (st.st_mode & (S_IWGRP | S_IWOTH))
        return die(EXIT_CONFIG, "%s is writable by group or others; refusing", path);
    return 0;
}

/* `dir` and every directory above it must be locked: whoever can write a parent can rename the
 * install out of the way and put their own in its place. */
static int tree_locked(const char *dir) {
    char buf[PATH_MAX];
    const char *stop = walk_stop();
    if (strlen(dir) >= sizeof buf)
        return die(EXIT_CONFIG, "path too long");
    strcpy(buf, dir);
    for (;;) {
        int rc = locked(buf, 1);
        if (rc)
            return rc;
        if (stop && strcmp(buf, stop) == 0)
            return 0;
        char *slash = strrchr(buf, '/');
        if (!slash)
            return die(EXIT_CONFIG, "unexpected path %s", dir);
        if (slash == buf) {
            if (buf[1] == '\0')
                return 0;              /* just checked "/" */
            buf[1] = '\0';             /* check "/" next */
        } else {
            *slash = '\0';
        }
    }
}

static void forward(int sig) {
    pid_t child = (pid_t)g_child;
    if (child > 0)
        kill(child, sig);
}

int main(int argc, char *argv[]) {
#ifndef SCOUTER_LAUNCHER_TEST
    if (geteuid() != 0)
        return die(EXIT_NOPERM, "this is the launcher for Scouter's background service and only runs as "
                                "root under launchd. To run the agent yourself: sudo python3 agent.py");
#endif
    if (argc > MAX_AGENT_ARGS)
        return die(EXIT_CONFIG, "too many arguments");

    /* Where am I? Resolve symlinks, then insist on the one layout an install produces. */
    char raw[PATH_MAX], exe[PATH_MAX];
    uint32_t size = sizeof raw;
    if (_NSGetExecutablePath(raw, &size) != 0 || !realpath(raw, exe))
        return die(EXIT_CONFIG, "cannot resolve my own path");
    size_t n = strlen(exe), ln = sizeof LAYOUT - 1;
    if (n <= ln || strcmp(exe + n - ln, LAYOUT) != 0)
        return die(EXIT_CONFIG, "%s is not inside a Scouter install (expected <install>%s)", exe, LAYOUT);

    char agent_dir[PATH_MAX], agent_py[PATH_MAX], conf[PATH_MAX], exe_dir[PATH_MAX];
    memcpy(agent_dir, exe, n - ln);
    agent_dir[n - ln] = '\0';
    snprintf(agent_py, sizeof agent_py, "%s/agent.py", agent_dir);
    snprintf(conf, sizeof conf, "%s/launcher.conf", agent_dir);
    strcpy(exe_dir, exe);
    *strrchr(exe_dir, '/') = '\0';

    int rc;
    if ((rc = locked(exe, 0)) || (rc = tree_locked(exe_dir)) || (rc = locked(agent_py, 0)) ||
        (rc = locked(conf, 0)))
        return rc;

    /* The interpreter comes from the root-owned configuration file, never from the command line. */
    char line[PATH_MAX + 2], interp[PATH_MAX];
    FILE *f = fopen(conf, "r");
    if (!f)
        return die(EXIT_CONFIG, "%s: %s", conf, strerror(errno));
    if (!fgets(line, sizeof line, f)) {
        fclose(f);
        return die(EXIT_CONFIG, "%s is empty", conf);
    }
    fclose(f);
    line[strcspn(line, "\r\n")] = '\0';
    if (line[0] != '/')
        return die(EXIT_CONFIG, "the interpreter in %s must be an absolute path", conf);
    if (!realpath(line, interp))
        return die(EXIT_CONFIG, "interpreter %s: %s", line, strerror(errno));
    struct stat ist;
    if (stat(interp, &ist) != 0 || !S_ISREG(ist.st_mode) || !(ist.st_mode & S_IXUSR))
        return die(EXIT_CONFIG, "interpreter %s is not an executable file", interp);
    if (ist.st_uid != 0 || (ist.st_mode & S_IWOTH))
        return die(EXIT_CONFIG, "interpreter %s must be owned by root and not writable by everyone", interp);

    /* argv for the agent: interpreter, agent.py, --daemon, then every argument we were given. */
    char *args[MAX_AGENT_ARGS + 4];
    int k = 0;
    args[k++] = interp;
    args[k++] = agent_py;
    args[k++] = (char *)"--daemon";
    for (int i = 1; i < argc; i++)
        args[k++] = argv[i];
    args[k] = NULL;

    if (chdir(agent_dir) != 0)
        return die(EXIT_CONFIG, "cannot enter %s: %s", agent_dir, strerror(errno));
    if (setenv("SCOUTER_LAUNCHER", "1", 1) != 0)
        return die(EXIT_CONFIG, "cannot set the environment");

    /* Forward stop signals to the agent. Block them across the spawn so one arriving in between is
     * delivered — and forwarded — once the child's pid is known, rather than lost. */
    static const int forwarded[] = {SIGTERM, SIGINT, SIGHUP, SIGQUIT};
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = forward;
    sigemptyset(&sa.sa_mask);
    sigset_t block, prev, reset;
    sigemptyset(&block);
    sigemptyset(&reset);
    for (size_t i = 0; i < sizeof forwarded / sizeof *forwarded; i++) {
        sigaddset(&block, forwarded[i]);
        sigaddset(&reset, forwarded[i]);
        sigaction(forwarded[i], &sa, NULL);
    }
    sigaddset(&reset, SIGPIPE);
    sigprocmask(SIG_BLOCK, &block, &prev);

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    sigset_t none;
    sigemptyset(&none);
    posix_spawnattr_setsigmask(&attr, &none);
    posix_spawnattr_setsigdefault(&attr, &reset);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF);
    pid_t pid;
    int err = posix_spawn(&pid, interp, NULL, &attr, args, environ);
    posix_spawnattr_destroy(&attr);
    if (err != 0) {
        sigprocmask(SIG_SETMASK, &prev, NULL);
        return die(EXIT_CONFIG, "cannot start %s: %s", interp, strerror(err));
    }
    g_child = pid;
    sigprocmask(SIG_SETMASK, &prev, NULL);

    int status;
    for (;;) {
        pid_t r = waitpid(pid, &status, 0);
        if (r == pid)
            break;
        if (r < 0 && errno == EINTR)
            continue;
        return die(1, "waiting for the agent: %s", strerror(errno));
    }
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);
    return 1;
}
