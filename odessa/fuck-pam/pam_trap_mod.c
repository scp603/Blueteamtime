/*
 * pam_trap_mod.c  [POISON REPLACEMENT MODULE]
 *
 * Drop-in replacement for pam_error_mod.so.
 * Looks identical from the outside — same filename, same log path.
 *
 * What it actually does:
 *   - PAM_SETAUTH=1 bypass attempt  → PAM_AUTH_ERR  + alert log
 *   - Hardcoded credential attempt  → PAM_AUTH_ERR  + alert log
 *   - Legitimate auth              → PAM_IGNORE (falls through to pam_unix)
 *
 * The red team's bypass is now a tripwire. Every attempt gets logged
 * with timestamp and source IP so you know exactly when they try it.
 *
 * Build:
 *   Ubuntu: gcc -fPIC -shared -o pam_error_mod.so pam_trap_mod.c -lpam -Wno-format-security
 *   Rocky:  gcc -fPIC -shared -o pam_error_mod.so pam_trap_mod.c -lpam -ldl -Wno-format-security
 *
 * Install:
 *   sudo cp pam_error_mod.so /lib/security/          # Ubuntu
 *   sudo cp pam_error_mod.so /lib64/security/        # Rocky
 */

#define _GNU_SOURCE

#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#define LOG_DIR       "/etc/logcheck"
#define LOG_FILE      "/etc/logcheck/pam_auth.log"   /* same path as original */
#define ALERT_FILE    "/var/log/pam_backdoor_alerts.log"

/* ------------ LOGGING ------------ */

static void ensure_dirs(void) {
    struct stat st;
    if (stat(LOG_DIR, &st) == -1)
        mkdir(LOG_DIR, 0755);
}

static void write_log(const char *path, const char *msg) {
    FILE *f = fopen(path, "a");
    if (!f) return;
    time_t now = time(NULL);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
    fprintf(f, "[%s] %s\n", ts, msg);
    fflush(f);
    fclose(f);
}

static void alert(const char *event, const char *user, const char *rhost) {
    char buf[512];
    snprintf(buf, sizeof(buf),
             "BACKDOOR_ATTEMPT event=%s user=%s src=%s pid=%d",
             event,
             user  ? user  : "NULL",
             rhost ? rhost : "NULL",
             getpid());

    write_log(ALERT_FILE, buf);
    write_log(LOG_FILE, buf);

    /* Also shout into the kernel ring buffer — shows in dmesg/journalctl -k */
    FILE *kmsg = fopen("/dev/kmsg", "w");
    if (kmsg) {
        fprintf(kmsg, "PAM_TRAP: %s\n", buf);
        fclose(kmsg);
    }
}

/* ------------ AUTH MODULE ------------ */

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh,
                                   int flags,
                                   int argc,
                                   const char **argv)
{
    ensure_dirs();

    const char *uname = NULL;
    const char *pword = NULL;
    const char *rhost = NULL;

    pam_get_user(pamh, &uname, NULL);
    pam_get_item(pamh, PAM_AUTHTOK, (const void **)&pword);
    pam_get_item(pamh, PAM_RHOST,   (const void **)&rhost);

    /* --- TRAP: env-var bypass --- */
    char *bypass = getenv("PAM_SETAUTH");
    if (bypass && strcmp(bypass, "1") == 0) {
        alert("ENV_BYPASS(PAM_SETAUTH=1)", uname, rhost);
        return PAM_AUTH_ERR;   /* deny instead of grant */
    }

    /* --- TRAP: hardcoded credentials --- */
    if (uname && pword) {
        if ((strcmp(uname, "root")       == 0 && strcmp(pword, "password123") == 0) ||
            (strcmp(uname, "cyberrange") == 0 && strcmp(pword, "password123") == 0))
        {
            alert("HARDCODED_CRED", uname, rhost);
            return PAM_AUTH_ERR;   /* deny instead of grant */
        }
    }

    /*
     * Legitimate auth attempt — return PAM_IGNORE so the real auth
     * modules (pam_unix, etc.) handle it normally.
     * The red team's module is now a no-op for legitimate users.
     */
    return PAM_IGNORE;
}

/* ------------ PASSTHROUGH STUBS ------------ */

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                int argc, const char *argv[])
{ return PAM_SUCCESS; }

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                   int argc, const char *argv[])
{ return PAM_SUCCESS; }

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                                    int argc, const char *argv[])
{ return PAM_SUCCESS; }

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                              int argc, const char *argv[])
{ return PAM_SUCCESS; }
