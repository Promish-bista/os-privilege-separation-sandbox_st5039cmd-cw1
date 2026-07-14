/*
 * backend.c - v3
 * Full privilege-separated backend.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <crypt.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <errno.h>
#include <pwd.h>

#define SHADOW_PATH   "/etc/myshadow.txt"
#define SOCKET_PATH   "/tmp/authsvc.sock"
#define UNPRIV_USER   "authsvc"
#define BUF_SIZE      256

int verify_privileged(void) {
    uid_t euid = geteuid();
    fprintf(stderr, "[backend] runtime check: effective UID = %d\n", euid);
    if (euid != 0) {
        fprintf(stderr, "[backend] FATAL: not running with root privilege. Aborting.\n");
        return -1;
    }
    return 0;
}

int lookup_hash(const char *username, char *hash_out, size_t hash_out_len) {
    FILE *fp = fopen(SHADOW_PATH, "r");
    if (!fp) {
        perror("[backend] fopen shadow file");
        return -1;
    }

    char line[BUF_SIZE];
    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';
        if (strcmp(line, username) == 0) {
            char *hash = colon + 1;
            hash[strcspn(hash, "\n")] = '\0';
            strncpy(hash_out, hash, hash_out_len - 1);
            hash_out[hash_out_len - 1] = '\0';
            found = 1;
            break;
        }
    }
    fclose(fp);
    return found ? 0 : -1;
}

int verify_password(const char *password, const char *stored_hash) {
    char *result = crypt(password, stored_hash);
    if (!result) {
        perror("[backend] crypt failed");
        return -1;
    }
    return (strcmp(result, stored_hash) == 0) ? 0 : -1;
}
int drop_privileges(const char *username) {
    struct passwd *pw = getpwnam(username);
    if (!pw) {
        fprintf(stderr, "[backend] FATAL: no such user %s\n", username);
        return -1;
    }
    uid_t target_uid = pw->pw_uid;
    gid_t target_gid = pw->pw_gid;

    if (setresgid(target_gid, target_gid, target_gid) != 0) {
        perror("[backend] setresgid failed");
        return -1;
    }
    if (setresuid(target_uid, target_uid, target_uid) != 0) {
        perror("[backend] setresuid failed");
        return -1;
    }

    fprintf(stderr, "[backend] privileges dropped. real=%d eff=%d\n", getuid(), geteuid());

    if (setuid(0) == 0) {
        fprintf(stderr, "[backend] CRITICAL: was able to regain root after drop!\n");
        return -1;
    }
    fprintf(stderr, "[backend] confirmed: attempt to reclaim root failed as expected (%s)\n", strerror(errno));
    return 0;
}

void wipe_buffer(void *buf, size_t len) {
    explicit_bzero(buf, len);
}
int main(void) {
    fprintf(stderr, "[backend] started. real uid=%d effective uid=%d\n", getuid(), geteuid());

    if (verify_privileged() != 0) {
        exit(1);
    }

    unlink(SOCKET_PATH);

    int listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("[backend] socket");
        exit(1);
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("[backend] bind");
        exit(1);
    }

    chmod(SOCKET_PATH, 0666);

    if (listen(listen_fd, 1) != 0) {
        perror("[backend] listen");
        exit(1);
    }

    fprintf(stderr, "[backend] listening on %s\n", SOCKET_PATH);

    int conn_fd = accept(listen_fd, NULL, NULL);
    if (conn_fd < 0) {
        perror("[backend] accept");
        exit(1);
    }
    fprintf(stderr, "[backend] frontend connected\n");
 char inbuf[BUF_SIZE];
    memset(inbuf, 0, sizeof(inbuf));
    ssize_t n = recv(conn_fd, inbuf, sizeof(inbuf) - 1, 0);
    if (n <= 0) {
        perror("[backend] recv");
        close(conn_fd);
        exit(1);
    }
    inbuf[n] = '\0';

    char username[BUF_SIZE] = {0};
    char password[BUF_SIZE] = {0};
    char *sep = strchr(inbuf, ':');
    if (!sep) {
        fprintf(stderr, "[backend] malformed request\n");
        const char *resp = "FAIL";
        send(conn_fd, resp, strlen(resp), 0);
        close(conn_fd);
        wipe_buffer(inbuf, sizeof(inbuf));
        exit(1);
    }
    *sep = '\0';
    strncpy(username, inbuf, sizeof(username) - 1);
    strncpy(password, sep + 1, sizeof(password) - 1);

    fprintf(stderr, "[backend] validating login for user '%s'\n", username);

    char hash[BUF_SIZE];
    int auth_ok = 0;
    if (lookup_hash(username, hash, sizeof(hash)) == 0) {
        auth_ok = (verify_password(password, hash) == 0);
    }

    if (drop_privileges(UNPRIV_USER) != 0) {
        fprintf(stderr, "[backend] FATAL: could not drop privileges, refusing to continue\n");
        const char *resp = "FAIL";
        send(conn_fd, resp, strlen(resp), 0);
        close(conn_fd);
        wipe_buffer(password, sizeof(password));
        exit(1);
    }
const char *resp = auth_ok ? "PASS" : "FAIL";
    send(conn_fd, resp, strlen(resp), 0);
    fprintf(stderr, "[backend] result sent: %s\n", resp);

    close(conn_fd);
    close(listen_fd);
    unlink(SOCKET_PATH);

    wipe_buffer(password, sizeof(password));
    wipe_buffer(hash, sizeof(hash));
    wipe_buffer(inbuf, sizeof(inbuf));

    fprintf(stderr, "[backend] sensitive buffers wiped, exiting. final uid=%d euid=%d\n", getuid(), geteuid());
    return 0;
}
