/*
 * frontend.c
 * Runs as a normal, unprivileged user. Its ONLY job is to collect the
 * username and password and hand them to the backend over a UNIX
 * domain socket. It never touches the shadow file, never validates
 * anything itself, and never runs with elevated privilege.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCKET_PATH "/tmp/authsvc.sock"
#define BUF_SIZE 256

int main(void) {
    printf("[frontend] running as uid=%d euid=%d\n", getuid(), geteuid());

    char username[128];
    char password[128];

    printf("Username: ");
    if (!fgets(username, sizeof(username), stdin)) exit(1);
    username[strcspn(username, "\n")] = '\0';

    printf("Password: ");
    if (!fgets(password, sizeof(password), stdin)) exit(1);
    password[strcspn(password, "\n")] = '\0';

    int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("[frontend] socket");
        exit(1);
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("[frontend] connect (is the backend running?)");
        exit(1);
    }

    char msg[BUF_SIZE];
    snprintf(msg, sizeof(msg), "%s:%s", username, password);
    send(sock_fd, msg, strlen(msg), 0);

    char resp[BUF_SIZE] = {0};
    ssize_t n = recv(sock_fd, resp, sizeof(resp) - 1, 0);
    if (n > 0) {
        resp[n] = '\0';
        printf("[frontend] backend response: %s\n", resp);
        if (strcmp(resp, "PASS") == 0) {
            printf("Access granted.\n");
        } else {
            printf("Access denied.\n");
        }
    } else {
        printf("[frontend] no response from backend\n");
    }

    explicit_bzero(password, sizeof(password));

    close(sock_fd);
    return 0;
}
