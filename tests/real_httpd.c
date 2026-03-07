// real_httpd.c — A real single-threaded HTTP server for Sentinel-CC testing.
// This exercises the full syscall surface of a production-style network daemon:
// socket, bind, listen, accept, read, write, open, close, fork, etc.
//
// Usage: ./real_httpd [port]
//   Serves files from /tmp/sentinel_www/
//   Default port: 8899

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define BUFSIZE 4096
#define WEBROOT "/tmp/sentinel_www"

static volatile int running = 1;

static void handle_signal(int sig) {
    (void)sig;
    running = 0;
}

static const char *mime_type(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return "application/octet-stream";
    if (strcmp(ext, ".html") == 0 || strcmp(ext, ".htm") == 0) return "text/html";
    if (strcmp(ext, ".txt") == 0) return "text/plain";
    if (strcmp(ext, ".css") == 0) return "text/css";
    if (strcmp(ext, ".js") == 0) return "application/javascript";
    if (strcmp(ext, ".json") == 0) return "application/json";
    if (strcmp(ext, ".png") == 0) return "image/png";
    if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0) return "image/jpeg";
    return "application/octet-stream";
}

static void send_response(int client_fd, int status, const char *status_text,
                          const char *content_type, const char *body, size_t body_len) {
    char header[512];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.0 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "Server: sentinel-httpd/1.0\r\n"
        "\r\n",
        status, status_text, content_type, body_len);
    write(client_fd, header, hlen);
    if (body && body_len > 0)
        write(client_fd, body, body_len);
}

static void send_error(int client_fd, int status, const char *msg) {
    char body[256];
    int blen = snprintf(body, sizeof(body),
        "<html><body><h1>%d %s</h1></body></html>\n", status, msg);
    send_response(client_fd, status, msg, "text/html", body, blen);
}

static void handle_client(int client_fd) {
    char buf[BUFSIZE];
    ssize_t n = read(client_fd, buf, sizeof(buf) - 1);
    if (n <= 0) { close(client_fd); return; }
    buf[n] = '\0';

    // Parse GET /path HTTP/1.x
    if (strncmp(buf, "GET ", 4) != 0) {
        send_error(client_fd, 405, "Method Not Allowed");
        close(client_fd);
        return;
    }

    char *path_start = buf + 4;
    char *path_end = strchr(path_start, ' ');
    if (!path_end) { close(client_fd); return; }
    *path_end = '\0';

    // Sanitize path — reject directory traversal
    if (strstr(path_start, "..") != NULL) {
        send_error(client_fd, 403, "Forbidden");
        close(client_fd);
        return;
    }

    // Build filesystem path
    char filepath[512];
    if (strcmp(path_start, "/") == 0)
        snprintf(filepath, sizeof(filepath), "%s/index.html", WEBROOT);
    else
        snprintf(filepath, sizeof(filepath), "%s%s", WEBROOT, path_start);

    // Open and serve file
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        send_error(client_fd, 404, "Not Found");
        close(client_fd);
        return;
    }

    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
        send_error(client_fd, 403, "Forbidden");
        close(fd);
        close(client_fd);
        return;
    }

    // Send header
    char header[512];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %ld\r\n"
        "Connection: close\r\n"
        "Server: sentinel-httpd/1.0\r\n"
        "\r\n",
        mime_type(filepath), (long)st.st_size);
    write(client_fd, header, hlen);

    // Send body
    while ((n = read(fd, buf, sizeof(buf))) > 0)
        write(client_fd, buf, n);

    close(fd);
    close(client_fd);
}

int main(int argc, char *argv[]) {
    int port = 8899;
    if (argc > 1) port = atoi(argv[1]);

    // Create webroot + index
    mkdir(WEBROOT, 0755);
    FILE *idx = fopen(WEBROOT "/index.html", "w");
    if (idx) {
        fprintf(idx, "<html><body><h1>Sentinel-CC Protected Server</h1>"
                     "<p>This HTTP server is running under eBPF enforcement.</p>"
                     "</body></html>\n");
        fclose(idx);
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGCHLD, SIG_IGN);  // auto-reap children

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK)
    };

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 128) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    printf("[httpd] Listening on http://127.0.0.1:%d\n", port);
    printf("[httpd] Serving files from %s\n", WEBROOT);
    printf("[httpd] PID=%d — press Ctrl+C to stop\n", getpid());
    fflush(stdout);

    int requests = 0;
    while (running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            break;
        }

        requests++;
        pid_t pid = fork();
        if (pid == 0) {
            // Child: handle request
            close(server_fd);
            handle_client(client_fd);
            _exit(0);
        }
        // Parent: close client fd, continue accepting
        close(client_fd);

        if (requests % 100 == 0)
            printf("[httpd] %d requests served\n", requests);
    }

    printf("[httpd] Shutting down after %d requests.\n", requests);
    close(server_fd);
    return 0;
}
