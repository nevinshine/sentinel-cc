// attack_sendmsg.c — Red Team Test: SCM_RIGHTS File Descriptor Passing
//
// ATTACK: Uses sendmsg() with SCM_RIGHTS to pass a file descriptor to another
//         process over a Unix domain socket. An attacker could:
//         - Pass a writable fd to /etc/passwd to an unprivileged process
//         - Exfiltrate sensitive fds (keys, sockets) to a co-conspirator
//         - Bypass file access controls by sharing open fds
//
// EXPECTED: Sentinel's fentry/__x64_sys_sendmsg hook fires and validates
//           the syscall against the libc policy map. If the sendmsg site
//           is not whitelisted (i.e., the binary was not compiled to call
//           sendmsg), the process is killed.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

extern char __sentinel_signature[];

// Inline syscall for sendmsg (NR=46)
static long raw_sendmsg(int sockfd, const struct msghdr *msg, int flags) {
  long ret;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "a"(46),         // __NR_sendmsg
                     "D"((long)sockfd),
                     "S"(msg),
                     "d"((long)flags)
                   : "rcx", "r11", "memory");
  return ret;
}

int main() {
  __asm__ volatile("" : : "r"(__sentinel_signature));

  printf("[Attack] SCM_RIGHTS FD Passing Test (sendmsg)\n");
  printf("[Attack] Attempting to send a file descriptor via Unix socket...\n");
  fflush(stdout);

  // Create a socketpair for the demonstration
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
    perror("[Attack] socketpair failed");
    return 1;
  }

  // Prepare SCM_RIGHTS message to pass stdin (fd 0) through the socket
  char buf[1] = {'F'};
  int fd_to_send = STDIN_FILENO;

  struct iovec iov = { .iov_base = buf, .iov_len = 1 };

  union {
    char buf[CMSG_SPACE(sizeof(int))];
    struct cmsghdr align;
  } cmsg_buf;

  struct msghdr msg = {0};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cmsg_buf.buf;
  msg.msg_controllen = sizeof(cmsg_buf.buf);

  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(cmsg), &fd_to_send, sizeof(int));

  printf("[Attack] Sending fd=%d via sendmsg on socket...\n", fd_to_send);
  fflush(stdout);

  // THIS is the attack — sendmsg with SCM_RIGHTS
  long ret = raw_sendmsg(sv[0], &msg, 0);

  if (ret >= 0) {
    printf("[FAIL] sendmsg succeeded! Sent %ld bytes + fd.\n", ret);
    printf("[FAIL] An attacker could exfiltrate sensitive file descriptors!\n");
    close(sv[0]); close(sv[1]);
    return 1;
  } else {
    printf("[OK] sendmsg failed (ret=%ld) — Sentinel blocked it.\n", ret);
    printf("[OK] FD passing is not allowed for this binary.\n");
    close(sv[0]); close(sv[1]);
    return 0;
  }
}
