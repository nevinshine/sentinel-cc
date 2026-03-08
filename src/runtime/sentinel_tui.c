// sentinel_tui.c — Sentinel-CC Terminal Dashboard
// Reads JSON audit events from stdin and displays a live TUI overview.
//
// Usage:
//   sudo ./loader --audit --audit-format=json ./victim | ./sentinel-tui
//   tail -f /var/log/syslog | grep sentinel | ./sentinel-tui

#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#define VERSION "4.4.0"
#define MAX_HISTORY 256
#define MAX_SYSCALLS 512

// --- ANSI escape codes ---
#define CLR     "\033[H\033[J"
#define BOLD    "\033[1m"
#define DIM     "\033[2m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define CYAN    "\033[36m"
#define RESET   "\033[0m"
#define ERASE_LINE "\033[K"

static volatile sig_atomic_t g_running = 1;

static void handle_signal(int sig) {
  (void)sig;
  g_running = 0;
}

// Parsed audit event
struct tui_event {
  char action[16];
  unsigned int pid;
  unsigned int tid;
  unsigned int syscall_nr;
  long ret;          // For FEXIT events
  char rip[20];
  char offset[20];
  unsigned int module;
  char timestamp[32];
  int is_fexit;
};

// Per-syscall statistics
struct syscall_stats {
  unsigned int nr;
  unsigned long allow_count;
  unsigned long block_count;
  unsigned long fexit_count;
};

// Global counters
static unsigned long total_allow = 0;
static unsigned long total_block = 0;
static unsigned long total_cfi_ok = 0;
static unsigned long total_cfi_fail = 0;
static unsigned long total_nr_mismatch = 0;
static unsigned long total_fork = 0;
static unsigned long total_fexit = 0;
static unsigned long total_permissive = 0;
static unsigned long total_learn = 0;
static unsigned long total_lib_deny = 0;
static unsigned long total_shadow_ok = 0;
static unsigned long total_shadow_fail = 0;
static unsigned long total_fallback = 0;
static unsigned long total_kobj_deny = 0;
static unsigned long total_events = 0;

static struct tui_event history[MAX_HISTORY];
static int history_count = 0;
static int history_idx = 0; // Ring buffer write index

static struct syscall_stats sys_stats[MAX_SYSCALLS];
static int sys_stats_count = 0;

static const char *syscall_name(unsigned int nr) {
  switch (nr) {
  case 0:   return "read";
  case 1:   return "write";
  case 2:   return "open";
  case 3:   return "close";
  case 9:   return "mmap";
  case 10:  return "mprotect";
  case 16:  return "ioctl";
  case 33:  return "dup2";
  case 42:  return "connect";
  case 46:  return "sendmsg";
  case 56:  return "clone";
  case 57:  return "fork";
  case 59:  return "execve";
  case 101: return "ptrace";
  case 157: return "prctl";
  case 257: return "openat";
  case 311: return "vm_writev";
  case 317: return "seccomp";
  case 272: return "unshare";
  case 308: return "setns";
  case 319: return "memfd_create";
  case 321: return "bpf";
  default:  return NULL;
  }
}

// Find or create stats entry for a syscall number
static struct syscall_stats *get_stats(unsigned int nr) {
  for (int i = 0; i < sys_stats_count; i++) {
    if (sys_stats[i].nr == nr)
      return &sys_stats[i];
  }
  if (sys_stats_count < MAX_SYSCALLS) {
    struct syscall_stats *s = &sys_stats[sys_stats_count++];
    memset(s, 0, sizeof(*s));
    s->nr = nr;
    return s;
  }
  return NULL;
}

// Minimal JSON string value extraction (no external dependency)
static int json_get_str(const char *json, const char *key, char *out, size_t max) {
  char pat[64];
  snprintf(pat, sizeof(pat), "\"%s\":\"", key);
  const char *p = strstr(json, pat);
  if (!p) return 0;
  p += strlen(pat);
  const char *end = strchr(p, '"');
  if (!end) return 0;
  size_t len = (size_t)(end - p);
  if (len >= max) len = max - 1;
  memcpy(out, p, len);
  out[len] = '\0';
  return 1;
}

static int json_get_uint(const char *json, const char *key, unsigned int *out) {
  char pat[64];
  snprintf(pat, sizeof(pat), "\"%s\":", key);
  const char *p = strstr(json, pat);
  if (!p) return 0;
  p += strlen(pat);
  while (*p == ' ') p++;
  if (*p == '"') {
    // String-encoded number (e.g., "0x...")
    return 0;
  }
  *out = (unsigned int)strtoul(p, NULL, 10);
  return 1;
}

static int json_get_long(const char *json, const char *key, long *out) {
  char pat[64];
  snprintf(pat, sizeof(pat), "\"%s\":", key);
  const char *p = strstr(json, pat);
  if (!p) return 0;
  p += strlen(pat);
  while (*p == ' ') p++;
  *out = strtol(p, NULL, 10);
  return 1;
}

static int parse_event(const char *line, struct tui_event *evt) {
  memset(evt, 0, sizeof(*evt));
  if (!json_get_str(line, "action", evt->action, sizeof(evt->action)))
    return 0;
  json_get_uint(line, "pid", &evt->pid);
  json_get_uint(line, "tid", &evt->tid);
  json_get_uint(line, "syscall_nr", &evt->syscall_nr);
  json_get_str(line, "rip", evt->rip, sizeof(evt->rip));
  json_get_str(line, "offset", evt->offset, sizeof(evt->offset));
  json_get_uint(line, "module", &evt->module);
  json_get_str(line, "ts", evt->timestamp, sizeof(evt->timestamp));
  evt->is_fexit = (strcmp(evt->action, "FEXIT") == 0);
  if (evt->is_fexit)
    json_get_long(line, "ret", &evt->ret);
  return 1;
}

static void update_stats(const struct tui_event *evt) {
  total_events++;

  if (strcmp(evt->action, "ALLOW") == 0 || strcmp(evt->action, "ALLOW+CFI") == 0) {
    total_allow++;
    if (strcmp(evt->action, "ALLOW+CFI") == 0)
      total_cfi_ok++;
    struct syscall_stats *s = get_stats(evt->syscall_nr);
    if (s) s->allow_count++;
  } else if (strcmp(evt->action, "BLOCK") == 0) {
    total_block++;
    struct syscall_stats *s = get_stats(evt->syscall_nr);
    if (s) s->block_count++;
  } else if (strcmp(evt->action, "CFI-FAIL") == 0) {
    total_cfi_fail++;
    total_block++;
  } else if (strcmp(evt->action, "NR-MISMATCH") == 0) {
    total_nr_mismatch++;
    total_block++;
  } else if (strcmp(evt->action, "FORK-TRACK") == 0) {
    total_fork++;
  } else if (strcmp(evt->action, "FEXIT") == 0) {
    total_fexit++;
    struct syscall_stats *s = get_stats(evt->syscall_nr);
    if (s) s->fexit_count++;
  } else if (strcmp(evt->action, "PERMISSIVE") == 0) {
    total_permissive++;
    total_block++;
  } else if (strcmp(evt->action, "DLOPEN-EXT") == 0) {
    // Informational: library loaded, no counter needed
  } else if (strcmp(evt->action, "LEARN") == 0) {
    total_learn++;
  } else if (strcmp(evt->action, "LIB-DENY") == 0) {
    total_lib_deny++;
    total_block++;
  } else if (strcmp(evt->action, "SHADOW-OK") == 0) {
    total_shadow_ok++;
  } else if (strcmp(evt->action, "SHADOW-FAIL") == 0) {
    total_shadow_fail++;
    total_block++;
  } else if (strcmp(evt->action, "FALLBACK") == 0) {
    total_fallback++;
    total_block++;
  } else if (strcmp(evt->action, "KOBJ-DENY") == 0) {
    total_kobj_deny++;
    total_block++;
  }

  // Add to ring buffer
  history[history_idx] = *evt;
  history_idx = (history_idx + 1) % MAX_HISTORY;
  if (history_count < MAX_HISTORY)
    history_count++;
}

static int get_term_width(void) {
  struct winsize ws;
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
    return ws.ws_col;
  return 80;
}

static int get_term_height(void) {
  struct winsize ws;
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0)
    return ws.ws_row;
  return 24;
}

static const char *action_color(const char *action) {
  if (strcmp(action, "ALLOW") == 0 || strcmp(action, "ALLOW+CFI") == 0)
    return GREEN;
  if (strcmp(action, "BLOCK") == 0 || strcmp(action, "CFI-FAIL") == 0 ||
      strcmp(action, "NR-MISMATCH") == 0)
    return RED;
  if (strcmp(action, "FORK-TRACK") == 0)
    return CYAN;
  if (strcmp(action, "FEXIT") == 0)
    return YELLOW;
  return RESET;
}

static void render(void) {
  int width = get_term_width();
  int height = get_term_height();

  printf(CLR);

  // Header bar
  printf(BOLD CYAN);
  for (int i = 0; i < width; i++) putchar('=');
  printf(RESET "\n");
  printf(BOLD "  Sentinel-CC Dashboard v%s" RESET, VERSION);

  // Uptime / event rate
  static time_t start_time = 0;
  if (start_time == 0) start_time = time(NULL);
  time_t elapsed = time(NULL) - start_time;
  if (elapsed > 0) {
    printf("  |  %lu events  |  %lu evt/s  |  uptime %lds",
           total_events, total_events / (unsigned long)elapsed, (long)elapsed);
  }
  printf("\n");

  printf(BOLD CYAN);
  for (int i = 0; i < width; i++) putchar('=');
  printf(RESET "\n");

  // Summary counters
  printf(BOLD "  Counters:" RESET "\n");
  printf("    " GREEN "ALLOW: %lu" RESET "  " RED "BLOCK: %lu" RESET
         "  " GREEN "CFI-OK: %lu" RESET "  " RED "CFI-FAIL: %lu" RESET
         "  " RED "NR-MISMATCH: %lu" RESET "  " CYAN "FORK: %lu" RESET
         "  " YELLOW "FEXIT: %lu" RESET,
         total_allow, total_block, total_cfi_ok, total_cfi_fail,
         total_nr_mismatch, total_fork, total_fexit);
  if (total_permissive > 0)
    printf("  " YELLOW "PERMISSIVE: %lu" RESET, total_permissive);
  if (total_learn > 0)
    printf("  " YELLOW "LEARN: %lu" RESET, total_learn);
  if (total_shadow_ok > 0)
    printf("  " GREEN "SHADOW-OK: %lu" RESET, total_shadow_ok);
  if (total_shadow_fail > 0)
    printf("  " RED "SHADOW-FAIL: %lu" RESET, total_shadow_fail);
  if (total_lib_deny > 0)
    printf("  " RED "LIB-DENY: %lu" RESET, total_lib_deny);
  if (total_fallback > 0)
    printf("  " RED "FALLBACK: %lu" RESET, total_fallback);
  printf("\n\n");

  // Per-syscall breakdown
  if (sys_stats_count > 0) {
    printf(BOLD "  Per-Syscall Breakdown:" RESET "\n");
    printf("    %-14s %10s %10s %10s\n", "Syscall", "Allow", "Block", "Fexit");
    printf("    %-14s %10s %10s %10s\n", "──────────────", "──────────",
           "──────────", "──────────");
    int shown = 0;
    for (int i = 0; i < sys_stats_count && shown < 12; i++) {
      const char *name = syscall_name(sys_stats[i].nr);
      char label[32];
      if (name)
        snprintf(label, sizeof(label), "%s(%u)", name, sys_stats[i].nr);
      else
        snprintf(label, sizeof(label), "NR=%u", sys_stats[i].nr);
      printf("    %-14s " GREEN "%10lu" RESET " " RED "%10lu" RESET
             " " YELLOW "%10lu" RESET "\n",
             label, sys_stats[i].allow_count,
             sys_stats[i].block_count, sys_stats[i].fexit_count);
      shown++;
    }
    printf("\n");
  }

  // Recent events (live tail)
  int avail = height - 16 - (sys_stats_count > 0 ? sys_stats_count + 4 : 0);
  if (avail < 3) avail = 3;
  if (avail > history_count) avail = history_count;

  printf(BOLD "  Recent Events (%d shown):" RESET "\n", avail);
  printf(DIM "    %-12s %-6s %-6s %-3s %-14s %-12s" RESET "\n",
         "Action", "PID", "TID", "NR", "RIP", "Offset/Ret");

  for (int i = 0; i < avail; i++) {
    // Read backwards from ring buffer
    int idx = (history_idx - 1 - i + MAX_HISTORY) % MAX_HISTORY;
    struct tui_event *e = &history[idx];
    const char *color = action_color(e->action);

    if (e->is_fexit) {
      printf("    %s%-12s" RESET " %-6u %-6u %-3u %-14s ret=%-ld\n",
             color, e->action, e->pid, e->tid, e->syscall_nr,
             "-", e->ret);
    } else {
      printf("    %s%-12s" RESET " %-6u %-6u %-3u %-14s %s\n",
             color, e->action, e->pid, e->tid, e->syscall_nr,
             e->rip[0] ? e->rip : "-",
             e->offset[0] ? e->offset : "-");
    }
  }

  printf("\n" DIM "  Press Ctrl+C to exit" RESET "\n");
  fflush(stdout);
}

int main(int argc, char **argv) {
  if (argc > 1 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
    printf("Sentinel-CC Terminal Dashboard v%s\n\n", VERSION);
    printf("Usage: sentinel-loader --audit --audit-format=json ./binary | %s\n\n",
           argv[0]);
    printf("Reads JSON audit events from stdin and displays a live terminal\n");
    printf("dashboard with counters, per-syscall breakdown, and event tail.\n");
    return 0;
  }
  if (argc > 1 && (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-v") == 0)) {
    printf("Sentinel-CC Terminal Dashboard v%s\n", VERSION);
    return 0;
  }

  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);

  // Detect if stdin is a terminal (no pipe)
  if (isatty(STDIN_FILENO)) {
    fprintf(stderr, "sentinel-tui: no input detected.\n");
    fprintf(stderr, "Usage: sentinel-loader --audit --audit-format=json ./binary"
                    " | sentinel-tui\n");
    return 1;
  }

  setbuf(stdout, NULL);

  char line[4096];
  time_t last_render = 0;

  while (g_running && fgets(line, sizeof(line), stdin)) {
    // Skip lines that aren't JSON
    char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '{') continue;

    struct tui_event evt;
    if (parse_event(p, &evt)) {
      update_stats(&evt);

      // Render at most 4 times per second to avoid flicker
      time_t now = time(NULL);
      if (now != last_render) {
        render();
        last_render = now;
      }
    }
  }

  // Final render
  render();
  printf("\n" BOLD "Session complete. %lu total events processed." RESET "\n",
         total_events);

  return 0;
}
