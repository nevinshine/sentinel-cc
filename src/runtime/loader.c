// loader.c — Sentinel-CC Runtime Loader
// Verifies binary signature, parses .sentinel policy, resolves dynamic
// library symbols, sets up BPF enforcement, and manages child lifecycle.
//
// Usage: ./loader [--help] [--version] [--audit] <binary> [args...]

#include "../common/sentinel_shared.h"

#include "../../sentinel.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <keyutils.h>
#include <libelf.h>
#include <limits.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

// --- Loader-specific constants ---
#define VMA_BLOCK_SIZE  0x100000UL // 1MB
#define VMA_BLOCK_PREFIX 44        // 64 - 20 = 44 bits for 1MB blocks
#define MAX_POLICY_ENTRIES 4096
#define PTRACE_STEP_LIMIT 10000

// --- Policy Entry from .sentinel section ---
// Must match the struct layout the compiler pass generates:
//   { void *site, void *function, int64_t size }
struct sentinel_policy_entry {
  uint64_t site_addr;   // Absolute address of syscall site
  uint64_t func_addr;   // Absolute address of enclosing function
  int64_t  syscall_nr;  // Phase 3: encoded syscall number (0=any, >0 = nr+1)
};

// --- Global state for signal handler cleanup ---
static struct sentinel_bpf *g_skel = NULL;
static pid_t g_child = -1;
static volatile sig_atomic_t g_shutdown = 0;

// =============================================================================
// Signal Handler — graceful cleanup
// =============================================================================
static void signal_handler(int sig) {
  g_shutdown = 1;
  if (g_child > 0) {
    kill(g_child, SIGTERM);
    waitpid(g_child, NULL, WNOHANG);
  }
  if (g_skel) {
    sentinel_bpf__destroy(g_skel);
    g_skel = NULL;
  }
  fprintf(stderr, "\n[Loader] Caught signal %d, cleaned up. Exiting.\n", sig);
  _exit(128 + sig);
}

static void install_signal_handlers(void) {
  struct sigaction sa = {.sa_handler = signal_handler, .sa_flags = 0};
  sigemptyset(&sa.sa_mask);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGHUP, &sa, NULL);
}

// =============================================================================
// OpenSSL Error Handler
// =============================================================================
static void handle_openssl_error(const char *context) {
  fprintf(stderr, "[FATAL] OpenSSL error in %s:\n", context);
  ERR_print_errors_fp(stderr);
  exit(1);
}

// Forward declaration (defined after libc call-graph infrastructure)
static int is_key_revoked(EVP_PKEY *pub);

// =============================================================================
// Verify Binary Signature via Kernel Keyring
// Returns the verified open fd on success (caller must close), or -1 on error.
// Keeping the fd open prevents TOCTOU — caller can fexecve() from this fd.
// =============================================================================
static int verify_signature(const char *binary_path) {
  int ret = -1;
  int fd = -1;
  Elf *e = NULL;
  EVP_PKEY *pub = NULL;
  EVP_MD_CTX *mdctx = NULL;
  char *keybuf = NULL;
  BIO *bio = NULL;

  if (elf_version(EV_CURRENT) == EV_NONE) {
    fprintf(stderr, "[FATAL] ELF library init failed: %s\n", elf_errmsg(-1));
    goto out;
  }

  fd = open(binary_path, O_RDONLY);
  if (fd < 0) {
    perror("[FATAL] open binary");
    goto out;
  }

  e = elf_begin(fd, ELF_C_READ, NULL);
  if (!e) {
    fprintf(stderr, "[FATAL] elf_begin: %s\n", elf_errmsg(-1));
    goto out;
  }

  size_t shstrndx;
  if (elf_getshdrstrndx(e, &shstrndx) != 0) {
    fprintf(stderr, "[FATAL] Cannot get section string table.\n");
    goto out;
  }

  Elf_Scn *scn = NULL;
  Elf_Data *text = NULL, *sentinel = NULL, *sig = NULL;
  Elf_Data *sentinel_imports = NULL, *sentinel_cfi = NULL;
  GElf_Shdr shdr;

  while ((scn = elf_nextscn(e, scn)) != NULL) {
    gelf_getshdr(scn, &shdr);
    char *name = elf_strptr(e, shstrndx, shdr.sh_name);
    if (!name)
      continue;
    if (strcmp(name, ".text") == 0)
      text = elf_getdata(scn, NULL);
    else if (strcmp(name, ".sentinel") == 0)
      sentinel = elf_getdata(scn, NULL);
    else if (strcmp(name, ".signature") == 0)
      sig = elf_getdata(scn, NULL);
    else if (strcmp(name, ".sentinel_imports") == 0)
      sentinel_imports = elf_getdata(scn, NULL);
    else if (strcmp(name, ".sentinel_cfi") == 0)
      sentinel_cfi = elf_getdata(scn, NULL);
  }

  if (!text || !sentinel || !sig) {
    fprintf(stderr, "[FATAL] Missing security sections (.text=%p .sentinel=%p "
                    ".signature=%p)\n",
            (void *)text, (void *)sentinel, (void *)sig);
    goto out;
  }

  // Load Public Key from Session Keyring
  key_serial_t key_id =
      keyctl_search(KEY_SPEC_SESSION_KEYRING, "user", "sentinel:pubkey", 0);
  if (key_id == -1) {
    // Fallback: try user keyring
    key_id = keyctl_search(KEY_SPEC_USER_KEYRING, "user", "sentinel:pubkey", 0);
  }
  if (key_id == -1) {
    fprintf(stderr,
            "[FATAL] Key 'sentinel:pubkey' not found in any keyring.\n"
            "  Add it with: keyctl add user sentinel:pubkey \"$(cat pub.pem)\" @s\n");
    goto out;
  }

  long klen = keyctl_read(key_id, NULL, 0);
  if (klen <= 0) {
    perror("[FATAL] keyctl_read size");
    goto out;
  }

  keybuf = malloc(klen);
  if (!keybuf) {
    perror("[FATAL] malloc");
    goto out;
  }

  long read_len = keyctl_read(key_id, keybuf, klen);
  if (read_len != klen) {
    fprintf(stderr, "[FATAL] Key read incomplete (%ld/%ld).\n", read_len, klen);
    goto out;
  }

  bio = BIO_new_mem_buf(keybuf, klen);
  pub = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  if (!pub)
    handle_openssl_error("PEM_read_bio_PUBKEY");

  // Key revocation check
  if (is_key_revoked(pub)) {
    fprintf(stderr, "[FATAL] Refusing to accept signature from revoked key.\n");
    goto out;
  }

  mdctx = EVP_MD_CTX_new();
  if (!mdctx)
    handle_openssl_error("EVP_MD_CTX_new");

  // Compute SHA-256(.text + .sentinel [+ .sentinel_cfi] [+ .sentinel_imports])
  // Both sign_tool and loader use the same section order.
  unsigned char hash[32];
  {
    EVP_MD_CTX *hash_ctx = EVP_MD_CTX_new();
    if (!hash_ctx)
      handle_openssl_error("EVP_MD_CTX_new (hash)");
    unsigned int hash_len = 0;
    if (EVP_DigestInit_ex(hash_ctx, EVP_sha256(), NULL) <= 0 ||
        EVP_DigestUpdate(hash_ctx, text->d_buf, text->d_size) <= 0 ||
        EVP_DigestUpdate(hash_ctx, sentinel->d_buf, sentinel->d_size) <= 0) {
      EVP_MD_CTX_free(hash_ctx);
      handle_openssl_error("SHA-256 hash (base)");
    }
    // Include .sentinel_cfi if present (alphabetical order)
    if (sentinel_cfi && sentinel_cfi->d_buf && sentinel_cfi->d_size > 0) {
      if (EVP_DigestUpdate(hash_ctx, sentinel_cfi->d_buf,
                           sentinel_cfi->d_size) <= 0) {
        EVP_MD_CTX_free(hash_ctx);
        handle_openssl_error("SHA-256 hash (.sentinel_cfi)");
      }
    }
    // Include .sentinel_imports if present
    if (sentinel_imports && sentinel_imports->d_buf &&
        sentinel_imports->d_size > 0) {
      if (EVP_DigestUpdate(hash_ctx, sentinel_imports->d_buf,
                           sentinel_imports->d_size) <= 0) {
        EVP_MD_CTX_free(hash_ctx);
        handle_openssl_error("SHA-256 hash (.sentinel_imports)");
      }
    }
    if (EVP_DigestFinal_ex(hash_ctx, hash, &hash_len) <= 0) {
      EVP_MD_CTX_free(hash_ctx);
      handle_openssl_error("SHA-256 hash (final)");
    }
    EVP_MD_CTX_free(hash_ctx);
  }

  // Ed25519: NULL digest — algorithm has its own internal hash
  if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pub) <= 0)
    handle_openssl_error("DigestVerifyInit");

  // Ed25519 single-shot verify
  ret = EVP_DigestVerify(mdctx, sig->d_buf, sig->d_size, hash, sizeof(hash));

out:
  if (mdctx)
    EVP_MD_CTX_free(mdctx);
  if (pub)
    EVP_PKEY_free(pub);
  if (bio)
    BIO_free(bio);
  free(keybuf);
  if (e)
    elf_end(e);

  if (ret == 1) {
    printf("[Loader] Signature Verified. Integrity Confirmed.\n");
    return fd;  // Return verified fd — caller uses fexecve()
  } else {
    if (fd >= 0)
      close(fd);
    fprintf(stderr,
            "[FATAL] Signature Verification FAILED! Binary may be tampered.\n");
    return -1;
  }
}

// =============================================================================
// Parse .sentinel section — extract policy offsets from the binary itself
// Returns number of entries found, fills offsets[] array with text-relative
// offsets of each syscall site.
// =============================================================================
static int parse_sentinel_section(const char *binary_path, uint64_t *offsets,
                                  int64_t *syscall_nrs, int max_entries,
                                  uint64_t *text_base_out,
                                  uint64_t *elf_load_base_out) {
  int count = 0;
  int fd = -1;
  Elf *e = NULL;

  if (elf_version(EV_CURRENT) == EV_NONE)
    return -1;

  fd = open(binary_path, O_RDONLY);
  if (fd < 0)
    return -1;

  e = elf_begin(fd, ELF_C_READ, NULL);
  if (!e)
    goto out;

  // Parse ELF load base from first PT_LOAD segment
  // For PIE (ET_DYN): typically 0x0
  // For non-PIE (ET_EXEC): typically 0x400000
  size_t phnum = 0;
  uint64_t elf_load_base = 0;
  int found_load = 0;
  elf_getphdrnum(e, &phnum);
  for (size_t i = 0; i < phnum; i++) {
    GElf_Phdr phdr;
    if (gelf_getphdr(e, i, &phdr) && phdr.p_type == PT_LOAD) {
      elf_load_base = phdr.p_vaddr;
      found_load = 1;
      break;
    }
  }
  if (elf_load_base_out)
    *elf_load_base_out = elf_load_base;
  if (!found_load)
    fprintf(stderr, "[Warn] No PT_LOAD found; assuming load_base=0\n");

  size_t shstrndx;
  if (elf_getshdrstrndx(e, &shstrndx) != 0)
    goto out;

  Elf_Scn *scn = NULL;
  Elf_Data *sentinel_data = NULL;
  GElf_Shdr shdr;
  uint64_t text_addr = 0;

  while ((scn = elf_nextscn(e, scn)) != NULL) {
    gelf_getshdr(scn, &shdr);
    char *name = elf_strptr(e, shstrndx, shdr.sh_name);
    if (!name)
      continue;
    if (strcmp(name, ".sentinel") == 0)
      sentinel_data = elf_getdata(scn, NULL);
    if (strcmp(name, ".text") == 0)
      text_addr = shdr.sh_addr;
  }

  if (!sentinel_data || sentinel_data->d_size == 0)
    goto out;

  if (text_base_out)
    *text_base_out = text_addr;

  // Each entry is { void *site, void *function, int64_t size } = 24 bytes
  size_t entry_size = sizeof(struct sentinel_policy_entry);
  int n = sentinel_data->d_size / entry_size;

  printf("[Loader] .sentinel section: %d entries (%zu bytes)\n", n,
         sentinel_data->d_size);

  for (int i = 0; i < n && count < max_entries; i++) {
    struct sentinel_policy_entry *pe =
        (struct sentinel_policy_entry *)((char *)sentinel_data->d_buf +
                                         i * entry_size);
    // Skip dummy/null entries
    if (pe->site_addr == 0)
      continue;

    // Store the virtual address — we'll convert to offset after ASLR resolve
    offsets[count] = pe->site_addr;
    // Phase 3: Decode syscall number (0 = any, >0 = nr + 1)
    int64_t decoded_nr = (pe->syscall_nr > 0) ? (pe->syscall_nr - 1) : -1;
    if (syscall_nrs)
      syscall_nrs[count] = decoded_nr;
    printf("[Loader]   Policy[%d]: site=0x%lx func=0x%lx nr=%ld\n", count,
           (unsigned long)pe->site_addr, (unsigned long)pe->func_addr,
           (long)decoded_nr);
    count++;
  }

out:
  if (e)
    elf_end(e);
  if (fd >= 0)
    close(fd);
  return count;
}

// =============================================================================
// Scan a libc function for 'syscall' opcodes (0x0f 0x05) and return their
// exact offsets. The BPF hook captures rip-2 = address of the 'syscall'
// instruction, so we must whitelist THOSE offsets, not the function start.
// =============================================================================
#define LIBC_SCAN_DEFAULT 128 // fallback scan window when st_size==0

static int resolve_libc_syscall_sites(const char *libc_path,
                                      const char *sym_name,
                                      uint64_t *offsets_out,
                                      int max_offsets) {
  int fd = -1;
  Elf *e = NULL;
  int count = 0;
  uint64_t sym_addr = 0, sym_size = 0;

  if (elf_version(EV_CURRENT) == EV_NONE)
    return 0;
  fd = open(libc_path, O_RDONLY);
  if (fd < 0)
    return 0;
  e = elf_begin(fd, ELF_C_READ, NULL);
  if (!e) {
    close(fd);
    return 0;
  }

  // 1. Find the symbol (address + size)
  Elf_Scn *scn = NULL;
  GElf_Shdr shdr;
  while ((scn = elf_nextscn(e, scn)) != NULL) {
    gelf_getshdr(scn, &shdr);
    if (shdr.sh_type != SHT_DYNSYM && shdr.sh_type != SHT_SYMTAB)
      continue;
    Elf_Data *data = elf_getdata(scn, NULL);
    if (!data)
      continue;
    int nsyms = (int)(shdr.sh_size / shdr.sh_entsize);
    for (int i = 0; i < nsyms; i++) {
      GElf_Sym sym;
      gelf_getsym(data, i, &sym);
      char *name = elf_strptr(e, shdr.sh_link, sym.st_name);
      if (name && strcmp(name, sym_name) == 0 && sym.st_value != 0) {
        sym_addr = sym.st_value;
        sym_size = sym.st_size;
        break;
      }
    }
    if (sym_addr)
      break;
  }

  if (!sym_addr) {
    elf_end(e);
    close(fd);
    return 0;
  }
  if (sym_size == 0)
    sym_size = LIBC_SCAN_DEFAULT;

  // 2. Find the executable section containing this symbol
  scn = NULL;
  while ((scn = elf_nextscn(e, scn)) != NULL) {
    gelf_getshdr(scn, &shdr);
    if (shdr.sh_type != SHT_PROGBITS)
      continue;
    if (!(shdr.sh_flags & SHF_EXECINSTR))
      continue;
    if (sym_addr < shdr.sh_addr ||
        sym_addr >= shdr.sh_addr + shdr.sh_size)
      continue;

    Elf_Data *data = elf_getdata(scn, NULL);
    if (!data || !data->d_buf)
      break;

    uint64_t off_in_sec = sym_addr - shdr.sh_addr;
    uint8_t *bytes = (uint8_t *)data->d_buf + off_in_sec;
    uint64_t limit = sym_size;
    if (off_in_sec + limit > data->d_size)
      limit = data->d_size - off_in_sec;

    // 3. Scan for 0x0f 0x05 (syscall opcode)
    for (uint64_t j = 0; j + 1 < limit && count < max_offsets; j++) {
      if (bytes[j] == 0x0f && bytes[j + 1] == 0x05) {
        offsets_out[count++] = sym_addr + j;
      }
    }
    break;
  }

  elf_end(e);
  close(fd);
  return count;
}

// =============================================================================
// Find libc.so path from /proc/PID/maps
// =============================================================================
static int find_libc_path(pid_t pid, char *out_path, size_t path_size) {
  char maps_path[64], line[512];
  snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
  FILE *fp = fopen(maps_path, "r");
  if (!fp)
    return -1;

  while (fgets(line, sizeof(line), fp)) {
    // Match only real libc — avoid libcrypto, libcap, libcurl, etc.
    if ((strstr(line, "/libc.so") || strstr(line, "/libc-")) &&
        !strstr(line, "libcrypto") && !strstr(line, "libcap")) {
      // Extract path: it's the last field after the inode
      char *path = strchr(line, '/');
      if (path) {
        // Strip trailing newline
        char *nl = strchr(path, '\n');
        if (nl)
          *nl = '\0';
        strncpy(out_path, path, path_size - 1);
        out_path[path_size - 1] = '\0';
        fclose(fp);
        return 0;
      }
    }
  }
  fclose(fp);
  return -1;
}

// =============================================================================
// Generic: find a module's full path from /proc/PID/maps
// =============================================================================
static int find_module_path(pid_t pid, const char *needle,
                            char *out_path, size_t path_size) {
  char maps_path[64], line[512];
  snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
  FILE *fp = fopen(maps_path, "r");
  if (!fp)
    return -1;
  while (fgets(line, sizeof(line), fp)) {
    if (!strstr(line, needle))
      continue;
    char *path = strchr(line, '/');
    if (path) {
      char *nl = strchr(path, '\n');
      if (nl)
        *nl = '\0';
      strncpy(out_path, path, path_size - 1);
      out_path[path_size - 1] = '\0';
      fclose(fp);
      return 0;
    }
  }
  fclose(fp);
  return -1;
}

// =============================================================================
// Scan an ELF binary's executable sections for all 'syscall' (0f 05) opcodes.
// Returns ELF-relative offsets of each syscall instruction found.
// =============================================================================
static int scan_elf_text_for_syscalls(const char *path,
                                      uint64_t *offsets_out,
                                      int max_offsets) {
  int fd = -1;
  Elf *e = NULL;
  int count = 0;

  if (elf_version(EV_CURRENT) == EV_NONE)
    return 0;
  fd = open(path, O_RDONLY);
  if (fd < 0)
    return 0;
  e = elf_begin(fd, ELF_C_READ, NULL);
  if (!e) {
    close(fd);
    return 0;
  }

  Elf_Scn *scn = NULL;
  GElf_Shdr shdr;
  while ((scn = elf_nextscn(e, scn)) != NULL) {
    gelf_getshdr(scn, &shdr);
    if (shdr.sh_type != SHT_PROGBITS)
      continue;
    if (!(shdr.sh_flags & SHF_EXECINSTR))
      continue;
    Elf_Data *data = elf_getdata(scn, NULL);
    if (!data || !data->d_buf)
      continue;
    uint8_t *bytes = (uint8_t *)data->d_buf;
    for (uint64_t j = 0; j + 1 < data->d_size && count < max_offsets; j++) {
      if (bytes[j] == 0x0f && bytes[j + 1] == 0x05)
        offsets_out[count++] = shdr.sh_addr + j;
    }
  }

  elf_end(e);
  close(fd);
  return count;
}

// =============================================================================
// Per-App Libc Filtering: Call-Graph-Guided Syscall Whitelist
//
// Instead of whitelisting ALL ~400+ syscall sites in libc, only whitelist
// those reachable from the app's actual call graph. This drastically reduces
// the ROP/JOP attack surface in libc.
//
// Algorithm:
//   1. Parse .sentinel_imports from the binary to get external function names
//   2. Build libc's symbol table (addr → name → size)
//   3. BFS from imported symbols through libc's internal call graph:
//      - Scan each function body for E8 (relative CALL) opcodes
//      - Resolve targets to libc symbols
//      - Recursively visit callees
//   4. Collect 0f 05 (syscall) sites only from reachable functions
// =============================================================================

#define MAX_LIBC_SYMS  8192
#define MAX_REACHABLE  4096
#define CALLGRAPH_DEPTH_LIMIT 24
#define DEFAULT_FUNC_SIZE 256  // Fallback when st_size == 0

struct libc_sym_entry {
  uint64_t addr;
  uint64_t size;
  char name[128];
};

// Executable section data for byte scanning
struct exec_section {
  uint64_t vaddr;    // Section virtual address in ELF
  uint8_t *data;     // Raw bytes (malloc'd copy)
  size_t   size;
};

static int sym_addr_cmp(const void *a, const void *b) {
  const struct libc_sym_entry *sa = a, *sb = b;
  if (sa->addr < sb->addr) return -1;
  if (sa->addr > sb->addr) return 1;
  return 0;
}

// Build sorted symbol table from libc ELF (both .dynsym and .symtab)
static int build_libc_symtab(const char *path, struct libc_sym_entry *out,
                             int max) {
  int fd = -1, count = 0;
  Elf *e = NULL;

  if (elf_version(EV_CURRENT) == EV_NONE) return 0;
  fd = open(path, O_RDONLY);
  if (fd < 0) return 0;
  e = elf_begin(fd, ELF_C_READ, NULL);
  if (!e) { close(fd); return 0; }

  Elf_Scn *scn = NULL;
  GElf_Shdr shdr;
  while ((scn = elf_nextscn(e, scn)) != NULL) {
    gelf_getshdr(scn, &shdr);
    if (shdr.sh_type != SHT_DYNSYM && shdr.sh_type != SHT_SYMTAB)
      continue;
    Elf_Data *data = elf_getdata(scn, NULL);
    if (!data) continue;
    int nsyms = (int)(shdr.sh_size / shdr.sh_entsize);
    for (int i = 0; i < nsyms && count < max; i++) {
      GElf_Sym sym;
      gelf_getsym(data, i, &sym);
      // Only function symbols with nonzero address
      if (GELF_ST_TYPE(sym.st_info) != STT_FUNC || sym.st_value == 0)
        continue;
      char *name = elf_strptr(e, shdr.sh_link, sym.st_name);
      if (!name || name[0] == '\0') continue;
      // Deduplicate by address (aliases)
      int dup = 0;
      for (int j = 0; j < count; j++) {
        if (out[j].addr == sym.st_value) { dup = 1; break; }
      }
      if (dup) continue;
      out[count].addr = sym.st_value;
      out[count].size = sym.st_size ? sym.st_size : DEFAULT_FUNC_SIZE;
      strncpy(out[count].name, name, 127);
      out[count].name[127] = '\0';
      count++;
    }
  }

  elf_end(e);
  close(fd);

  // Sort by address for binary search
  qsort(out, count, sizeof(out[0]), sym_addr_cmp);
  return count;
}

// Find symbol containing a given address via binary search
static struct libc_sym_entry *find_sym_at_addr(struct libc_sym_entry *syms,
                                               int n, uint64_t addr) {
  int lo = 0, hi = n - 1;
  while (lo <= hi) {
    int mid = (lo + hi) / 2;
    if (addr < syms[mid].addr)
      hi = mid - 1;
    else if (addr >= syms[mid].addr + syms[mid].size)
      lo = mid + 1;
    else
      return &syms[mid];
  }
  // Fallback: find the nearest symbol below addr
  for (int i = n - 1; i >= 0; i--) {
    if (syms[i].addr <= addr && addr < syms[i].addr + syms[i].size)
      return &syms[i];
    if (syms[i].addr < addr)
      break;
  }
  return NULL;
}

// Find symbol by name (linear scan — called once per import)
static struct libc_sym_entry *find_sym_by_name(struct libc_sym_entry *syms,
                                               int n, const char *name) {
  for (int i = 0; i < n; i++) {
    if (strcmp(syms[i].name, name) == 0)
      return &syms[i];
  }
  return NULL;
}

// Load executable sections from libc ELF
static int load_exec_sections(const char *path, struct exec_section *out,
                              int max) {
  int fd = -1, count = 0;
  Elf *e = NULL;
  if (elf_version(EV_CURRENT) == EV_NONE) return 0;
  fd = open(path, O_RDONLY);
  if (fd < 0) return 0;
  e = elf_begin(fd, ELF_C_READ, NULL);
  if (!e) { close(fd); return 0; }

  Elf_Scn *scn = NULL;
  GElf_Shdr shdr;
  while ((scn = elf_nextscn(e, scn)) != NULL && count < max) {
    gelf_getshdr(scn, &shdr);
    if (shdr.sh_type != SHT_PROGBITS || !(shdr.sh_flags & SHF_EXECINSTR))
      continue;
    Elf_Data *data = elf_getdata(scn, NULL);
    if (!data || !data->d_buf || data->d_size == 0) continue;
    out[count].vaddr = shdr.sh_addr;
    out[count].data = malloc(data->d_size);
    if (!out[count].data) continue;
    memcpy(out[count].data, data->d_buf, data->d_size);
    out[count].size = data->d_size;
    count++;
  }

  elf_end(e);
  close(fd);
  return count;
}

static void free_exec_sections(struct exec_section *secs, int n) {
  for (int i = 0; i < n; i++) free(secs[i].data);
}

// Get raw bytes for a given address range from loaded sections
static uint8_t *get_bytes_at(struct exec_section *secs, int nsecs,
                             uint64_t addr, size_t len, size_t *avail) {
  for (int i = 0; i < nsecs; i++) {
    if (addr >= secs[i].vaddr &&
        addr < secs[i].vaddr + secs[i].size) {
      uint64_t off = addr - secs[i].vaddr;
      *avail = secs[i].size - off;
      if (*avail > len) *avail = len;
      return secs[i].data + off;
    }
  }
  *avail = 0;
  return NULL;
}

// Parse .sentinel_imports from binary ELF.
// Returns number of imports found; fills imports[] with pointers into blob.
// Caller must free(*blob).
static int parse_sentinel_imports(const char *binary_path,
                                  char ***imports_out, char **blob_out) {
  int fd = -1, count = 0;
  Elf *e = NULL;
  *imports_out = NULL;
  *blob_out = NULL;

  if (elf_version(EV_CURRENT) == EV_NONE) return 0;
  fd = open(binary_path, O_RDONLY);
  if (fd < 0) return 0;
  e = elf_begin(fd, ELF_C_READ, NULL);
  if (!e) { close(fd); return 0; }

  size_t shstrndx;
  if (elf_getshdrstrndx(e, &shstrndx) != 0) goto out;

  Elf_Scn *scn = NULL;
  GElf_Shdr shdr;
  while ((scn = elf_nextscn(e, scn)) != NULL) {
    gelf_getshdr(scn, &shdr);
    char *name = elf_strptr(e, shstrndx, shdr.sh_name);
    if (name && strcmp(name, ".sentinel_imports") == 0) {
      Elf_Data *data = elf_getdata(scn, NULL);
      if (!data || !data->d_buf || data->d_size == 0) break;

      // Copy blob
      char *blob = malloc(data->d_size);
      if (!blob) break;
      memcpy(blob, data->d_buf, data->d_size);

      // Count null-terminated strings
      int n = 0;
      for (size_t i = 0; i < data->d_size; i++) {
        if (blob[i] == '\0') n++;
      }
      char **arr = calloc(n, sizeof(char *));
      if (!arr) { free(blob); break; }

      int idx = 0;
      char *p = blob;
      char *end = blob + data->d_size;
      while (p < end && idx < n) {
        if (*p != '\0') {
          arr[idx++] = p;
          p += strlen(p) + 1;
        } else {
          p++;
        }
      }

      *blob_out = blob;
      *imports_out = arr;
      count = idx;
      break;
    }
  }

out:
  if (e) elf_end(e);
  if (fd >= 0) close(fd);
  return count;
}

// Parse .sentinel_cfi section: array of {site_addr, func_addr} pairs.
// Caller uses this + ELF symtab to set up per-site CFI ranges.
struct sentinel_cfi_entry {
  uint64_t site_addr;
  uint64_t func_addr;
};

static int parse_sentinel_cfi(const char *binary_path,
                              struct sentinel_cfi_entry *out, int max) {
  int fd = -1, count = 0;
  Elf *e = NULL;

  if (elf_version(EV_CURRENT) == EV_NONE) return 0;
  fd = open(binary_path, O_RDONLY);
  if (fd < 0) return 0;
  e = elf_begin(fd, ELF_C_READ, NULL);
  if (!e) { close(fd); return 0; }

  size_t shstrndx;
  if (elf_getshdrstrndx(e, &shstrndx) != 0) goto out;

  Elf_Scn *scn = NULL;
  GElf_Shdr shdr;
  while ((scn = elf_nextscn(e, scn)) != NULL) {
    gelf_getshdr(scn, &shdr);
    char *name = elf_strptr(e, shstrndx, shdr.sh_name);
    if (name && strcmp(name, ".sentinel_cfi") == 0) {
      Elf_Data *data = elf_getdata(scn, NULL);
      if (!data || !data->d_buf) break;
      size_t entry_size = sizeof(struct sentinel_cfi_entry);
      int n = data->d_size / entry_size;
      for (int i = 0; i < n && count < max; i++) {
        struct sentinel_cfi_entry *pe =
            (struct sentinel_cfi_entry *)((char *)data->d_buf + i * entry_size);
        if (pe->site_addr != 0) {
          out[count++] = *pe;
        }
      }
      break;
    }
  }

out:
  if (e) elf_end(e);
  if (fd >= 0) close(fd);
  return count;
}

// Trace libc call graph via BFS from entry points.
// Scans function bodies for E8 (relative CALL) opcodes, resolves targets
// to symbols, and collects 0f 05 (syscall) sites from reachable functions.
// Returns number of syscall sites found.
static int trace_libc_callgraph(const char *libc_path,
                                struct libc_sym_entry *syms, int nsyms,
                                char **imports, int nimports,
                                uint64_t *syscall_sites_out, int max_sites,
                                int *reachable_count_out) {
  // Load executable sections
  struct exec_section sections[16];
  int nsecs = load_exec_sections(libc_path, sections, 16);
  if (nsecs == 0) return 0;

  // BFS work queue (indices into syms[])
  int *queue = calloc(MAX_REACHABLE, sizeof(int));
  uint8_t *visited = calloc(nsyms, sizeof(uint8_t));
  if (!queue || !visited) {
    free(queue); free(visited);
    free_exec_sections(sections, nsecs);
    return 0;
  }

  int q_head = 0, q_tail = 0;

  // Seed the BFS with imported symbols
  for (int i = 0; i < nimports; i++) {
    struct libc_sym_entry *sym = find_sym_by_name(syms, nsyms, imports[i]);
    if (!sym) continue;
    int idx = sym - syms;
    if (!visited[idx] && q_tail < MAX_REACHABLE) {
      visited[idx] = 1;
      queue[q_tail++] = idx;
    }
  }

  // Also seed common aliases that glibc uses internally.
  // These are trampoline symbols that multiple wrappers call into,
  // plus functions commonly reached via indirect calls (FILE vtables,
  // allocator internals) that pure E8/E9 scanning can't follow.
  const char *essential_seeds[] = {
      "__syscall_cancel_arch", "__syscall_cancel",
      "__internal_syscall_cancel", "__libc_do_syscall",
      // Commonly reached via FILE vtable / stdio internals
      "__GI___ioctl", "__ioctl", "ioctl",
      "__isatty", "isatty", "__isatty_nostatus",
      "__tcgetattr", "tcgetattr",
      "__GI___fstat64", "__fstat64", "__fxstat64", "fstat", "__fstat",
      "__GI___lseek64", "__lseek64", "lseek64", "lseek",
      // Memory allocator internals (brk/mmap paths)
      "__brk", "__sbrk", "__mmap", "__munmap",
      // Signal-related (frequently called via indirect dispatch)
      "__sigaction", "__rt_sigaction", "__sigprocmask",
      // Exit / atexit handlers
      "_exit", "__GI__exit", "__exit_funcs",
      NULL
  };
  for (int i = 0; essential_seeds[i]; i++) {
    struct libc_sym_entry *sym = find_sym_by_name(syms, nsyms, essential_seeds[i]);
    if (!sym) continue;
    int idx = sym - syms;
    if (!visited[idx] && q_tail < MAX_REACHABLE) {
      visited[idx] = 1;
      queue[q_tail++] = idx;
    }
  }

  // Auto-discover glibc internal variants: for every imported symbol "foo",
  // also seed "__foo", "__GI_foo", "__GI___foo", "__foo_nostatus", etc.
  // This catches glibc's naming convention where public wrappers delegate
  // to internal implementations via function pointers (FILE vtables, etc.).
  for (int i = 0; i < nimports; i++) {
    const char *imp = imports[i];
    // Strip leading underscores to get the base name
    const char *base = imp;
    while (*base == '_') base++;
    int base_len = strlen(base);
    if (base_len < 2) continue;

    for (int s = 0; s < nsyms; s++) {
      if (visited[s] || q_tail >= MAX_REACHABLE) continue;
      const char *sn = syms[s].name;
      // Match: exact import, __import, __GI_import, __GI___import,
      // import_nostatus, __import_nostatus, __import_nocancel, etc.
      if (strstr(sn, base) != NULL &&
          (strncmp(sn, "__", 2) == 0 || strncmp(sn, base, base_len) == 0)) {
        visited[s] = 1;
        queue[q_tail++] = s;
      }
    }
  }

  // BFS through call graph
  int depth_limit = CALLGRAPH_DEPTH_LIMIT;
  int depth_boundary = q_tail;
  int current_depth = 0;

  while (q_head < q_tail && current_depth < depth_limit) {
    int sym_idx = queue[q_head++];
    struct libc_sym_entry *sym = &syms[sym_idx];

    // Track BFS depth
    if (q_head > depth_boundary) {
      current_depth++;
      depth_boundary = q_tail;
    }

    // Get function bytes
    size_t avail = 0;
    uint8_t *bytes = get_bytes_at(sections, nsecs, sym->addr, sym->size, &avail);
    if (!bytes || avail < 5) continue;

    // Scan for E8 rel32 (CALL) and E9 rel32 (JMP, tail calls)
    for (size_t j = 0; j + 4 < avail; j++) {
      if (bytes[j] != 0xE8 && bytes[j] != 0xE9) continue;
      // Compute target: addr_after_insn + displacement
      int32_t disp;
      memcpy(&disp, &bytes[j + 1], 4);
      uint64_t call_addr = sym->addr + j;
      uint64_t target = call_addr + 5 + (int64_t)disp;

      // Resolve target to a symbol
      struct libc_sym_entry *callee = find_sym_at_addr(syms, nsyms, target);
      if (!callee) continue;
      int callee_idx = callee - syms;
      if (!visited[callee_idx] && q_tail < MAX_REACHABLE) {
        visited[callee_idx] = 1;
        queue[q_tail++] = callee_idx;
      }
    }
  }

  *reachable_count_out = q_tail;

  // Collect syscall sites (0f 05) from all reachable functions
  int nsites = 0;
  for (int i = 0; i < q_tail && nsites < max_sites; i++) {
    struct libc_sym_entry *sym = &syms[queue[i]];
    size_t avail = 0;
    uint8_t *bytes = get_bytes_at(sections, nsecs, sym->addr, sym->size, &avail);
    if (!bytes) continue;
    for (size_t j = 0; j + 1 < avail && nsites < max_sites; j++) {
      if (bytes[j] == 0x0f && bytes[j + 1] == 0x05) {
        syscall_sites_out[nsites++] = sym->addr + j;
      }
    }
  }

  free(queue);
  free(visited);
  free_exec_sections(sections, nsecs);
  return nsites;
}

// =============================================================================
// Key Revocation: Check if the current public key is revoked
// Reads /etc/sentinel/revoked_keys (SHA-256 fingerprints, hex, one per line)
// =============================================================================
static int is_key_revoked(EVP_PKEY *pub) {
  // Compute SHA-256 fingerprint of the public key DER encoding
  unsigned char *der = NULL;
  int der_len = i2d_PUBKEY(pub, &der);
  if (der_len <= 0) return 0; // Can't check — allow

  unsigned char fp[32];
  unsigned int fp_len = 0;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) { OPENSSL_free(der); return 0; }
  EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
  EVP_DigestUpdate(ctx, der, der_len);
  EVP_DigestFinal_ex(ctx, fp, &fp_len);
  EVP_MD_CTX_free(ctx);
  OPENSSL_free(der);

  // Convert to hex string
  char fp_hex[65];
  for (unsigned int i = 0; i < fp_len; i++)
    snprintf(fp_hex + i * 2, 3, "%02x", fp[i]);
  fp_hex[64] = '\0';

  // Check revocation file
  FILE *rfp = fopen("/etc/sentinel/revoked_keys", "r");
  if (!rfp) return 0; // No revocation file — not revoked
  char line[256];
  while (fgets(line, sizeof(line), rfp)) {
    // Strip newline
    char *nl = strchr(line, '\n');
    if (nl) *nl = '\0';
    // Skip comments and empty lines
    if (line[0] == '#' || line[0] == '\0') continue;
    if (strncmp(line, fp_hex, 64) == 0) {
      fclose(rfp);
      fprintf(stderr, "[FATAL] Public key is REVOKED (fingerprint: %.16s...)\n",
              fp_hex);
      return 1;
    }
  }
  fclose(rfp);
  return 0;
}

// =============================================================================
// Check if libc is loaded yet
// =============================================================================
static unsigned long get_libc_base(pid_t pid) {
  char path[64], line[256];
  snprintf(path, sizeof(path), "/proc/%d/maps", pid);
  FILE *fp = fopen(path, "r");
  if (!fp)
    return 0;
  unsigned long base = 0;
  while (fgets(line, sizeof(line), fp)) {
    // Anchored match: /libc.so or /libc- to avoid libcrypto, libcap, etc.
    if (strstr(line, "/libc.so") || strstr(line, "/libc-")) {
      sscanf(line, "%lx", &base);
      break;
    }
  }
  fclose(fp);
  return base;
}

// =============================================================================
// Populate VMA entries for a module using 1MB LPM blocks
// =============================================================================
static int populate_vma_for_module(int vma_fd, pid_t pid,
                                   const char *module_name,
                                   uint32_t module_id,
                                   unsigned long *out_base) {
  char path[64], line[512];
  snprintf(path, sizeof(path), "/proc/%d/maps", pid);
  FILE *fp = fopen(path, "r");
  if (!fp)
    return -1;

  unsigned long min_addr = ULONG_MAX, max_addr = 0;
  while (fgets(line, sizeof(line), fp)) {
    if (!strstr(line, module_name))
      continue;
    unsigned long start, end;
    if (sscanf(line, "%lx-%lx", &start, &end) != 2)
      continue;
    if (start < min_addr)
      min_addr = start;
    if (end > max_addr)
      max_addr = end;
  }
  fclose(fp);

  if (min_addr == ULONG_MAX)
    return -1;

  *out_base = min_addr;

  unsigned long block_start = min_addr & ~(VMA_BLOCK_SIZE - 1);
  int count = 0;

  for (unsigned long addr = block_start; addr < max_addr;
       addr += VMA_BLOCK_SIZE) {
    struct vma_key k = {.prefixlen = VMA_BLOCK_PREFIX,
                        .addr = __builtin_bswap64(addr)};
    struct vma_value v = {.module_id = module_id, .base_addr = min_addr};
    if (bpf_map_update_elem(vma_fd, &k, &v, BPF_ANY) == 0)
      count++;
  }

  return count;
}

// =============================================================================
// Scan binary ELF for CFI symbols and set up the cfi_policy map.
// Now reads .sentinel to find the REAL syscall offset instead of guessing.
// =============================================================================
static void setup_cfi_policy(struct sentinel_bpf *skel, const char *bin_path,
                             uint64_t *policy_offsets, int policy_count,
                             uint64_t elf_load_base) {
  int fd = -1;
  Elf *e = NULL;

  if (elf_version(EV_CURRENT) == EV_NONE)
    return;
  fd = open(bin_path, O_RDONLY);
  if (fd < 0)
    return;

  e = elf_begin(fd, ELF_C_READ, NULL);
  if (!e)
    goto out;

  Elf_Scn *scn = NULL;
  GElf_Shdr shdr;
  Elf_Data *data = NULL;

  uint64_t do_write_addr = 0, do_write_size = 0;
  uint64_t safe_caller_addr = 0, safe_caller_size = 0;

  while ((scn = elf_nextscn(e, scn)) != NULL) {
    gelf_getshdr(scn, &shdr);
    if (shdr.sh_type != SHT_SYMTAB)
      continue;

    data = elf_getdata(scn, NULL);
    if (!data)
      continue;

    int nsyms = shdr.sh_size / shdr.sh_entsize;
    for (int i = 0; i < nsyms; i++) {
      GElf_Sym sym;
      gelf_getsym(data, i, &sym);
      char *name = elf_strptr(e, shdr.sh_link, sym.st_name);
      if (!name)
        continue;
      if (strcmp(name, "do_write") == 0) {
        do_write_addr = sym.st_value;
        do_write_size = sym.st_size;
      }
      if (strcmp(name, "safe_caller") == 0) {
        safe_caller_addr = sym.st_value;
        safe_caller_size = sym.st_size;
      }
    }
  }

  if (!do_write_addr || !safe_caller_addr) {
    printf("[Loader] No CFI symbols found (not a CFI test binary).\n");
    goto out;
  }

  // Convert ELF absolute addresses to module-relative offsets
  do_write_addr -= elf_load_base;
  safe_caller_addr -= elf_load_base;

  printf("[Loader] CFI Symbols: do_write=0x%lx(%lu bytes), "
         "safe_caller=0x%lx(%lu bytes)\n",
         (unsigned long)do_write_addr, (unsigned long)do_write_size,
         (unsigned long)safe_caller_addr, (unsigned long)safe_caller_size);

  // Find the syscall offset that falls within do_write using .sentinel data
  uint64_t syscall_offset = 0;
  int found_in_sentinel = 0;

  for (int i = 0; i < policy_count; i++) {
    uint64_t adj = policy_offsets[i] - elf_load_base;
    if (adj >= do_write_addr &&
        adj < do_write_addr + do_write_size) {
      syscall_offset = adj;
      found_in_sentinel = 1;
      printf("[Loader] CFI: Found syscall in do_write via .sentinel at 0x%lx\n",
             (unsigned long)syscall_offset);
      break;
    }
  }

  if (!found_in_sentinel) {
    // Fallback heuristic if .sentinel didn't give us one inside do_write
    syscall_offset = do_write_addr + 16;
    printf("[Loader] CFI: Using heuristic syscall offset 0x%lx\n",
           (unsigned long)syscall_offset);
  }

  // Update CFI Map
  int cfi_fd = bpf_map__fd(skel->maps.cfi_policy);
  struct cfi_range range = {.start = safe_caller_addr,
                            .end = safe_caller_addr + safe_caller_size};

  if (bpf_map_update_elem(cfi_fd, &syscall_offset, &range, BPF_ANY) != 0)
    fprintf(stderr, "[Warn] Failed to update CFI policy map: %s\n",
            strerror(errno));
  printf("[Loader] CFI Policy: Syscall@0x%lx REQUIRES Caller[0x%lx-0x%lx]\n",
         (unsigned long)syscall_offset, (unsigned long)range.start,
         (unsigned long)range.end);

out:
  if (e)
    elf_end(e);
  if (fd >= 0)
    close(fd);
}

// =============================================================================
// Audit ring buffer callback
// =============================================================================
static const char *action_str(uint8_t action) {
  switch (action) {
  case EVENT_ALLOW:       return "ALLOW";
  case EVENT_BLOCK:       return "BLOCK";
  case EVENT_CFI_OK:      return "ALLOW+CFI";
  case EVENT_CFI_FAIL:    return "CFI-FAIL";
  case EVENT_NR_MISMATCH: return "NR-MISMATCH";
  case EVENT_FORK_TRACK:  return "FORK-TRACK";
  default:                return "UNKNOWN";
  }
}

static int audit_event_handler(void *ctx, void *data, size_t data_sz) {
  (void)ctx;
  if (data_sz < sizeof(struct audit_event))
    return 0;
  struct audit_event *evt = data;
  printf("[Audit] %s PID=%u TID=%u SYS=%u RIP=0x%lx Off=0x%lx Mod=%u\n",
         action_str(evt->action), evt->tgid, evt->tid, evt->syscall_nr,
         (unsigned long)evt->syscall_rip, (unsigned long)evt->offset,
         evt->module_id);
  return 0;
}

// =============================================================================
// CLI
// =============================================================================
static void print_usage(const char *prog) {
  printf("Sentinel-CC Loader v%s\n\n", SENTINEL_VERSION);
  printf("Usage: %s [options] <binary> [args...]\n\n", prog);
  printf("Options:\n");
  printf("  --help       Show this help message\n");
  printf("  --version    Show version\n");
  printf("  --audit      Enable real-time audit event printing\n");
  printf("\nExample:\n");
  printf("  sudo %s ./victim\n", prog);
  printf("  sudo %s --audit ./victim_phase2\n", prog);
}

// =============================================================================
// MAIN
// =============================================================================
int main(int argc, char **argv) {
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  // --- Parse CLI arguments ---
  int audit_mode = 0;
  int arg_start = 1;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      print_usage(argv[0]);
      return 0;
    }
    if (strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-v") == 0) {
      printf("Sentinel-CC Loader v%s\n", SENTINEL_VERSION);
      return 0;
    }
    if (strcmp(argv[i], "--audit") == 0) {
      audit_mode = 1;
      arg_start = i + 1;
      continue;
    }
    // First non-flag argument is the binary
    arg_start = i;
    break;
  }

  if (arg_start >= argc) {
    fprintf(stderr, "[FATAL] No binary specified. Use --help for usage.\n");
    return 1;
  }

  const char *binary = argv[arg_start];

  // --- Install signal handlers for cleanup ---
  install_signal_handlers();

  // --- 1. Verify Signature (returns open fd for TOCTOU-safe exec) ---
  int verified_fd = verify_signature(binary);
  if (verified_fd < 0)
    return 1;

  // --- 2. Parse .sentinel section from binary (the Policy-Carrying Code!) ---
  uint64_t policy_offsets[MAX_POLICY_ENTRIES];
  int64_t policy_syscall_nrs[MAX_POLICY_ENTRIES];
  uint64_t text_vaddr = 0;
  uint64_t elf_load_base = 0;
  int policy_count =
      parse_sentinel_section(binary, policy_offsets, policy_syscall_nrs,
                             MAX_POLICY_ENTRIES, &text_vaddr, &elf_load_base);


  if (policy_count < 0) {
    fprintf(stderr, "[FATAL] Failed to parse .sentinel section.\n");
    return 1;
  }
  if (policy_count == 0)
    printf("[Loader] No inline syscall sites in main binary (libc-only).\n");
  else
    printf("[Loader] Parsed %d policy entries from .sentinel "
           "(text_vaddr=0x%lx, elf_load_base=0x%lx)\n",
           policy_count, (unsigned long)text_vaddr,
           (unsigned long)elf_load_base);

  // --- 3. Setup BPF ---
  g_skel = sentinel_bpf__open();
  if (!g_skel) {
    fprintf(stderr, "[FATAL] Failed to open BPF skeleton.\n");
    return 1;
  }
  g_skel->rodata->audit_mode = audit_mode ? 1 : 0;
  if (sentinel_bpf__load(g_skel)) {
    fprintf(stderr, "[FATAL] Failed to load BPF programs.\n");
    sentinel_bpf__destroy(g_skel);
    return 1;
  }
  if (sentinel_bpf__attach(g_skel) != 0) {
    fprintf(stderr, "[FATAL] Failed to attach BPF programs.\n");
    sentinel_bpf__destroy(g_skel);
    return 1;
  }
  printf("[Loader] BPF programs loaded and attached.\n");

  // --- 4. Setup audit ring buffer if requested ---
  struct ring_buffer *rb = NULL;
  if (audit_mode) {
    int rb_fd = bpf_map__fd(g_skel->maps.audit_ringbuf);
    rb = ring_buffer__new(rb_fd, audit_event_handler, NULL, NULL);
    if (!rb)
      fprintf(stderr, "[Warn] Failed to create ring buffer consumer.\n");
    else
      printf("[Loader] Audit mode enabled.\n");
  }

  printf("[Loader] Launching '%s' with Ptrace synchronization...\n", binary);

  // --- 5. Start Victim with Ptrace ---
  g_child = fork();
  if (g_child < 0) {
    perror("[FATAL] fork");
    sentinel_bpf__destroy(g_skel);
    return 1;
  }

  if (g_child == 0) {
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    fexecve(verified_fd, &argv[arg_start], environ);
    perror("[Child] fexecve");
    _exit(1);
  }
  close(verified_fd);  // Parent no longer needs it

  // --- 6. Wait for child exec() trap ---
  int status;
  waitpid(g_child, &status, 0);

  if (!(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)) {
    fprintf(stderr, "[FATAL] Failed to trap child (status=%d)\n", status);
    kill(g_child, SIGKILL);
    waitpid(g_child, NULL, 0);
    sentinel_bpf__destroy(g_skel);
    return 1;
  }

  printf("[Loader] Trapped child at exec(). Waiting for dynamic linker...\n");

  // --- 7. Wait for libc to be loaded (dynamic linker runs first) ---
  unsigned long libc_base = 0, bin_base = 0;
  int steps = 0;

  while (1) {
    libc_base = get_libc_base(g_child);
    if (libc_base != 0)
      break;

    ptrace(PTRACE_SYSCALL, g_child, 0, 0);
    waitpid(g_child, &status, 0);

    if (WIFEXITED(status)) {
      fprintf(stderr, "[Loader] Child exited before libc loaded (static binary?)\n");
      // Static binary — no libc to wait for, proceed with binary-only policy
      break;
    }
    steps++;
    if (steps > PTRACE_STEP_LIMIT) {
      fprintf(stderr, "[Loader] Timeout waiting for libc (%d steps).\n", steps);
      break;
    }
  }

  // --- 8. Populate VMA Map ---
  int vma_fd = bpf_map__fd(g_skel->maps.vma_map);

  const char *bin_name = strrchr(binary, '/');
  bin_name = bin_name ? bin_name + 1 : binary;

  int bin_blocks =
      populate_vma_for_module(vma_fd, g_child, bin_name, MODULE_MAIN, &bin_base);
  printf("[Loader] Binary VMA: base=0x%lx (%d LPM blocks)\n",
         bin_base, bin_blocks);

  int libc_blocks = -1;
  if (libc_base != 0) {
    libc_blocks = populate_vma_for_module(vma_fd, g_child, "libc", MODULE_LIBC,
                                          &libc_base);
    printf("[Loader] Libc VMA: base=0x%lx (%d LPM blocks, after %d steps)\n",
           libc_base, libc_blocks, steps);
  }

  // --- 9. Create Policy Maps and populate from .sentinel ---
  int registry_fd = bpf_map__fd(g_skel->maps.policy_registry);

  // Main binary policy map
  int main_map_fd =
      bpf_map_create(BPF_MAP_TYPE_HASH, "main_policy", sizeof(uint64_t),
                     sizeof(uint64_t), 4096, NULL);
  if (main_map_fd < 0) {
    fprintf(stderr, "[FATAL] Failed to create main policy map: %s\n",
            strerror(errno));
    goto cleanup;
  }

  uint32_t mod_main = MODULE_MAIN;
  if (bpf_map_update_elem(registry_fd, &mod_main, &main_map_fd, BPF_ANY) != 0) {
    fprintf(stderr, "[FATAL] Failed to register main policy map: %s\n",
            strerror(errno));
    close(main_map_fd);
    goto cleanup;
  }

  // Populate main binary policy from .sentinel entries
  // Convert ELF virtual addresses → module-relative offsets
  // BPF computes: offset = rip - base_addr (from /proc/pid/maps)
  // Loader must store: elf_vaddr - elf_load_base
  //   PIE  (ET_DYN):  elf_load_base ≈ 0   → offset ≈ elf_vaddr
  //   Static (ET_EXEC): elf_load_base = 0x400000 → offset = elf_vaddr - 0x400000
  (void)text_vaddr;
  int loaded = 0;
  for (int i = 0; i < policy_count; i++) {
    uint64_t offset = policy_offsets[i]; // ELF absolute virtual address
    uint64_t runtime_offset = offset - elf_load_base;
    // Phase 3: Encode syscall number binding in policy value
    int64_t nr = policy_syscall_nrs[i];
    uint64_t val;
    if (nr >= 0)
      val = POLICY_FLAG_CHECK_NR | (uint64_t)(uint32_t)nr;
    else
      val = 1; // Wildcard: allow any syscall from this offset
    if (bpf_map_update_elem(main_map_fd, &runtime_offset, &val, BPF_ANY) == 0)
      loaded++;
    if (nr >= 0)
      printf("[Loader]   Whitelist: Main offset 0x%lx (nr=%ld)\n",
             (unsigned long)runtime_offset, (long)nr);
    else
      printf("[Loader]   Whitelist: Main offset 0x%lx (nr=any)\n",
             (unsigned long)runtime_offset);
  }
  printf("[Loader] Loaded %d/%d policy entries for main binary.\n", loaded,
         policy_count);

  // --- 10. Resolve and populate libc policy dynamically ---
  // Parse .sentinel_imports for call-graph-guided filtering
  char **app_imports = NULL;
  char *imports_blob = NULL;
  int nimports = parse_sentinel_imports(binary, &app_imports, &imports_blob);

  if (libc_base != 0) {
    int libc_map_fd =
        bpf_map_create(BPF_MAP_TYPE_HASH, "libc_policy", sizeof(uint64_t),
                       sizeof(uint64_t), 4096, NULL);
    if (libc_map_fd < 0) {
      fprintf(stderr, "[Warn] Failed to create libc policy map.\n");
    } else {
      uint32_t mod_libc = MODULE_LIBC;
      if (bpf_map_update_elem(registry_fd, &mod_libc, &libc_map_fd, BPF_ANY) != 0) {
        fprintf(stderr, "[FATAL] Failed to register libc policy map: %s\n",
                strerror(errno));
        close(libc_map_fd);
        goto cleanup;
      }

      // Dynamically resolve libc symbol offsets
      char libc_path[512] = {0};
      if (find_libc_path(g_child, libc_path, sizeof(libc_path)) == 0) {
        printf("[Loader] Libc path: %s\n", libc_path);

        int libc_total = 0;

        // =================================================================
        // Per-App Libc Filtering: Call-Graph-Guided Whitelist
        // =================================================================
        if (nimports > 0) {
          printf("[Loader] Per-app libc filtering: %d imports from "
                 ".sentinel_imports\n", nimports);

          // Build libc symbol table
          struct libc_sym_entry *libc_syms_table =
              calloc(MAX_LIBC_SYMS, sizeof(struct libc_sym_entry));
          if (!libc_syms_table) {
            fprintf(stderr, "[Warn] malloc failed for libc symtab\n");
            goto libc_fallback;
          }

          int nsyms = build_libc_symtab(libc_path, libc_syms_table,
                                        MAX_LIBC_SYMS);
          printf("[Loader] Libc symbol table: %d function symbols\n", nsyms);

          if (nsyms == 0) {
            free(libc_syms_table);
            goto libc_fallback;
          }

          // Trace call graph from imports
          uint64_t cg_sites[2048];
          int reachable_count = 0;
          int cg_nsites = trace_libc_callgraph(libc_path, libc_syms_table,
                                                nsyms, app_imports, nimports,
                                                cg_sites, 2048,
                                                &reachable_count);

          // Now apply nr-binding where possible.
          // Build a quick lookup of known libc wrapper → syscall nr.
          struct { const char *name; uint32_t nr; } nr_bindings[] = {
            {"write", 1}, {"__write", 1}, {"__libc_write", 1},
            {"__write_nocancel", 1},
            {"read", 0}, {"__read", 0}, {"__libc_read", 0},
            {"__read_nocancel", 0},
            {"openat", 257}, {"openat64", 257}, {"__openat_nocancel", 257},
            {"open", 257}, {"open64", 257}, {"__open", 257},
            {"__libc_open", 257}, {"__open_nocancel", 257},
            {"mmap", 9}, {"mmap64", 9}, {"__mmap", 9},
            {"mprotect", 10}, {"__mprotect", 10},
            {"connect", 42}, {"__connect", 42},
            {"memfd_create", 319},
            {"prctl", 157}, {"__prctl", 157},
            {"sendmsg", 46}, {"__sendmsg", 46},
            {"dup2", 33}, {"close", 3}, {"__close", 3},
            {"ioctl", 16},
            {NULL, 0}
          };

          // For each site found by call-graph tracing, check if it falls
          // within a known named wrapper to get nr-binding, else wildcard.
          for (int j = 0; j < cg_nsites; j++) {
            uint64_t site = cg_sites[j];
            uint64_t val = 1; // Default: wildcard

            // Check if this site is inside a known wrapper
            struct libc_sym_entry *containing_sym =
                find_sym_at_addr(libc_syms_table, nsyms, site);
            if (containing_sym) {
              for (int k = 0; nr_bindings[k].name; k++) {
                if (strcmp(containing_sym->name, nr_bindings[k].name) == 0) {
                  val = POLICY_FLAG_CHECK_NR | (uint64_t)nr_bindings[k].nr;
                  break;
                }
              }
            }

            if (bpf_map_update_elem(libc_map_fd, &site, &val, BPF_ANY) == 0)
              libc_total++;
          }

          // Report the filtering result
          uint64_t all_sites[512];
          int total_libc_sites = scan_elf_text_for_syscalls(libc_path,
                                                            all_sites, 512);
          printf("[Loader] Call-graph libc filtering: %d imports → "
                 "%d reachable functions → %d syscall sites\n",
                 nimports, reachable_count, cg_nsites);
          printf("[Loader] Attack surface reduction: %d/%d libc sites "
                 "whitelisted (%.1f%% reduction)\n",
                 libc_total, total_libc_sites,
                 total_libc_sites > 0
                     ? (1.0 - (double)libc_total / total_libc_sites) * 100.0
                     : 0.0);

          free(libc_syms_table);
          goto libc_ld_whitelist; // Skip legacy full-text scan
        }

        // =================================================================
        // LEGACY FALLBACK: Full-text scan (no .sentinel_imports available)
        // =================================================================
libc_fallback:
        printf("[Loader] No .sentinel_imports — using legacy full-text libc scan\n");
        {
        // Whitelist common libc syscall wrappers.
        // Phase 3: Scan each symbol for the actual 'syscall' instruction
        // (0f 05) to get the exact offset that BPF will see at rip-2.
        struct { const char *name; uint32_t nr; } libc_syms[] = {
          // write(2) family  — hooked as SYS_write (1)
          {"write", 1}, {"__write", 1}, {"__libc_write", 1},
          {"__write_nocancel", 1},
          // read(2) family   — hooked as SYS_read (0)
          {"read", 0}, {"__read", 0}, {"__libc_read", 0},
          {"__read_nocancel", 0},
          // open/openat      — glibc routes open() → SYS_openat (257)
          {"openat", 257}, {"openat64", 257}, {"__openat_nocancel", 257},
          {"open", 257}, {"open64", 257}, {"__open", 257},
          {"__open64", 257}, {"__libc_open", 257}, {"__libc_open64", 257},
          {"__open_nocancel", 257}, {"__open64_nocancel", 257},
          // mmap(2) family   — SYS_mmap (9)
          {"mmap", 9}, {"mmap64", 9}, {"__mmap", 9},
          // mprotect(2)      — SYS_mprotect (10)
          {"mprotect", 10}, {"__mprotect", 10},
          // connect(2)       — SYS_connect (42)
          {"connect", 42}, {"__connect", 42},
          // memfd_create(2)  — SYS_memfd_create (319)
          {"memfd_create", 319},
          // prctl(2)         — SYS_prctl (157)
          {"prctl", 157}, {"__prctl", 157},
          // sendmsg(2)       — SYS_sendmsg (46)
          {"sendmsg", 46}, {"__sendmsg", 46},
          // dup2(2)          — SYS_dup2 (33)
          {"dup2", 33},
          // close(2)         — SYS_close (3)
          {"close", 3}, {"__close", 3}, {"__libc_close", 3},
          {"__close_nocancel", 3},
          // ioctl(2)         — SYS_ioctl (16)
          {"ioctl", 16},
          {NULL, 0}
        };
        for (int i = 0; libc_syms[i].name != NULL; i++) {
          uint64_t sites[8];
          int nsites = resolve_libc_syscall_sites(libc_path,
                           libc_syms[i].name, sites, 8);
          for (int j = 0; j < nsites; j++) {
            uint64_t val = POLICY_FLAG_CHECK_NR | (uint64_t)libc_syms[i].nr;
            bpf_map_update_elem(libc_map_fd, &sites[j], &val, BPF_ANY);
            libc_total++;
          }
        }

        // Glibc ≥ 2.34 cancellation trampoline
        const char *cancel_syms[] = {
            "__syscall_cancel_arch", "__syscall_cancel",
            "__internal_syscall_cancel", NULL};
        for (int i = 0; cancel_syms[i] != NULL; i++) {
          uint64_t sites[4];
          int nsites = resolve_libc_syscall_sites(libc_path,
                           cancel_syms[i], sites, 4);
          for (int j = 0; j < nsites; j++) {
            uint64_t val = 1;
            bpf_map_update_elem(libc_map_fd, &sites[j], &val, BPF_ANY);
            libc_total++;
          }
        }

        // Full text scan fallback
        {
          uint64_t all_sites[512];
          int nall = scan_elf_text_for_syscalls(libc_path, all_sites, 512);
          int fallback_added = 0;
          for (int j = 0; j < nall; j++) {
            uint64_t val = 1;
            if (bpf_map_update_elem(libc_map_fd, &all_sites[j], &val,
                                    BPF_NOEXIST) == 0)
              fallback_added++;
          }
          libc_total += fallback_added;
          printf("[Loader] Libc full-text scan: %d total sites, %d new "
                 "wildcard entries added.\n", nall, fallback_added);
        }
        } // end legacy fallback block

        printf("[Loader] Whitelisted %d libc syscall sites total.\n",
               libc_total);

        // --- 10b. Whitelist dynamic linker (ld.so) syscall sites ---
libc_ld_whitelist:
        {
          unsigned long ld_base = 0;
          char ld_path[512] = {0};
          // Find ld.so base from /proc maps
          char maps_path[64], maps_line[512];
          snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", g_child);
          FILE *mfp = fopen(maps_path, "r");
          if (mfp) {
            while (fgets(maps_line, sizeof(maps_line), mfp)) {
              if (strstr(maps_line, "ld-linux") || strstr(maps_line, "ld-musl")) {
                if (ld_base == 0)
                  sscanf(maps_line, "%lx", &ld_base);
                break;
              }
            }
            fclose(mfp);
          }
          if (ld_base != 0 &&
              find_module_path(g_child, "ld-linux", ld_path,
                               sizeof(ld_path)) == 0) {
            printf("[Loader] ld.so path: %s (base=0x%lx)\n",
                   ld_path, ld_base);
            // Scan ld.so for syscall sites (ELF-relative offsets)
            uint64_t sites[256];
            int nsites = scan_elf_text_for_syscalls(ld_path, sites, 256);
            int ld_added = 0;
            for (int j = 0; j < nsites; j++) {
              // Convert ELF offset → runtime addr → libc-relative offset
              // Runtime addr = ld_base + elf_offset (ld.so is PIE, load_base=0)
              // Libc-relative = runtime_addr - libc_base
              uint64_t runtime_addr = ld_base + sites[j];
              uint64_t libc_rel_offset = runtime_addr - libc_base;
              uint64_t val = 1; // Wildcard: trusted
              if (bpf_map_update_elem(libc_map_fd, &libc_rel_offset,
                                      &val, BPF_NOEXIST) == 0)
                ld_added++;
            }
            printf("[Loader] Whitelisted %d ld.so syscall sites "
                   "(as libc-relative offsets).\n", ld_added);

            // Add ld-linux VMA blocks to LPM trie as MODULE_LIBC with
            // base_addr = libc_base. This is critical: the ld.so syscall
            // sites are stored as libc-relative offsets, so the BPF enforcer
            // must compute  offset = RIP - libc_base  (not RIP - ld_base).
            // We can't use populate_vma_for_module() because it would set
            // base_addr = ld_linux_base, producing wrong offsets.
            {
              char ld_mp[64], ld_ml[512];
              snprintf(ld_mp, sizeof(ld_mp), "/proc/%d/maps", g_child);
              FILE *ld_fp = fopen(ld_mp, "r");
              int ld_blocks = 0;
              if (ld_fp) {
                unsigned long ld_min = ULONG_MAX, ld_max = 0;
                while (fgets(ld_ml, sizeof(ld_ml), ld_fp)) {
                  if (!strstr(ld_ml, "ld-linux") && !strstr(ld_ml, "ld-musl"))
                    continue;
                  unsigned long s, e;
                  sscanf(ld_ml, "%lx-%lx", &s, &e);
                  if (s < ld_min) ld_min = s;
                  if (e > ld_max) ld_max = e;
                }
                fclose(ld_fp);
                if (ld_min != ULONG_MAX) {
                  unsigned long blk = ld_min & ~(VMA_BLOCK_SIZE - 1);
                  for (unsigned long a = blk; a < ld_max; a += VMA_BLOCK_SIZE) {
                    struct vma_key k = {.prefixlen = VMA_BLOCK_PREFIX,
                                        .addr = __builtin_bswap64(a)};
                    struct vma_value v = {.module_id = MODULE_LIBC,
                                          .base_addr = libc_base};
                    bpf_map_update_elem(vma_fd, &k, &v, BPF_ANY);
                    ld_blocks++;
                  }
                }
              }
              if (ld_blocks > 0)
                printf("[Loader] ld-linux VMA: %d LPM blocks "
                       "(MODULE_LIBC, base=0x%lx)\n", ld_blocks, libc_base);
            }
          }
        }

      } else {
        fprintf(stderr, "[Warn] Could not find libc path in proc maps.\n");
      }
      close(libc_map_fd);
    }
  }

  // --- 10c. Multi-Library Support: Auto-discover all shared libraries ---
  // Scan /proc/PID/maps for ALL r-xp mappings that aren't the main binary,
  // libc, or ld.so. For each unique library, assign a dynamic module ID,
  // create a policy map, populate with full-text syscall scan, and register.
  {
    char maps_path[64], line[512];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", g_child);
    FILE *mfp = fopen(maps_path, "r");
    if (mfp) {
      // Collect unique library paths from r-xp mappings
      char seen_libs[32][512];
      int n_libs = 0;
      uint32_t next_mod_id = MODULE_DYNAMIC_BASE;

      while (fgets(line, sizeof(line), mfp) && n_libs < 32) {
        // Only look at executable mappings
        if (!strstr(line, "r-xp") && !strstr(line, "r--p"))
          continue;
        // Must have a path (starts with /)
        char *path = strchr(line, '/');
        if (!path)
          continue;
        char *nl = strchr(path, '\n');
        if (nl)
          *nl = '\0';

        // Skip already-handled modules
        if (strstr(path, bin_name))
          continue;
        if (strstr(path, "/libc.so") || strstr(path, "/libc-"))
          continue;
        if (strstr(path, "ld-linux") || strstr(path, "ld-musl"))
          continue;
        // Skip non-library files (e.g., [vdso], locale, etc.)
        if (!strstr(path, ".so"))
          continue;
        // Skip data files that contain '.so' but aren't shared libraries
        if (strstr(path, "ld.so.cache") || strstr(path, "ld.so.conf") ||
            strstr(path, ".cache") || strstr(path, "locale-archive") ||
            strstr(path, "gconv-modules"))
          continue;

        // Deduplicate
        int dup = 0;
        for (int i = 0; i < n_libs; i++) {
          if (strcmp(seen_libs[i], path) == 0) {
            dup = 1;
            break;
          }
        }
        if (dup)
          continue;

        strncpy(seen_libs[n_libs], path, 511);
        seen_libs[n_libs][511] = '\0';
        n_libs++;
      }
      fclose(mfp);

      // For each discovered library, create policy + VMA entries
      for (int i = 0; i < n_libs && next_mod_id < 64; i++) {
        const char *lib_path = seen_libs[i];
        // Extract short name for VMA matching (e.g., "libpthread" from full path)
        const char *short_name = strrchr(lib_path, '/');
        short_name = short_name ? short_name + 1 : lib_path;

        // Create inner policy map for this library
        char map_name[16];
        snprintf(map_name, sizeof(map_name), "lib_pol_%u", next_mod_id);
        int lib_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, map_name,
                                        sizeof(uint64_t), sizeof(uint64_t),
                                        4096, NULL);
        if (lib_map_fd < 0) {
          fprintf(stderr, "[Warn] Failed to create policy map for %s: %s\n",
                  short_name, strerror(errno));
          continue;
        }

        // Register in policy_registry
        uint32_t mod_id = next_mod_id;
        if (bpf_map_update_elem(registry_fd, &mod_id, &lib_map_fd, BPF_ANY) != 0) {
          fprintf(stderr, "[Warn] Failed to register %s (mod=%u): %s\n",
                  short_name, mod_id, strerror(errno));
          close(lib_map_fd);
          continue;
        }

        // Populate VMA blocks
        unsigned long lib_base = 0;
        int lib_blocks = populate_vma_for_module(vma_fd, g_child, short_name,
                                                 mod_id, &lib_base);

        // Full-text syscall scan — whitelist all 0f 05 sites as wildcard
        uint64_t sites[512];
        int nsites = scan_elf_text_for_syscalls(lib_path, sites, 512);
        int added = 0;
        for (int j = 0; j < nsites; j++) {
          uint64_t val = 1; // Wildcard
          if (bpf_map_update_elem(lib_map_fd, &sites[j], &val, BPF_ANY) == 0)
            added++;
        }

        printf("[Loader] Library '%s' (mod=%u): base=0x%lx, %d VMA blocks, "
               "%d/%d syscall sites whitelisted.\n",
               short_name, mod_id, lib_base, lib_blocks, added, nsites);

        close(lib_map_fd);
        next_mod_id++;
      }

      if (n_libs > 0)
        printf("[Loader] Multi-library: discovered %d additional libraries.\n",
               n_libs);
    }
  }

  // --- 11. Setup CFI policy ---
  // First try generalized CFI from .sentinel_cfi section (covers ALL functions)
  {
    struct sentinel_cfi_entry cfi_entries[MAX_POLICY_ENTRIES];
    int ncfi = parse_sentinel_cfi(binary, cfi_entries, MAX_POLICY_ENTRIES);

    if (ncfi > 0) {
      printf("[Loader] Generalized CFI: %d entries from .sentinel_cfi\n", ncfi);
      int cfi_fd = bpf_map__fd(g_skel->maps.cfi_policy);

      // Look up function sizes from the binary's symbol table
      int bin_fd = open(binary, O_RDONLY);
      Elf *bin_elf = NULL;
      if (bin_fd >= 0 && elf_version(EV_CURRENT) != EV_NONE)
        bin_elf = elf_begin(bin_fd, ELF_C_READ, NULL);

      for (int i = 0; i < ncfi; i++) {
        uint64_t site_offset = cfi_entries[i].site_addr - elf_load_base;
        uint64_t func_offset = cfi_entries[i].func_addr - elf_load_base;
        uint64_t func_size = 0;

        // Resolve function size from ELF symbol table
        if (bin_elf) {
          Elf_Scn *scn = NULL;
          GElf_Shdr shdr;
          while ((scn = elf_nextscn(bin_elf, scn)) != NULL) {
            gelf_getshdr(scn, &shdr);
            if (shdr.sh_type != SHT_SYMTAB) continue;
            Elf_Data *data = elf_getdata(scn, NULL);
            if (!data) continue;
            int nsyms = shdr.sh_size / shdr.sh_entsize;
            for (int j = 0; j < nsyms; j++) {
              GElf_Sym sym;
              gelf_getsym(data, j, &sym);
              if (sym.st_value == cfi_entries[i].func_addr &&
                  GELF_ST_TYPE(sym.st_info) == STT_FUNC) {
                func_size = sym.st_size;
                break;
              }
            }
            if (func_size) break;
          }
        }

        // Fallback: use reasonable default if size not found
        if (func_size == 0) func_size = 4096;

        struct cfi_range range = {.start = func_offset,
                                  .end = func_offset + func_size};
        if (bpf_map_update_elem(cfi_fd, &site_offset, &range, BPF_ANY) == 0) {
          printf("[Loader] CFI: site@0x%lx requires caller in [0x%lx-0x%lx]\n",
                 (unsigned long)site_offset, (unsigned long)range.start,
                 (unsigned long)range.end);
        }
      }

      if (bin_elf) elf_end(bin_elf);
      if (bin_fd >= 0) close(bin_fd);
    } else {
      // Fallback: hardcoded CFI (legacy)
      setup_cfi_policy(g_skel, binary, policy_offsets, policy_count,
                       elf_load_base);
    }
  }

  // Free imports
  free(app_imports);
  free(imports_blob);

  // --- 12. Track child TGID ---
  {
    int pid_map = bpf_map__fd(g_skel->maps.target_pid_map);
    uint32_t pid = g_child;
    uint32_t val = 1;
    if (bpf_map_update_elem(pid_map, &pid, &val, BPF_ANY) != 0) {
      fprintf(stderr, "[FATAL] Failed to track child PID: %s\n",
              strerror(errno));
      kill(g_child, SIGKILL);
      waitpid(g_child, NULL, 0);
      goto cleanup;
    }
  }

  printf("[Loader] Policy loaded. Detaching child (PID=%d).\n", g_child);
  ptrace(PTRACE_DETACH, g_child, NULL, NULL);

  // --- 13. Wait for child with optional audit polling ---
  if (rb) {
    // Poll audit events while child runs
    while (!g_shutdown) {
      int wret = waitpid(g_child, &status, WNOHANG);
      if (wret > 0) {
        if (WIFEXITED(status)) {
          printf("[Loader] Child exited with code %d.\n",
                 WEXITSTATUS(status));
          break;
        }
        if (WIFSIGNALED(status)) {
          printf("[Loader] Child killed by signal %d.\n", WTERMSIG(status));
          break;
        }
      }
      ring_buffer__poll(rb, 100 /* ms */);
    }
    ring_buffer__free(rb);
    rb = NULL;
  } else {
    // Simple wait
    waitpid(g_child, &status, 0);
    if (WIFEXITED(status))
      printf("[Loader] Child exited with code %d.\n", WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
      printf("[Loader] Child killed by signal %d.\n", WTERMSIG(status));
  }

  // Fall through to cleanup
cleanup:
  close(main_map_fd);
  if (g_skel) {
    sentinel_bpf__destroy(g_skel);
    g_skel = NULL;
  }
  printf("[Loader] Cleanup complete.\n");
  return 0;
}