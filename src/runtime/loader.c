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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

// Phase 2 Constants
#define MODULE_MAIN 1
#define MODULE_LIBC 2

struct vma_key {
  u_int32_t prefixlen;
  u_int64_t addr;
};

struct vma_value {
  u_int32_t module_id;
  u_int64_t base_addr;
};

struct cfi_range {
  u_int64_t start;
  u_int64_t end;
};

void handle_openssl_error() {
  ERR_print_errors_fp(stderr);
  exit(1);
}

// -----------------------------------------------------------------------------
// Verify Binary Signature (Kernel Keyring Phase 1.4)
// -----------------------------------------------------------------------------
void verify_signature(const char *binary_path) {
  if (elf_version(EV_CURRENT) == EV_NONE)
    exit(1);

  int fd = open(binary_path, O_RDONLY);
  if (fd < 0)
    exit(1);

  Elf *e = elf_begin(fd, ELF_C_READ, NULL);
  size_t shstrndx;
  elf_getshdrstrndx(e, &shstrndx);

  Elf_Scn *scn = NULL;
  Elf_Data *text = NULL, *sentinel = NULL, *sig = NULL;
  GElf_Shdr shdr;

  while ((scn = elf_nextscn(e, scn)) != NULL) {
    gelf_getshdr(scn, &shdr);
    char *name = elf_strptr(e, shstrndx, shdr.sh_name);
    if (!name)
      continue;
    if (strcmp(name, ".text") == 0)
      text = elf_getdata(scn, NULL);
    if (strcmp(name, ".sentinel") == 0)
      sentinel = elf_getdata(scn, NULL);
    if (strcmp(name, ".signature") == 0)
      sig = elf_getdata(scn, NULL);
  }

  if (!text || !sentinel || !sig) {
    fprintf(stderr, "[FATAL] Missing security sections.\n");
    exit(1);
  }

  // Load Public Key from Keyring (Session Keyring for Phase 2 Verification)
  key_serial_t key_id =
      keyctl_search(KEY_SPEC_SESSION_KEYRING, "user", "sentinel:pubkey", 0);
  if (key_id == -1) {
    fprintf(stderr,
            "[FATAL] Key 'sentinel:pubkey' not found in Session Keyring.\n");
    exit(1);
  }

  long len = keyctl_read(key_id, NULL, 0);
  if (len <= 0) {
    perror("[Loader] keyctl_read failed");
    fprintf(stderr, "[FATAL] Key length is invalid or 0.\n");
    exit(1);
  }

  char *buf = malloc(len);
  if (!buf) {
    perror("[FATAL] malloc failed");
    exit(1);
  }

  long read_len = keyctl_read(key_id, buf, len);
  if (read_len != len) {
    fprintf(stderr, "[FATAL] Key read incomplete.\n");
    exit(1);
  }

  BIO *bio = BIO_new_mem_buf(buf, len);
  EVP_PKEY *pub = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);

  BIO_free(bio);
  free(buf);

  if (!pub)
    handle_openssl_error();

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pub) <= 0)
    handle_openssl_error();
  if (EVP_DigestVerifyUpdate(ctx, text->d_buf, text->d_size) <= 0)
    handle_openssl_error();
  if (EVP_DigestVerifyUpdate(ctx, sentinel->d_buf, sentinel->d_size) <= 0)
    handle_openssl_error();

  int ret = EVP_DigestVerifyFinal(ctx, sig->d_buf, sig->d_size);
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pub);
  elf_end(e);
  close(fd);

  if (ret == 1) {
    printf("[Loader] Signature Verified. Integrity Confirmed.\n");
  } else {
    fprintf(stderr,
            "[FATAL] Signature Verification FAILED! Binary tampered.\n");
    exit(1);
  }
}

// Helper: Check if libc is loaded yet
unsigned long get_libc_base(pid_t pid) {
  char path[64], line[256];
  snprintf(path, sizeof(path), "/proc/%d/maps", pid);
  FILE *fp = fopen(path, "r");
  if (!fp)
    return 0;
  unsigned long base = 0;
  while (fgets(line, sizeof(line), fp)) {
    if (strstr(line, "libc.so") || strstr(line, "libc-")) {
      sscanf(line, "%lx", &base);
      break;
    }
  }
  fclose(fp);
  return base;
}

// -----------------------------------------------------------------------------
// Phase 2: Populate VMA entries for a module using 1MB LPM blocks
// Parses ALL mapping lines for the module, inserts entries at 1MB boundaries.
// Returns the module's lowest base address via *out_base.
// -----------------------------------------------------------------------------
#define VMA_BLOCK_SIZE 0x100000UL // 1MB
#define VMA_BLOCK_PREFIX 44       // 64 - 20 = 44 bits for 1MB blocks

int populate_vma_for_module(int vma_fd, pid_t pid, const char *module_name,
                            uint32_t module_id, unsigned long *out_base) {
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
    sscanf(line, "%lx-%lx", &start, &end);
    if (start < min_addr)
      min_addr = start;
    if (end > max_addr)
      max_addr = end;
  }
  fclose(fp);

  if (min_addr == ULONG_MAX)
    return -1;

  *out_base = min_addr;

  // Insert VMA entries at 1MB block boundaries
  unsigned long block_start = min_addr & ~(VMA_BLOCK_SIZE - 1); // Align down
  int count = 0;

  for (unsigned long addr = block_start; addr < max_addr;
       addr += VMA_BLOCK_SIZE) {
    // FIX: Use __builtin_bswap64 to match Big Endian Prefix
    struct vma_key k = {.prefixlen = VMA_BLOCK_PREFIX, .addr = __builtin_bswap64(addr)};
    struct vma_value v = {.module_id = module_id, .base_addr = min_addr};
    bpf_map_update_elem(vma_fd, &k, &v, BPF_ANY);
    count++;
  }

  return count;
}

// -----------------------------------------------------------------------------
// Phase 2.2: Scan binary for CFI symbols dynamically
// -----------------------------------------------------------------------------
void setup_cfi_for_test(struct sentinel_bpf *skel, const char *bin_path) {
  if (elf_version(EV_CURRENT) == EV_NONE)
    return;
  int fd = open(bin_path, O_RDONLY);
  if (fd < 0)
    return;

  Elf *e = elf_begin(fd, ELF_C_READ, NULL);
  Elf_Scn *scn = NULL;
  GElf_Shdr shdr;
  Elf_Data *data = NULL;

  uint64_t do_write_addr = 0;
  uint64_t do_write_size = 0;
  uint64_t safe_caller_addr = 0;
  uint64_t safe_caller_size = 0;

  // 1. Find Symbol Table
  while ((scn = elf_nextscn(e, scn)) != NULL) {
    gelf_getshdr(scn, &shdr);
    if (shdr.sh_type == SHT_SYMTAB) {
      data = elf_getdata(scn, NULL);
      int count = shdr.sh_size / shdr.sh_entsize;
      for (int i = 0; i < count; i++) {
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
  }

  if (do_write_addr && safe_caller_addr) {
    printf("[Loader] Found CFI Symbols: do_write=0x%lx(%lu bytes), "
           "safe_caller=0x%lx(%lu bytes)\n",
           do_write_addr, do_write_size, safe_caller_addr, safe_caller_size);

    // Heuristic: syscall instruction is near the end of do_write's asm block
    // mov $1, %rax (7 bytes) + mov $1, %rdi (5 bytes) + mov, mov, syscall
    // Typical offset ~16 bytes into do_write. In production, parse .sentinel.
    uint64_t syscall_offset = do_write_addr + 16;

    // 2. Update CFI Map
    int cfi_fd = bpf_map__fd(skel->maps.cfi_policy);
    struct cfi_range range = {.start = safe_caller_addr,
                              .end = safe_caller_addr + safe_caller_size};

    bpf_map_update_elem(cfi_fd, &syscall_offset, &range, BPF_ANY);

    // 3. Update Inner Policy for this syscall (allow list)
    int registry_fd = bpf_map__fd(skel->maps.policy_registry);
    uint32_t mod_id = MODULE_MAIN;

    int main_map_fd =
        bpf_map_create(BPF_MAP_TYPE_HASH, "main_policy", sizeof(uint64_t),
                       sizeof(uint64_t), 1024, NULL);
    bpf_map_update_elem(registry_fd, &mod_id, &main_map_fd, BPF_ANY);

    uint64_t ok = 1;
    bpf_map_update_elem(main_map_fd, &syscall_offset, &ok, BPF_ANY);

    printf("[Loader] CFI Policy: Syscall@0x%lx REQUIRES Caller[0x%lx-0x%lx]\n",
           syscall_offset, range.start, range.end);
  } else {
    printf("[Loader] No CFI symbols found (not a CFI test binary).\n");
  }

  elf_end(e);
  close(fd);
}

int main(int argc, char **argv) {
  setbuf(stdout, NULL);
  if (argc < 2)
    return 1;

  // 1. Verify Signature (Phase 1.4)
  verify_signature(argv[1]);

  // 2. Setup BPF
  struct sentinel_bpf *skel = sentinel_bpf__open_and_load();
  if (!skel)
    return 1;
  sentinel_bpf__attach(skel);

  printf("[Loader] Launching victim '%s' with Ptrace synchronization...\n",
         argv[1]);

  // Phase 2.2: Setup CFI policy if this is a CFI test binary
  if (strstr(argv[1], "victim_cfi")) {
    setup_cfi_for_test(skel, argv[1]);
  }

  // 3. Start Victim (Ptrace Traceme)
  pid_t child = fork();
  if (child == 0) {
    // Allow parent to trace me
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    // Exec triggers SIGTRAP to parent
    execv(argv[1], &argv[1]);
    perror("execv");
    exit(1);
  }

  // 4. Parent waits for Child's exec() to complete
  int status;
  waitpid(child, &status, 0);

  if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
    printf("[Loader] Trapped child at exec(). Waiting for Libc...\n");

    unsigned long libc_base = 0;
    unsigned long bin_base = 0;
    int steps = 0;

    // Loop until Libc is loaded (Dynamic Linker running)
    while (1) {
      libc_base = get_libc_base(child);
      if (libc_base != 0)
        break;

      // Not yet. Let child run one syscall.
      ptrace(PTRACE_SYSCALL, child, 0, 0);
      waitpid(child, &status, 0);

      if (WIFEXITED(status)) {
        fprintf(stderr, "[Loader] Child exited before loading libc!\n");
        return 1;
      }
      steps++;
      if (steps > 10000) { // Safety break
        fprintf(stderr, "[Loader] Timeout waiting for Libc.\n");
        break;
      }
    }

    // 5. Populate VMA Map with 1MB-block LPM entries for each module
    int vma_fd = bpf_map__fd(skel->maps.vma_map);

    const char *bin_name = strrchr(argv[1], '/');
    bin_name = bin_name ? bin_name + 1 : argv[1];

    int libc_blocks =
        populate_vma_for_module(vma_fd, child, "libc", MODULE_LIBC, &libc_base);
    int bin_blocks = populate_vma_for_module(vma_fd, child, bin_name,
                                             MODULE_MAIN, &bin_base);

    printf("[Loader] Libc VMA: base=0x%lx (%d LPM blocks, after %d steps)\n",
           libc_base, libc_blocks, steps);
    printf("[Loader] Binary VMA: base=0x%lx (%d LPM blocks)\n", bin_base,
           bin_blocks);

    // 6. Create Inner Policy Maps (if not already created by CFI setup)
    int registry_fd = bpf_map__fd(skel->maps.policy_registry);

    // Create Libc Policy Map
    int libc_map_fd =
        bpf_map_create(BPF_MAP_TYPE_HASH, "libc_policy", sizeof(uint64_t),
                       sizeof(uint64_t), 1024, NULL);
    uint32_t mod_libc = MODULE_LIBC;
    bpf_map_update_elem(registry_fd, &mod_libc, &libc_map_fd, BPF_ANY);

    // Populate Libc Policy
    uint64_t libc_write_offset = 0xe91e0;
    uint64_t val = 1;
    bpf_map_update_elem(libc_map_fd, &libc_write_offset, &val, BPF_ANY);

    printf("[Loader] Whitelisted Libc 'write' at offset 0x%lx\n",
           libc_write_offset);

    // 7. Track TGID (CRITICAL: covers all threads in the process)
    int pid_map = bpf_map__fd(skel->maps.target_pid_map);
    uint32_t pid = child;
    bpf_map_update_elem(pid_map, &pid, &pid, BPF_ANY);

    printf("[Loader] Policy Loaded. Detaching to let child run (PID=%d).\n",
           child);
    ptrace(PTRACE_DETACH, child, NULL, NULL);
  } else {
    fprintf(stderr, "[Loader] Failed to trap child (Status: %d)\n", status);
    kill(child, SIGKILL);
    return 1;
  }

  wait(NULL);
  if (skel)
    sentinel_bpf__destroy(skel);
  return 0;
}