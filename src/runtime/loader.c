#include "../../sentinel.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <gelf.h>
#include <keyutils.h>
#include <libelf.h>
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

// Helper: Parse /proc/PID/maps to find Libc Base Address
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

// Helper: Get Main Binary Base Address (for PIE binaries)
unsigned long get_binary_base(pid_t pid, const char *bin_name) {
  char path[64], line[256];
  snprintf(path, sizeof(path), "/proc/%d/maps", pid);
  FILE *fp = fopen(path, "r");
  if (!fp)
    return 0;

  unsigned long base = 0;
  while (fgets(line, sizeof(line), fp)) {
    if (strstr(line, bin_name)) { // Simplified match
      sscanf(line, "%lx", &base);
      break;
    }
  }
  fclose(fp);
  return base;
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
    // We ensure ld.so runs enough to map libc, but not enough to run main.
    while (1) {
      libc_base = get_libc_base(child);
      if (libc_base != 0)
        break; // Found it!

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

    bin_base = get_binary_base(child, "victim_phase2");

    printf("[Loader] Detected Libc Base: 0x%lx (after %d syscall steps)\n",
           libc_base, steps);
    printf("[Loader] Detected Binary Base: 0x%lx\n", bin_base);

    // 5. Update VMA Map (LPM Trie)
    int vma_fd = bpf_map__fd(skel->maps.vma_map);

    // Entry for Libc
    struct vma_key k1 = {.prefixlen = 64, .addr = libc_base};
    struct vma_value v1 = {.module_id = MODULE_LIBC, .base_addr = libc_base};
    bpf_map_update_elem(vma_fd, &k1, &v1, BPF_ANY);

    // Entry for Main Binary
    struct vma_key k2 = {.prefixlen = 64, .addr = bin_base};
    struct vma_value v2 = {.module_id = MODULE_MAIN, .base_addr = bin_base};
    bpf_map_update_elem(vma_fd, &k2, &v2, BPF_ANY);

    // 6. Create Inner Policy Maps
    int registry_fd = bpf_map__fd(skel->maps.policy_registry);

    // Create Libc Policy Map
    int libc_map_fd =
        bpf_map_create(BPF_MAP_TYPE_HASH, "libc_policy", sizeof(uint64_t),
                       sizeof(uint64_t), 1024, NULL);
    uint32_t mod_libc = MODULE_LIBC;
    bpf_map_update_elem(registry_fd, &mod_libc, &libc_map_fd, BPF_ANY);

    // Populate Libc Policy
    // Offset for 'write' (from nm -D /lib64/libc.so.6)
    uint64_t libc_write_offset = 0xe91e0;
    uint64_t val = 1;
    bpf_map_update_elem(libc_map_fd, &libc_write_offset, &val, BPF_ANY);

    printf("[Loader] Whitelisted Libc 'write' at offset 0x%lx\n",
           libc_write_offset);

    // 7. Track PID (CRITICAL: Must be done before detach)
    int pid_map = bpf_map__fd(skel->maps.target_pid_map);
    uint32_t pid = child;
    bpf_map_update_elem(pid_map, &pid, &pid, BPF_ANY);

    printf("[Loader] Policy Loaded. Detaching to let child run.\n");
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
