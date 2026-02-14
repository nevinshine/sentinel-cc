// loader.c
// Phase 1.2: Reads policy directly from the ELF .sentinel section (PCC)
// Precise Labels: Keys are exact syscall instruction addresses.

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
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

// Must match the struct in SentinelPass.cpp associated with policy entries
struct sentinel_entry {
  uint64_t site_addr; // Exact address of the syscall instruction
  uint64_t func_addr; // Address of the containing function
  uint64_t size;      // Size (currently 0)
};

// Must match the struct in sentinel.bpf.c (Phase 3) map value
struct policy_rule {
  uint64_t allowed_caller_start;
  uint64_t allowed_caller_end;
};

void handle_openssl_error() {
  ERR_print_errors_fp(stderr);
  exit(1);
}

// -----------------------------------------------------------------------------
// Verify Binary Signature
// -----------------------------------------------------------------------------
void verify_signature(const char *binary_path, const char *pubkey_path) {
  if (elf_version(EV_CURRENT) == EV_NONE) {
    fprintf(stderr, "ELF Init Failed: %s\n", elf_errmsg(-1));
    exit(1);
  }

  int fd = open(binary_path, O_RDONLY);
  if (fd < 0) {
    perror("open binary");
    exit(1);
  }

  Elf *e = elf_begin(fd, ELF_C_READ, NULL);
  if (!e) {
    fprintf(stderr, "elf_begin Failed\n");
    exit(1);
  }

  size_t shstrndx;
  elf_getshdrstrndx(e, &shstrndx);

  Elf_Scn *scn = NULL;
  Elf_Data *text = NULL, *sentinel = NULL, *sig = NULL;
  int found = 0;

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
    fprintf(stderr, "[FATAL] Missing security sections in binary.\n");
    fprintf(stderr, "This binary is NOT signed by the trust chain.\n");
    exit(1);
  }

  // Load Public Key from Linux Kernel Keyring
  // Phase 1.4: Root of Trust. Key is not on disk (pub.pem), but in kernel.
  // We use the "User" keyring for this demo. Production would use
  // ".builtin_trusted_keys".

  // 1. Search for the key by description "sentinel:pubkey"
  key_serial_t key_id =
      keyctl_search(KEY_SPEC_USER_KEYRING, "user", "sentinel:pubkey", 0);
  if (key_id == -1) {
    perror("[FATAL] Public key not found in Kernel Keyring");
    fprintf(stderr, "Hint: Did you run 'keyctl add user sentinel:pubkey "
                    "\"$(cat pub.pem)\" @u'?\n");
    exit(1);
  }

  // 2. Read key size
  long key_len = keyctl_read(key_id, NULL, 0);
  if (key_len < 0) {
    perror("keyctl_read size");
    exit(1);
  }

  // 3. Allocate buffer and read key
  char *key_buf = malloc(key_len);
  if (!key_buf) {
    perror("malloc");
    exit(1);
  }
  if (keyctl_read(key_id, key_buf, key_len) < 0) {
    perror("keyctl_read data");
    exit(1);
  }

  // 4. Parse PEM from memory
  BIO *bio = BIO_new_mem_buf(key_buf, key_len);
  EVP_PKEY *pub = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);

  BIO_free(bio);
  free(key_buf);

  if (!pub)
    handle_openssl_error();

  // Verify Hash
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
            "[FATAL] Signature Verification FAILED! Binary may be tampered.\n");
    exit(1);
  }
}

int main(int argc, char **argv) {
  setbuf(stdout, NULL); // Disable output buffering

  if (argc < 2) {
    fprintf(stderr, "Usage: %s <binary_path>\n", argv[0]);
    return 1;
  }

  // Phase 1.3: Verify Signature BEFORE loading BPF
  verify_signature(argv[1], "pub.pem");

  // 1. Setup BPF
  struct sentinel_bpf *skel;
  int err;
  skel = sentinel_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

  if (sentinel_bpf__attach(skel)) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    return 1;
  }

  // 2. Open ELF to find .sentinel section
  if (elf_version(EV_CURRENT) == EV_NONE) {
    fprintf(stderr, "ELF library initialization failed: %s\n", elf_errmsg(-1));
    return 1;
  }

  int fd = open(argv[1], O_RDONLY, 0);
  if (fd < 0) {
    perror("Failed to open binary");
    return 1;
  }

  Elf *e = elf_begin(fd, ELF_C_READ, NULL);
  if (!e) {
    fprintf(stderr, "elf_begin() failed: %s\n", elf_errmsg(-1));
    return 1;
  }

  size_t shstrndx;
  if (elf_getshdrstrndx(e, &shstrndx) != 0) {
    fprintf(stderr, "elf_getshdrstrndx() failed: %s\n", elf_errmsg(-1));
    return 1;
  }

  Elf_Scn *scn = NULL;
  GElf_Shdr shdr;
  Elf_Data *data = NULL;

  printf("[Loader] Scanning ELF for .sentinel section...\n");

  while ((scn = elf_nextscn(e, scn)) != NULL) {
    gelf_getshdr(scn, &shdr);
    char *name = elf_strptr(e, shstrndx, shdr.sh_name);

    if (name && strcmp(name, ".sentinel") == 0) {
      data = elf_getdata(scn, NULL);
      break;
    }
  }

  if (!data) {
    fprintf(stderr, "[Error] No .sentinel section found in binary!\n");
    return 1;
  }

  // 3. Load Policy from ELF into Kernel
  int map_fd = bpf_map__fd(skel->maps.policy_map);
  int count = shdr.sh_size / sizeof(struct sentinel_entry);
  struct sentinel_entry *entries = (struct sentinel_entry *)data->d_buf;

  printf("[Loader] Found %d precise policy entries. Loading into Kernel...\n",
         count);

  for (int i = 0; i < count; i++) {
    // Phase 1.2: Site == Syscall Instruction Address (BlockAddress).
    // BPF 'ip' is Address AFTER syscall (2 bytes '0f 05').
    // So Map Key MUST be Site + 2.

    unsigned long key = entries[i].site_addr + 2;

    // Mocking the "Caller Range" for now (Self-Call within function).
    // Since we don't extract exact function size yet, assume [Func, Func +
    // 0x1000].
    struct policy_rule val = {entries[i].func_addr,
                              entries[i].func_addr + 0x1000};

    int ret = bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
    if (ret != 0) {
      fprintf(stderr, "Failed to update map for 0x%lx: %d\n", key, ret);
    } else {
      printf(
          "   [+] Allowed: 0x%lx (Instruction Offset matches Run-Time RIP)\n",
          key);
    }
  }

  // 4. Exec Victim in child process
  pid_t child = fork();
  if (child == 0) {
    execv(argv[1], &argv[1]);
    perror("execv failed");
    return 1;
  }

  // Parent process: Set up PID map
  int pid_map_fd = bpf_map__fd(skel->maps.target_pid_map);
  u_int32_t pkey = 0, pval = child;
  bpf_map_update_elem(pid_map_fd, &pkey, &pval, BPF_ANY);

  printf("[Loader] Target PID: %d\n", child);
  printf("[Loader] BPF enforcer active. Waiting for victim to finish...\n");

  wait(NULL);

  // Cleanup
  sentinel_bpf__destroy(skel);
  elf_end(e);
  close(fd);

  return 0;
}
