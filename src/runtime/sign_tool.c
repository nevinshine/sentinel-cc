// sign_tool.c — Sentinel-CC Binary Signing Tool
// Signs Hash(.text + .sentinel) with Ed25519 and writes into .signature
//
// Usage: ./sign_tool [--help] [--version] <binary_path> <private_key.pem>

#define SENTINEL_VERSION "4.0.0"

#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SIG_SIZE 64 // Ed25519

static void print_usage(const char *prog) {
  printf("Sentinel-CC Signing Tool v%s\n\n", SENTINEL_VERSION);
  printf("Usage: %s [options] <binary> <private.pem>\n\n", prog);
  printf("Signs a Sentinel-instrumented binary by computing\n");
  printf("Ed25519(SHA-256(.text + .sentinel)) and writing the\n");
  printf("signature into the .signature ELF section.\n\n");
  printf("Options:\n");
  printf("  --help       Show this help message\n");
  printf("  --version    Show version\n");
}

int main(int argc, char **argv) {
  // --- Parse CLI ---
  int arg_start = 1;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      print_usage(argv[0]);
      return 0;
    }
    if (strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-v") == 0) {
      printf("Sentinel-CC Signing Tool v%s\n", SENTINEL_VERSION);
      return 0;
    }
    arg_start = i;
    break;
  }

  if (argc - arg_start < 2) {
    fprintf(stderr, "Usage: %s <binary> <private.pem>\n", argv[0]);
    fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
    return 1;
  }

  const char *bin = argv[arg_start];
  const char *keyfile = argv[arg_start + 1];

  int ret = 1; // Default: failure
  int fd = -1;
  Elf *e = NULL;
  FILE *fp = NULL;
  EVP_PKEY *priv = NULL;
  EVP_MD_CTX *ctx = NULL;

  // 1. Initialize ELF Library
  if (elf_version(EV_CURRENT) == EV_NONE) {
    fprintf(stderr, "[FATAL] ELF Init Failed: %s\n", elf_errmsg(-1));
    goto cleanup;
  }

  fd = open(bin, O_RDWR);
  if (fd < 0) {
    perror("[FATAL] open binary");
    goto cleanup;
  }

  e = elf_begin(fd, ELF_C_RDWR, NULL);
  if (!e) {
    fprintf(stderr, "[FATAL] elf_begin: %s\n", elf_errmsg(-1));
    goto cleanup;
  }

  // 2. Locate Sections
  size_t shstrndx;
  if (elf_getshdrstrndx(e, &shstrndx) != 0) {
    fprintf(stderr, "[FATAL] Cannot get section string table.\n");
    goto cleanup;
  }

  Elf_Scn *scn = NULL;
  Elf_Data *text = NULL, *sentinel = NULL;
  Elf_Data *sentinel_imports = NULL, *sentinel_cfi = NULL;
  off_t sig_offset = 0;
  size_t sig_section_size = 0;
  int found_sections = 0;

  GElf_Shdr shdr;
  while ((scn = elf_nextscn(e, scn)) != NULL) {
    gelf_getshdr(scn, &shdr);
    char *name = elf_strptr(e, shstrndx, shdr.sh_name);
    if (!name)
      continue;

    if (strcmp(name, ".text") == 0) {
      text = elf_getdata(scn, NULL);
      if (text)
        found_sections |= 1;
    }
    if (strcmp(name, ".sentinel") == 0) {
      sentinel = elf_getdata(scn, NULL);
      if (sentinel)
        found_sections |= 2;
    }
    if (strcmp(name, ".signature") == 0) {
      sig_offset = shdr.sh_offset;
      sig_section_size = shdr.sh_size;
      found_sections |= 4;
    }
    if (strcmp(name, ".sentinel_imports") == 0)
      sentinel_imports = elf_getdata(scn, NULL);
    if (strcmp(name, ".sentinel_cfi") == 0)
      sentinel_cfi = elf_getdata(scn, NULL);
  }

  if (found_sections != 7) {
    fprintf(stderr, "[FATAL] Missing sections (found=%d, need=7).\n",
            found_sections);
    if (!(found_sections & 1))
      fprintf(stderr, "  Missing: .text\n");
    if (!(found_sections & 2))
      fprintf(stderr, "  Missing: .sentinel\n");
    if (!(found_sections & 4))
      fprintf(stderr, "  Missing: .signature\n");
    goto cleanup;
  }

  if (sig_section_size < SIG_SIZE) {
    fprintf(stderr, "[FATAL] .signature section too small (%zu < %d).\n",
            sig_section_size, SIG_SIZE);
    goto cleanup;
  }

  printf("[Signer] .text=%zu bytes, .sentinel=%zu bytes", text->d_size,
         sentinel->d_size);
  if (sentinel_cfi && sentinel_cfi->d_buf)
    printf(", .sentinel_cfi=%zu bytes", sentinel_cfi->d_size);
  if (sentinel_imports && sentinel_imports->d_buf)
    printf(", .sentinel_imports=%zu bytes", sentinel_imports->d_size);
  printf("\n");

  // 3. Load Private Key
  fp = fopen(keyfile, "r");
  if (!fp) {
    perror("[FATAL] open keyfile");
    goto cleanup;
  }
  priv = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  fclose(fp);
  fp = NULL;
  if (!priv) {
    fprintf(stderr, "[FATAL] Failed to read private key.\n");
    ERR_print_errors_fp(stderr);
    goto cleanup;
  }

  // 4. Compute & Sign: Ed25519(SHA-256(.text + .sentinel [+ .sentinel_cfi] [+ .sentinel_imports]))
  // Same section order as loader verification — alphabetical for optional sections.
  unsigned char hash[32]; // SHA-256 output
  {
    EVP_MD_CTX *hash_ctx = EVP_MD_CTX_new();
    if (!hash_ctx) {
      fprintf(stderr, "[FATAL] EVP_MD_CTX_new failed.\n");
      goto cleanup;
    }
    unsigned int hash_len = 0;
    if (EVP_DigestInit_ex(hash_ctx, EVP_sha256(), NULL) <= 0 ||
        EVP_DigestUpdate(hash_ctx, text->d_buf, text->d_size) <= 0 ||
        EVP_DigestUpdate(hash_ctx, sentinel->d_buf, sentinel->d_size) <= 0) {
      fprintf(stderr, "[FATAL] SHA-256 hash computation failed.\n");
      ERR_print_errors_fp(stderr);
      EVP_MD_CTX_free(hash_ctx);
      goto cleanup;
    }
    // Include .sentinel_cfi if present (alphabetical order)
    if (sentinel_cfi && sentinel_cfi->d_buf && sentinel_cfi->d_size > 0) {
      if (EVP_DigestUpdate(hash_ctx, sentinel_cfi->d_buf,
                           sentinel_cfi->d_size) <= 0) {
        EVP_MD_CTX_free(hash_ctx);
        goto cleanup;
      }
    }
    // Include .sentinel_imports if present
    if (sentinel_imports && sentinel_imports->d_buf &&
        sentinel_imports->d_size > 0) {
      if (EVP_DigestUpdate(hash_ctx, sentinel_imports->d_buf,
                           sentinel_imports->d_size) <= 0) {
        EVP_MD_CTX_free(hash_ctx);
        goto cleanup;
      }
    }
    if (EVP_DigestFinal_ex(hash_ctx, hash, &hash_len) <= 0) {
      EVP_MD_CTX_free(hash_ctx);
      goto cleanup;
    }
    EVP_MD_CTX_free(hash_ctx);
  }

  ctx = EVP_MD_CTX_new();
  if (!ctx) {
    fprintf(stderr, "[FATAL] EVP_MD_CTX_new failed.\n");
    goto cleanup;
  }

  // Ed25519: NULL digest — algorithm has its own internal hash
  if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, priv) <= 0) {
    fprintf(stderr, "[FATAL] Ed25519 DigestSignInit failed.\n");
    ERR_print_errors_fp(stderr);
    goto cleanup;
  }

  unsigned char signature[SIG_SIZE];
  size_t siglen = SIG_SIZE;

  // Ed25519 single-shot sign: sign the SHA-256 hash
  if (EVP_DigestSign(ctx, signature, &siglen, hash, sizeof(hash)) <= 0) {
    fprintf(stderr, "[FATAL] Ed25519 DigestSign failed.\n");
    ERR_print_errors_fp(stderr);
    goto cleanup;
  }

  // 5. Write Signature to Binary
  if (lseek(fd, sig_offset, SEEK_SET) == (off_t)-1) {
    perror("[FATAL] lseek to .signature");
    goto cleanup;
  }
  ssize_t written = write(fd, signature, siglen);
  if (written < 0 || (size_t)written != siglen) {
    perror("[FATAL] write signature");
    goto cleanup;
  }

  printf("[Signer] Successfully signed '%s' (SigLen=%zu, "
         "Hash=SHA256(.text+.sentinel))\n",
         bin, siglen);
  ret = 0; // Success

cleanup:
  if (ctx)
    EVP_MD_CTX_free(ctx);
  if (priv)
    EVP_PKEY_free(priv);
  if (fp)
    fclose(fp);
  if (e)
    elf_end(e);
  if (fd >= 0)
    close(fd);
  return ret;
}
