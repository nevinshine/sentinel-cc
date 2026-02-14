// sign_tool.c
// Professional Signing Tool for Sentinel-CC
// Usage: ./sign_tool <binary_path> <private_key.pem>

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

#define SIG_SIZE 256 // RSA-2048

void handle_openssl_error() {
  ERR_print_errors_fp(stderr);
  exit(1);
}

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "Usage: %s <binary> <private.pem>\n", argv[0]);
    return 1;
  }

  const char *bin = argv[1];
  const char *keyfile = argv[2];

  // 1. Initialize ELF Library
  if (elf_version(EV_CURRENT) == EV_NONE) {
    fprintf(stderr, "ELF Init Failed: %s\n", elf_errmsg(-1));
    return 1;
  }

  int fd = open(bin, O_RDWR);
  if (fd < 0) {
    perror("open binary");
    return 1;
  }

  Elf *e = elf_begin(fd, ELF_C_RDWR, NULL);
  if (!e) {
    fprintf(stderr, "elf_begin Failed: %s\n", elf_errmsg(-1));
    close(fd);
    return 1;
  }

  // 2. Locate Sections
  size_t shstrndx;
  elf_getshdrstrndx(e, &shstrndx);

  Elf_Scn *scn = NULL;
  Elf_Data *text = NULL, *sentinel = NULL;
  off_t sig_offset = 0;
  int found_sections = 0;

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
    if (strcmp(name, ".signature") == 0) {
      sig_offset = shdr.sh_offset;
      found_sections |= 4;
    }
  }

  if (text)
    found_sections |= 1;
  if (sentinel)
    found_sections |= 2;

  if (found_sections != 7) {
    fprintf(stderr, "[Error] Missing sections. Code: %d (Need 7)\n",
            found_sections);
    fprintf(stderr, "Code=1 (.text), 2 (.sentinel), 4 (.signature)\n");
    elf_end(e);
    close(fd);
    return 1;
  }

  // 3. Load Private Key
  FILE *fp = fopen(keyfile, "r");
  if (!fp) {
    perror("open keyfile");
    return 1;
  }
  EVP_PKEY *priv = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  fclose(fp);
  if (!priv)
    handle_openssl_error();

  // 4. Compute & Sign Hash (Code + Policy)
  // We use EVP_DigestSign to match EVP_DigestVerify in the loader
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, priv) <= 0)
    handle_openssl_error();
  if (EVP_DigestSignUpdate(ctx, text->d_buf, text->d_size) <= 0)
    handle_openssl_error();
  if (EVP_DigestSignUpdate(ctx, sentinel->d_buf, sentinel->d_size) <= 0)
    handle_openssl_error();

  unsigned char signature[SIG_SIZE];
  size_t siglen = SIG_SIZE;

  if (EVP_DigestSignFinal(ctx, signature, &siglen) <= 0)
    handle_openssl_error();
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(priv);

  // 5. Write Signature to Binary
  if (lseek(fd, sig_offset, SEEK_SET) == (off_t)-1) {
    perror("lseek");
    return 1;
  }
  if (write(fd, signature, siglen) != siglen) {
    perror("write");
    return 1;
  }

  printf("[Signer] Successfully signed %s (SigLen: %zu)\n", bin, siglen);

  elf_end(e);
  close(fd);
  return 0;
}
