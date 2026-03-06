// sentinel_dump.c — Sentinel-CC Policy Inspector
// Reads and pretty-prints all .sentinel* sections from an ELF binary.
//
// Usage: sentinel-dump [--json] <binary>

#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define VERSION "4.1.0"

// Must match compiler pass output layout
struct policy_entry {
  uint64_t site_addr;
  uint64_t func_addr;
  int64_t  syscall_nr;
};

// Must match compiler pass output layout
struct cfi_entry {
  uint64_t site_addr;
  uint64_t func_addr;
};

// Well-known syscall names for x86-64
static const char *syscall_name(int nr) {
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
  case 311: return "process_vm_writev";
  case 317: return "seccomp";
  case 319: return "memfd_create";
  default:  return NULL;
  }
}

static int json_mode = 0;

static void dump_sentinel(Elf_Data *data, uint64_t text_vaddr) {
  if (!data || !data->d_buf || data->d_size == 0) {
    printf("  (empty)\n");
    return;
  }

  size_t count = data->d_size / sizeof(struct policy_entry);
  struct policy_entry *entries = (struct policy_entry *)data->d_buf;

  if (json_mode) {
    printf("  \"sentinel\": [\n");
    for (size_t i = 0; i < count; i++) {
      int64_t nr_raw = entries[i].syscall_nr;
      int nr = (nr_raw > 0) ? (int)(nr_raw - 1) : -1;
      const char *name = (nr >= 0) ? syscall_name(nr) : NULL;

      printf("    {\"site\":\"0x%lx\",\"func\":\"0x%lx\",\"offset\":\"0x%lx\"",
             (unsigned long)entries[i].site_addr,
             (unsigned long)entries[i].func_addr,
             (unsigned long)(entries[i].site_addr - text_vaddr));
      if (nr >= 0) {
        printf(",\"syscall_nr\":%d", nr);
        if (name)
          printf(",\"syscall_name\":\"%s\"", name);
      } else {
        printf(",\"syscall_nr\":\"any\"");
      }
      printf("}%s\n", (i + 1 < count) ? "," : "");
    }
    printf("  ]");
    return;
  }

  printf("  %-6s %-18s %-18s %-10s %s\n",
         "Index", "Site Address", "Function", "Offset", "Syscall");
  printf("  %-6s %-18s %-18s %-10s %s\n",
         "-----", "------------------", "------------------",
         "----------", "-------");

  for (size_t i = 0; i < count; i++) {
    int64_t nr_raw = entries[i].syscall_nr;
    int nr = (nr_raw > 0) ? (int)(nr_raw - 1) : -1;
    const char *name = (nr >= 0) ? syscall_name(nr) : NULL;
    uint64_t offset = entries[i].site_addr - text_vaddr;

    printf("  [%3zu]  0x%016lx 0x%016lx 0x%08lx",
           i, (unsigned long)entries[i].site_addr,
           (unsigned long)entries[i].func_addr,
           (unsigned long)offset);

    if (nr >= 0) {
      if (name)
        printf(" %s (%d)\n", name, nr);
      else
        printf(" NR=%d\n", nr);
    } else {
      printf(" (any)\n");
    }
  }
  printf("  Total: %zu syscall site(s)\n", count);
}

static void dump_cfi(Elf_Data *data, uint64_t text_vaddr) {
  if (!data || !data->d_buf || data->d_size == 0) {
    printf("  (empty)\n");
    return;
  }

  size_t count = data->d_size / sizeof(struct cfi_entry);
  struct cfi_entry *entries = (struct cfi_entry *)data->d_buf;

  if (json_mode) {
    printf("  \"sentinel_cfi\": [\n");
    for (size_t i = 0; i < count; i++) {
      printf("    {\"site\":\"0x%lx\",\"func\":\"0x%lx\","
             "\"site_offset\":\"0x%lx\",\"func_offset\":\"0x%lx\"}%s\n",
             (unsigned long)entries[i].site_addr,
             (unsigned long)entries[i].func_addr,
             (unsigned long)(entries[i].site_addr - text_vaddr),
             (unsigned long)(entries[i].func_addr - text_vaddr),
             (i + 1 < count) ? "," : "");
    }
    printf("  ]");
    return;
  }

  printf("  %-6s %-18s %-18s %-12s %-12s\n",
         "Index", "Syscall Site", "Caller Func", "Site Off", "Func Off");
  printf("  %-6s %-18s %-18s %-12s %-12s\n",
         "-----", "------------------", "------------------",
         "------------", "------------");

  for (size_t i = 0; i < count; i++) {
    printf("  [%3zu]  0x%016lx 0x%016lx 0x%08lx   0x%08lx\n",
           i, (unsigned long)entries[i].site_addr,
           (unsigned long)entries[i].func_addr,
           (unsigned long)(entries[i].site_addr - text_vaddr),
           (unsigned long)(entries[i].func_addr - text_vaddr));
  }
  printf("  Total: %zu CFI rule(s)\n", count);
}

static void dump_imports(Elf_Data *data) {
  if (!data || !data->d_buf || data->d_size == 0) {
    printf("  (empty)\n");
    return;
  }

  const char *blob = (const char *)data->d_buf;
  size_t len = data->d_size;
  size_t count = 0;

  if (json_mode) {
    printf("  \"sentinel_imports\": [");
    size_t pos = 0;
    int first = 1;
    while (pos < len) {
      const char *name = blob + pos;
      size_t slen = strnlen(name, len - pos);
      if (slen > 0) {
        printf("%s\"%s\"", first ? "" : ",", name);
        first = 0;
        count++;
      }
      pos += slen + 1;
    }
    printf("]");
    return;
  }

  printf("  ");
  size_t pos = 0;
  while (pos < len) {
    const char *name = blob + pos;
    size_t slen = strnlen(name, len - pos);
    if (slen > 0) {
      if (count > 0 && count % 6 == 0)
        printf("\n  ");
      printf("%-20s", name);
      count++;
    }
    pos += slen + 1;
  }
  printf("\n  Total: %zu import(s) (%zu bytes)\n", count, len);
}

static void dump_signature(Elf_Data *data) {
  if (!data || !data->d_buf || data->d_size == 0) {
    printf("  (empty)\n");
    return;
  }

  const unsigned char *sig = (const unsigned char *)data->d_buf;
  size_t len = data->d_size;

  // Check if all zeros (unsigned)
  int is_zero = 1;
  for (size_t i = 0; i < len; i++) {
    if (sig[i] != 0) { is_zero = 0; break; }
  }

  if (json_mode) {
    printf("  \"signature\": {\"size\":%zu,\"signed\":%s,\"hex\":\"",
           len, is_zero ? "false" : "true");
    for (size_t i = 0; i < len && i < 32; i++)
      printf("%02x", sig[i]);
    if (len > 32)
      printf("...");
    printf("\"}");
    return;
  }

  printf("  Size: %zu bytes (%s)\n", len,
         len == 64 ? "Ed25519" : len == 256 ? "RSA-2048 (legacy)" : "unknown");
  printf("  Status: %s\n", is_zero ? "UNSIGNED (all zeros)" : "SIGNED");
  printf("  Hex: ");
  for (size_t i = 0; i < len && i < 32; i++)
    printf("%02x", sig[i]);
  if (len > 32)
    printf("...");
  printf("\n");
}

int main(int argc, char **argv) {
  int arg_start = 1;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      printf("Sentinel-CC Policy Inspector v%s\n\n", VERSION);
      printf("Usage: %s [--json] <binary>\n\n", argv[0]);
      printf("Reads and displays all Sentinel sections from an ELF binary:\n");
      printf("  .sentinel          Syscall policy (site whitelist)\n");
      printf("  .sentinel_cfi      CFI caller-range metadata\n");
      printf("  .sentinel_imports  External function import list\n");
      printf("  .signature         Ed25519 signature\n");
      return 0;
    }
    if (strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-v") == 0) {
      printf("Sentinel-CC Policy Inspector v%s\n", VERSION);
      return 0;
    }
    if (strcmp(argv[i], "--json") == 0) {
      json_mode = 1;
      arg_start = i + 1;
      continue;
    }
    arg_start = i;
    break;
  }

  if (arg_start >= argc) {
    fprintf(stderr, "Usage: %s [--json] <binary>\n", argv[0]);
    return 1;
  }

  const char *path = argv[arg_start];

  if (elf_version(EV_CURRENT) == EV_NONE) {
    fprintf(stderr, "ELF init failed: %s\n", elf_errmsg(-1));
    return 1;
  }

  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    perror(path);
    return 1;
  }

  Elf *e = elf_begin(fd, ELF_C_READ, NULL);
  if (!e) {
    fprintf(stderr, "elf_begin: %s\n", elf_errmsg(-1));
    close(fd);
    return 1;
  }

  size_t shstrndx;
  if (elf_getshdrstrndx(e, &shstrndx) != 0) {
    fprintf(stderr, "Cannot read section string table.\n");
    elf_end(e);
    close(fd);
    return 1;
  }

  // Find .text vaddr for offset computation
  uint64_t text_vaddr = 0;
  Elf_Data *sec_sentinel = NULL, *sec_cfi = NULL;
  Elf_Data *sec_imports = NULL, *sec_signature = NULL;
  int found = 0;

  Elf_Scn *scn = NULL;
  while ((scn = elf_nextscn(e, scn)) != NULL) {
    GElf_Shdr shdr;
    gelf_getshdr(scn, &shdr);
    const char *name = elf_strptr(e, shstrndx, shdr.sh_name);
    if (!name) continue;

    if (strcmp(name, ".text") == 0) {
      text_vaddr = shdr.sh_addr;
    } else if (strcmp(name, ".sentinel") == 0) {
      sec_sentinel = elf_getdata(scn, NULL);
      found |= 1;
    } else if (strcmp(name, ".sentinel_cfi") == 0) {
      sec_cfi = elf_getdata(scn, NULL);
      found |= 2;
    } else if (strcmp(name, ".sentinel_imports") == 0) {
      sec_imports = elf_getdata(scn, NULL);
      found |= 4;
    } else if (strcmp(name, ".signature") == 0) {
      sec_signature = elf_getdata(scn, NULL);
      found |= 8;
    }
  }

  if (found == 0) {
    fprintf(stderr, "No Sentinel sections found in '%s'.\n"
                    "Was it compiled with -fpass-plugin=SentinelPass.so?\n",
            path);
    elf_end(e);
    close(fd);
    return 1;
  }

  if (json_mode) {
    printf("{\n  \"binary\": \"%s\",\n  \"text_vaddr\": \"0x%lx\",\n",
           path, (unsigned long)text_vaddr);
    int need_comma = 0;
    if (found & 1) {
      if (need_comma) printf(",\n");
      dump_sentinel(sec_sentinel, text_vaddr);
      need_comma = 1;
    }
    if (found & 2) {
      if (need_comma) printf(",\n");
      dump_cfi(sec_cfi, text_vaddr);
      need_comma = 1;
    }
    if (found & 4) {
      if (need_comma) printf(",\n");
      dump_imports(sec_imports);
      need_comma = 1;
    }
    if (found & 8) {
      if (need_comma) printf(",\n");
      dump_signature(sec_signature);
      need_comma = 1;
    }
    printf("\n}\n");
  } else {
    printf("Sentinel-CC Policy Inspector v%s\n", VERSION);
    printf("Binary: %s\n", path);
    printf(".text vaddr: 0x%lx\n\n", (unsigned long)text_vaddr);

    if (found & 1) {
      printf("── .sentinel (Syscall Policy) ─────────────────────────────────\n");
      dump_sentinel(sec_sentinel, text_vaddr);
      printf("\n");
    }
    if (found & 2) {
      printf("── .sentinel_cfi (CFI Caller Ranges) ──────────────────────────\n");
      dump_cfi(sec_cfi, text_vaddr);
      printf("\n");
    }
    if (found & 4) {
      printf("── .sentinel_imports (External Functions) ─────────────────────\n");
      dump_imports(sec_imports);
      printf("\n");
    }
    if (found & 8) {
      printf("── .signature ──────────────────────────────────────────────────\n");
      dump_signature(sec_signature);
      printf("\n");
    }

    // Summary line
    printf("Sections present: .sentinel%s%s%s\n",
           (found & 2) ? " .sentinel_cfi" : "",
           (found & 4) ? " .sentinel_imports" : "",
           (found & 8) ? " .signature" : "");
  }

  elf_end(e);
  close(fd);
  return 0;
}
