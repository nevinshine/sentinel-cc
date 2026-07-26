// sentinel_dump.c — Sentinel-CC Policy Inspector
// Reads and pretty-prints .llvm.syscall.bounds from an ELF binary.
//
// Usage: sentinel-dump <binary>

#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define VERSION "4.2.0-research"

#pragma pack(push, 1)
struct sentinel_header {
  char magic[4];
  uint8_t version;
  uint32_t count;
};
#pragma pack(pop)

// Must match compiler pass output layout
struct policy_entry {
  uint64_t site_addr;
  uint64_t func_addr;
  int64_t  syscall_nr;
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
  if (!data || !data->d_buf || data->d_size < sizeof(struct sentinel_header)) {
    printf("  (empty or missing header)\n");
    return;
  }

  size_t offset = 0;
  size_t global_index = 0;
  int first_header = 1;

  if (!json_mode) {
    printf("  %-6s %-18s %-18s %-10s %s\n",
           "Index", "Site Address", "Function", "Offset", "Syscall");
    printf("  %-6s %-18s %-18s %-10s %s\n",
           "-----", "------------------", "------------------",
           "----------", "-------");
  } else {
    printf("  \"llvm_syscall_bounds\": [\n");
  }

  while (offset + sizeof(struct sentinel_header) <= data->d_size) {
    struct sentinel_header *hdr = (struct sentinel_header *)((char *)data->d_buf + offset);
    if (strncmp(hdr->magic, "\x7FSEN", 4) != 0) {
      if (!json_mode) printf("  [ERROR] Invalid magic bytes at offset %zu.\n", offset);
      break;
    }
    
    size_t expected_size = sizeof(struct sentinel_header) + hdr->count * sizeof(struct policy_entry);
    if (offset + expected_size > data->d_size) {
      if (!json_mode) printf("  [ERROR] Section too small for declared count at offset %zu.\n", offset);
      break;
    }

    struct policy_entry *entries = (struct policy_entry *)((char *)data->d_buf + offset + sizeof(struct sentinel_header));

    for (size_t i = 0; i < hdr->count; i++) {
      int64_t nr_raw = entries[i].syscall_nr;
      int nr = (nr_raw > 0) ? (int)(nr_raw - 1) : -1;
      const char *name = (nr >= 0) ? syscall_name(nr) : NULL;
      uint64_t site_offset = entries[i].site_addr - text_vaddr;

      if (json_mode) {
        printf("    {\"site\":\"0x%lx\",\"func\":\"0x%lx\",\"offset\":\"0x%lx\"",
               (unsigned long)entries[i].site_addr,
               (unsigned long)entries[i].func_addr,
               (unsigned long)site_offset);
        if (nr >= 0) {
          printf(",\"syscall_nr\":%d", nr);
          if (name)
            printf(",\"syscall_name\":\"%s\"", name);
        } else {
          printf(",\"syscall_nr\":\"any\"");
        }
        printf("}%s\n", (offset + expected_size >= data->d_size && i + 1 == hdr->count) ? "" : ",");
      } else {
        printf("  [%3zu]  0x%016lx 0x%016lx 0x%08lx",
               global_index, (unsigned long)entries[i].site_addr,
               (unsigned long)entries[i].func_addr,
               (unsigned long)site_offset);

        if (nr >= 0) {
          if (name)
            printf(" %s (%d)\n", name, nr);
          else
            printf(" NR=%d\n", nr);
        } else {
          printf(" (any)\n");
        }
      }
      global_index++;
    }
    offset += expected_size;
  }

  if (json_mode) {
    printf("  ]");
  } else {
    printf("  Total: %zu syscall site(s) across all translation units\n", global_index);
  }
}

int main(int argc, char **argv) {
  int arg_start = 1;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      printf("Sentinel-CC Policy Inspector v%s\n\n", VERSION);
      printf("Usage: %s [--json] <binary>\n\n", argv[0]);
      printf("Reads and displays the .llvm.syscall.bounds section from an ELF binary.\n");
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

  uint64_t text_vaddr = 0;
  Elf_Data *sec_sentinel = NULL;
  int found = 0;

  Elf_Scn *scn = NULL;
  while ((scn = elf_nextscn(e, scn)) != NULL) {
    GElf_Shdr shdr;
    gelf_getshdr(scn, &shdr);
    const char *name = elf_strptr(e, shstrndx, shdr.sh_name);
    if (!name) continue;

    if (strcmp(name, ".text") == 0) {
      text_vaddr = shdr.sh_addr;
    } else if (strcmp(name, ".llvm.syscall.bounds") == 0) {
      sec_sentinel = elf_getdata(scn, NULL);
      found |= 1;
    }
  }

  if (found == 0) {
    fprintf(stderr, "No .llvm.syscall.bounds section found in '%s'.\n"
                    "Was it compiled with -fpass-plugin=SentinelPass.so?\n",
            path);
    elf_end(e);
    close(fd);
    return 1;
  }

  if (json_mode) {
    printf("{\n  \"binary\": \"%s\",\n  \"text_vaddr\": \"0x%lx\",\n",
           path, (unsigned long)text_vaddr);
    if (found & 1) {
      dump_sentinel(sec_sentinel, text_vaddr);
    }
    printf("\n}\n");
  } else {
    printf("Sentinel-CC Policy Inspector v%s\n", VERSION);
    printf("Binary: %s\n", path);
    printf(".text vaddr: 0x%lx\n\n", (unsigned long)text_vaddr);

    if (found & 1) {
      printf("── .llvm.syscall.bounds (Syscall Policy) ───────────────────────\n");
      dump_sentinel(sec_sentinel, text_vaddr);
      printf("\n");
    }

    printf("Sections present: .llvm.syscall.bounds\n");
  }

  elf_end(e);
  close(fd);
  return 0;
}
