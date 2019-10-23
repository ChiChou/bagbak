#define MH_MAGIC_64 0xfeedfacf
#define LC_ENCRYPTION_INFO 0x21
#define LC_ENCRYPTION_INFO_64 0x2C
#define NULL 0

typedef unsigned int uint32_t;
typedef int integer_t;

typedef long long __int64_t;
typedef __int64_t __darwin_off_t;
typedef __darwin_off_t off_t;

typedef integer_t cpu_type_t;
typedef integer_t cpu_subtype_t;

struct mach_header {
  uint32_t magic;
  cpu_type_t cputype;
  cpu_subtype_t cpusubtype;
  uint32_t filetype;
  uint32_t ncmds;
  uint32_t sizeofcmds;
  uint32_t flags;
};

struct mach_header_64 {
  uint32_t magic;
  cpu_type_t cputype;
  cpu_subtype_t cpusubtype;
  uint32_t filetype;
  uint32_t ncmds;
  uint32_t sizeofcmds;
  uint32_t flags;
  uint32_t reserved;
};

struct load_command {
  uint32_t cmd;
  uint32_t cmdsize;
};

struct encryption_info_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t cryptoff;
  uint32_t cryptsize;
  uint32_t cryptid;
};

struct encryption_info_command_64 {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t cryptoff;
  uint32_t cryptsize;
  uint32_t cryptid;
  uint32_t pad;
};

struct result {
  void *ptr;
  uint32_t offset;
  uint32_t size;

  uint32_t offset_id;
  uint32_t size_id;
};

struct result find_encryption_info(struct mach_header *mh) {
  struct load_command *lc;
  struct encryption_info_command *eic;
  int i = 0;
  struct result ret = { 0 };

  if (mh->magic == MH_MAGIC_64) {
    lc = (struct load_command *)((unsigned char *)mh + sizeof(struct mach_header_64));
  } else {
    lc = (struct load_command *)((unsigned char *)mh + sizeof(struct mach_header));
  }

  for (i = 0; i < mh->ncmds; i++) {
    if (lc->cmd == LC_ENCRYPTION_INFO || lc->cmd == LC_ENCRYPTION_INFO_64) {
      eic = (struct encryption_info_command *)lc;
      if (!eic->cryptid) break;

      ret.ptr = eic;
      ret.offset = eic->cryptoff;
      ret.size = eic->cryptsize;
      ret.offset_id = (uint32_t)((void *)&eic->cryptid - (void *)mh);
      ret.size_id = sizeof(eic->cryptid);
      return ret;
    }

    lc = (struct load_command *)((unsigned char *)lc + lc->cmdsize);
  }

  return ret;
}