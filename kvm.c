#define _GNU_SOURCE

#include <asm/bootparam.h>
#include <err.h>
#include <kvm.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>

static void print_segment(const char *name, struct kvm_segment *seg) {
  printf(" %s       %04hx      %016llx  %08x  %02hhx    %x %x   %x  %x %x %x %x\n",
		name, seg->selector, seg->base, seg->limit, seg->type, seg->present,
    seg->dpl, seg->db, seg->s, seg->l, seg->g, seg->avl);
}

void kvm_get_regs(struct kvm_cpu *cpu) {
  int ret;

  ret = ioctl(cpu->fd_vcpu, KVM_GET_REGS, &cpu->regs);
  if (ret < 0)
    err(1, "unable to get cpu regs");

  ret = ioctl(cpu->fd_vcpu, KVM_GET_SREGS, &cpu->sregs);
  if (ret < 0)
    err(1, "unable to get cpu sregs");
}

void kvm_out_code(struct kvm_cpu *cpu) {
	cs_insn *insn;
	size_t count;

  kvm_get_regs(cpu);

  void *code = (char *)cpu->region.userspace_addr + cpu->regs.rip;
  count = cs_disasm(cpu->handle, code, 0x10, cpu->regs.rip, 0, &insn);
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
					insn[j].op_str);
		}

		cs_free(insn, count);
	} else
		printf("ERROR: Failed to disassemble given code!\n");
}

void kvm_out_regs(struct kvm_cpu *cpu) {
  kvm_get_regs(cpu);

  printf("\n Registers:\n");
	printf(  " ----------\n");
	printf(" rip: %016llx   rsp: %016llx flags: %016llx\n", cpu->regs.rip, cpu->regs.rsp, cpu->regs.rflags);
	printf(" rax: %016llx   rbx: %016llx   rcx: %016llx\n", cpu->regs.rax, cpu->regs.rbx, cpu->regs.rcx);
	printf(" rdx: %016llx   rsi: %016llx   rdi: %016llx\n", cpu->regs.rdx, cpu->regs.rsi, cpu->regs.rdi);
	printf(" rbp: %016llx    r8: %016llx    r9: %016llx\n", cpu->regs.rbp, cpu->regs.r8,  cpu->regs.r9);
	printf(" r10: %016llx   r11: %016llx   r12: %016llx\n", cpu->regs.r10, cpu->regs.r11, cpu->regs.r12);
	printf(" r13: %016llx   r14: %016llx   r15: %016llx\n", cpu->regs.r13, cpu->regs.r14, cpu->regs.r15);

	printf(" cr0: %016llx   cr2: %016llx   cr3: %016llx\n", cpu->sregs.cr0, cpu->sregs.cr2, cpu->sregs.cr3);
	printf(" cr4: %016llx   cr8: %016llx\n", cpu->sregs.cr4, cpu->sregs.cr8);
	printf("\n Segment registers:\n");
	printf(  " ------------------\n");
	printf(" register  selector  base              limit     type  p dpl db s l g avl\n");
	print_segment("cs ", &cpu->sregs.cs);
	print_segment("ss ", &cpu->sregs.ss);
	print_segment("ds ", &cpu->sregs.ds);
	print_segment("es ", &cpu->sregs.es);
	print_segment("fs ", &cpu->sregs.fs);
	print_segment("gs ", &cpu->sregs.gs);
}

void kvm_exit_handle(struct kvm_cpu *cpu) {
    switch (cpu->run->exit_reason) {
      case KVM_EXIT_HLT:
        puts("KVM_EXIT_HLT\n");
        exit(0);
      case KVM_EXIT_IO:
        kvm_handle_serial(cpu);
        break;
      case KVM_EXIT_FAIL_ENTRY:
        errx(1, "KVM_EXIT_FAIL_ENTRY: hardware_entry_failure_reason = 0x%llx",
           (unsigned long long)cpu->run->fail_entry.hardware_entry_failure_reason);
      case KVM_EXIT_DEBUG:
        kvm_out_regs(cpu);
        kvm_out_code(cpu);
        break;
      case KVM_EXIT_MMIO:
        errx(1, "KVM_EXIT_MMIO");
      case KVM_EXIT_SHUTDOWN:
        errx(1, "KVM_EXIT_SHUTDOWN");
      default:
        errx(1, "exit_reason = 0x%x", cpu->run->exit_reason);
    }
}

void kvm_load_kernel(struct kvm_cpu *cpu, void *kernel, const size_t size) {
  struct setup_header shdr = cpu->bprm->hdr;

  int offset = (shdr.setup_sects + 1) * 512;
  memcpy((void *)cpu->region.userspace_addr + 0x100000, kernel + offset, size - offset);
}

void kvm_setup_bprm(struct kvm_cpu *cpu, struct setup_header *shdr, const char *cmdline) {
  if (shdr->boot_flag != 0xAA55)
    errx(1, "Invalid boot flag");
  if (shdr->header != 0x53726448)
    errx(1, "Invalid setup header");

  cpu->bprm = cpu->region.userspace_addr + 0x20000;
  memset(cpu->bprm, 0, sizeof(struct boot_params));
  memcpy(&cpu->bprm->hdr, shdr, sizeof(*shdr));


  cpu->bprm->hdr.type_of_loader = 0xFF;
  cpu->bprm->hdr.loadflags |= KEEP_SEGMENTS;
  cpu->bprm->hdr.loadflags |= LOADED_HIGH;

  cpu->bprm->hdr.cmd_line_ptr = 0x40000;
  strcpy(cpu->bprm->hdr.cmd_line_ptr + cpu->region.userspace_addr, cmdline); 

  struct boot_e820_entry *primary = &cpu->bprm->e820_table[0];
	struct boot_e820_entry *secondary = &cpu->bprm->e820_table[1];

  primary->addr = 0;
	primary->size = cpu->region.memory_size;
	primary->type = 1;

  secondary->addr = cpu->region.memory_size;
	secondary->size = cpu->region2.memory_size;
	secondary->type = 1;

  cpu->bprm->e820_entries = 2;
}

void kvm_set_cpuid(struct kvm_cpu *cpu) {
  struct kvm_cpuid2 cpuid = {
    .nent = 4
  };

  struct kvm_cpuid_entry2 cpuid_entries[] = {
    {
      .function = 0,
      .eax = 1,
      .ebx = 0,
      .ecx = 0,
      .edx = 0
    }, {
      .function = 1,
      .eax = 0x400,
      .ebx = 0,
      .ecx = 0,
      .edx = 0x701b179
    }, {
      .function = 0x80000000,
      .eax = 0x80000001,
      .ebx = 0,
      .ecx = 0,
      .edx = 0
    }, {
      .function = 0x80000001,
      .eax = 0,
      .ebx = 0,
      .ecx = 0,
      .edx = 0x20100800
    }
  };

  memcpy(&cpuid.entries, &cpuid_entries, sizeof(struct kvm_cpuid_entry2) * 4);
  int ret = ioctl(cpu->fd_vcpu, KVM_SET_CPUID2, &cpuid);
  if (ret < 0)
    err(1, "unable to set cpuid");
}

void kvm_set_mem_regions(struct kvm_cpu *cpu) {
  int ret;
  void *mem_addr = mmap(NULL, cpu->mem_size, PROT_READ | PROT_WRITE | PROT_EXEC,
      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if (mem_addr == MAP_FAILED)
    err(1, "mmap failed");

  void *mem_addr2 = mmap(NULL, cpu->mem_size, PROT_READ | PROT_WRITE | PROT_EXEC,
      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if (mem_addr2 == MAP_FAILED)
    err(1, "mmap failed");

  struct kvm_userspace_memory_region primary = {
    .slot = 0,
    .guest_phys_addr = 0,
    .memory_size = cpu->mem_size,
    .userspace_addr = (__u64)mem_addr,
  };

  struct kvm_userspace_memory_region secondary = {
    .slot = 1,
    .guest_phys_addr = cpu->mem_size,
    .memory_size = cpu->mem_size,
    .userspace_addr = (__u64)mem_addr2,
  };

  cpu->region = primary;
  cpu->region2 = secondary;

  ret = ioctl(cpu->fd_vm, KVM_SET_USER_MEMORY_REGION, &primary);
  if (ret < 0)
    err(1, "unable to set primary user memory region");

  ret = ioctl(cpu->fd_vm, KVM_SET_USER_MEMORY_REGION, &secondary);
  if (ret < 0)
    err(1, "unable to set secondary user memory region");
}

void kvm_init_regs(struct kvm_cpu *cpu) {
  int ret;
  kvm_get_regs(cpu);

  struct kvm_segment segment = {
    .base = 0,
    .limit = 0xFFFFFFFF,
    .selector = 0x8,
    .present = 1,
    .type = 0xA, // RX
    .dpl = 0,
    .db = 1, // 32 bit
    .s = 1, // Code/data segment
    .l = 0, // 32 bit
    .g = 1, // 4KB
  };

  cpu->sregs.cs = segment;

  segment.selector = 0x10;
  segment.type = 0x2; // RW
  cpu->sregs.ds = cpu->sregs.es = cpu->sregs.fs = cpu->sregs.gs = cpu->sregs.ss = segment;
  cpu->sregs.cr0 |= 1; // Protected mode
  cpu->sregs.cr4 &= ~(1 << 5);

  ret = ioctl(cpu->fd_vcpu, KVM_SET_SREGS, &cpu->sregs);
  if (ret < 0)
    err(1, "unable to set cpu sregs");

  memset(&cpu->regs, 0, sizeof(cpu->regs));
  cpu->regs.rflags = 2;
  cpu->regs.rip = K_BASE_ADDR;
  cpu->regs.rsi = (void *)cpu->bprm - cpu->region.userspace_addr;
  cpu->regs.rsp = 0x60000;

  ret = ioctl(cpu->fd_vcpu, KVM_SET_REGS, &cpu->regs);
  if (ret < 0)
    err(1, "unable to set cpu regs");
}

void kvm_set_debug(struct kvm_cpu *cpu) {
  struct kvm_guest_debug debug = {0};
  debug.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_SW_BP;

  int ret = ioctl(cpu->fd_vcpu, KVM_SET_GUEST_DEBUG, &debug);
  if (ret < 0)
    err(1, "unable to set debug mode");
}

void kvm_load_initrd(struct kvm_cpu *cpu, int fd_init, size_t ksize) {
  struct stat init_stat;
  int ret;

  ret = fstat(fd_init, &init_stat);
  if (ret < 0)
    err(1, "unable to stat initrd");

  void *mem_init = mmap(NULL, init_stat.st_size, PROT_READ | PROT_WRITE | PROT_EXEC,
      MAP_PRIVATE, fd_init, 0);

  if (mem_init == MAP_FAILED)
    err(1, "mmap failed");


  __u64 koffset = 0x100000 + ksize - ((cpu->bprm->hdr.setup_sects + 1) * 512);
  void *start = (void *)cpu->region.userspace_addr + koffset;
  memcpy(start, mem_init, init_stat.st_size);

  cpu->bprm->hdr.ramdisk_image = koffset;
  cpu->bprm->hdr.ramdisk_size = init_stat.st_size;
}
