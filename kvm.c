#include <asm/bootparam.h>
#include <err.h>
#include <kvm.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

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

void kvm_handle_serial(struct kvm_cpu *cpu) {
    void *io_data = (void *)cpu->run + cpu->run->io.data_offset;
    int lsr = 0x20;
    switch (cpu->run->io.direction) {
      case KVM_EXIT_IO_OUT:
        switch (cpu->run->io.port) {
          case 0x3f8: // THR
            printf(io_data);
            break;
          default:
            printf("KVM_EXIT_IO_OUT: 0x%x\n", cpu->run->io.port);
            break;
        }
        break;
      case KVM_EXIT_IO_IN:
        switch (cpu->run->io.port) {
          case 0x3fd:
            memcpy(io_data, &lsr, sizeof(int));
            break;
          default:
            printf("KVM_EXIT_IO_IN: 0x%x\n", cpu->run->io.port);
            break;
        }
        break;
      default:
        warnx("unhandled KVM_EXIT_IO 0x%x", cpu->run->io.port);
        break;
    }
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

void kvm_setup_bprm(struct kvm_cpu *cpu, struct setup_header *shdr) {
  if (shdr->boot_flag != 0xAA55)
    errx(1, "Invalid boot flag");
  if (shdr->header != 0x53726448)
    errx(1, "Invalid setup header");

  cpu->bprm = cpu->region.userspace_addr + 0x20000;
  memset(cpu->bprm, 0, sizeof(struct boot_params));
  memcpy(&cpu->bprm->hdr, shdr, sizeof(*shdr));


  cpu->bprm->hdr.type_of_loader = 0xFF;
  cpu->bprm->hdr.loadflags |= KEEP_SEGMENTS;
//   cpu->bprm->hdr.loadflags |= LOADED_HIGH;
  const char *cmdline = "earlyprintk=serial debug ignore_loglevel memblock=debug console=ttyS0";

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
