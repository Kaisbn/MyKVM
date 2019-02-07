#include <err.h>
#include <kvm.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
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

  void *code = (char *)cpu->region.userspace_addr + cpu->regs.rip - K_BASE_ADDR;
  count = cs_disasm(cpu->handle, code, 0x10, K_BASE_ADDR, 0, &insn);
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
// 	print_dtable("gdt", &sregs.gdt);
// 	print_dtable("idt", &sregs.idt);
}

void kvm_exit_handle(struct kvm_cpu *cpu) {
    switch (cpu->run->exit_reason) {
      case KVM_EXIT_HLT:
        puts("KVM_EXIT_HLT\n");
        exit(0);
      case KVM_EXIT_IO:
        if (cpu->run->io.direction == KVM_EXIT_IO_OUT &&
            cpu->run->io.size == 1 &&
            cpu->run->io.port == 0x3f8 &&
            cpu->run->io.count == 1)
          putchar(*(((char *)cpu->run) + cpu->run->io.data_offset));
        else
          errx(1, "unhandled KVM_EXIT_IO");
        break;
      case KVM_EXIT_FAIL_ENTRY:
        errx(1, "KVM_EXIT_FAIL_ENTRY: hardware_entry_failure_reason = 0x%llx",
            (unsigned long long)cpu->run->fail_entry.hardware_entry_failure_reason);
      case KVM_EXIT_INTERNAL_ERROR:
        errx(1, "KVM_EXIT_INTERNAL_ERROR: suberror = 0x%x", cpu->run->internal.suberror);
      case KVM_EXIT_DEBUG:
        kvm_out_regs(cpu);
        kvm_out_code(cpu);
        break;
      default:
        errx(1, "exit_reason = 0x%x", cpu->run->exit_reason);
    }
}
