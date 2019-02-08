#ifndef _KVM_H
#define _KVM_H

#include <capstone/capstone.h>
#include <linux/kvm.h>

#define MEM_SIZE (1 << 30)
#define K_BASE_ADDR 0x100000
#define BPRM_BASE_ADDR 0x20000

struct kvm_cpu {
  int fd_kvm, fd_vm, fd_vcpu;
  __u64 mem_size;
  struct kvm_run *run;
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  struct kvm_userspace_memory_region region;
  struct kvm_userspace_memory_region region2;
  struct boot_params *bprm;
  csh handle; // Capstone handle
};

void kvm_get_regs(struct kvm_cpu *cpu);
void kvm_out_code(struct kvm_cpu *cpu);
void kvm_out_regs(struct kvm_cpu *cpu);
void kvm_exit_handle(struct kvm_cpu *cpu);
void kvm_load_kernel(struct kvm_cpu *cpu, void *kernel, const size_t size);
void kvm_set_cpuid(struct kvm_cpu *cpu);
void kvm_setup_bprm(struct kvm_cpu *cpu, struct setup_header *shdr, const char *cmdline);
void kvm_set_mem_regions(struct kvm_cpu *cpu);
void kvm_init_regs(struct kvm_cpu *cpu);
void kvm_set_debug(struct kvm_cpu *cpu);

#endif
