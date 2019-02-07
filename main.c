#define _GNU_SOURCE

#include <asm/bootparam.h>
#include <capstone/capstone.h>
#include <err.h>
#include <fcntl.h>
#include <kvm.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

void exit_handler(int status, void *arg) {
  (void)status;

  struct kvm_cpu *cpu = arg;
	cs_close(&cpu->handle);
}

int main(int argc, char **argv) {
  int ret, fd_bz, vcpu_size;
//   struct kvm_cpuid2 cpuid;
  struct kvm_guest_debug debug;
  struct kvm_cpu cpu;
  struct stat bz_stat;

  if (cs_open(CS_ARCH_X86, CS_MODE_32, &cpu.handle) != CS_ERR_OK)
		return -1;

  if (argc < 2)
    errx(1, "unable to find the image");

  cpu.fd_kvm = open("/dev/kvm", O_RDWR);
  if (cpu.fd_kvm < 0)
    err(1, "unable to open /dev/kvm");

  cpu.fd_vm = ioctl(cpu.fd_kvm, KVM_CREATE_VM, 0);
  if (cpu.fd_vm < 0)
    err(1, "unable to create vm");

  fd_bz = open(argv[1], O_RDONLY);
  if (fd_bz < 0)
    err(1, "unable to open bzImage");

  ret = fstat(fd_bz, &bz_stat);
  if (ret < 0)
    err(1, "unable to stat bzImage");

  if (bz_stat.st_size > MEM_SIZE)
    errx(1, "no space available for the image");

  // Load kernel
  void *mem_img = mmap(NULL, bz_stat.st_size, PROT_READ | PROT_WRITE,
      MAP_PRIVATE, fd_bz, 0);

  struct setup_header *shdr = mem_img + 0x1f1;
  memcpy(&cpu.bprm.hdr, shdr, sizeof(*shdr));

  void *mem_addr = mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  struct kvm_userspace_memory_region region = {
    .slot = 0,
    .flags = 0,
    .guest_phys_addr = K_BASE_ADDR,
    .memory_size = MEM_SIZE,
    .userspace_addr = (__u64)mem_addr,
  };

  cpu.region = region;

  kvm_load_kernel(&cpu, mem_img, bz_stat.st_size);

  ret = ioctl(cpu.fd_vm, KVM_SET_USER_MEMORY_REGION, &cpu.region);
  if (ret < 0)
    err(1, "unable to set user memory region");

  cpu.fd_vcpu = ioctl(cpu.fd_vm, KVM_CREATE_VCPU, 0);
  if (cpu.fd_vcpu < 0)
    err(1, "unable to create vcpu");

//   ret = ioctl(fd_vcpu, KVM_GET_SUPPORTED_CPUID, &cpuid);
//   if (ret < 0)
//     err(1, "unable to get supported cpuid");
//
//   ret = ioctl(fd_vcpu, KVM_SET_CPUID2, &cpuid);
//   if (ret < 0)
//     err(1, "unable to set cpuid");

  vcpu_size = ioctl(cpu.fd_kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
  if (vcpu_size < 0)
    err(1, "unable to get vcpu mmap size");

  cpu.run = mmap(NULL, vcpu_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, cpu.fd_vcpu, 0);

  kvm_get_regs(&cpu);

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

  cpu.sregs.cs = segment;

  segment.selector = 0x10;
  segment.type = 0x2; // RW
  cpu.sregs.ds = cpu.sregs.es = cpu.sregs.fs = cpu.sregs.gs = cpu.sregs.ss = segment;
  cpu.sregs.cr0 |= 1; // Protected mode

  ret = ioctl(cpu.fd_vcpu, KVM_SET_SREGS, &cpu.sregs);
  if (ret < 0)
    err(1, "unable to set cpu sregs");

  cpu.regs.rflags = 2;
  cpu.regs.rip = K_BASE_ADDR;
  cpu.regs.rsi = (__u64)&cpu.bprm;
  // TODO: find free zone for rsp
  cpu.regs.rsp = bz_stat.st_size + 0x100000;

  ret = ioctl(cpu.fd_vcpu, KVM_SET_REGS, &cpu.regs);
  if (ret < 0)
    err(1, "unable to set cpu regs");

  debug.control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP;
  debug.control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP;

  ret = ioctl(cpu.fd_vcpu, KVM_SET_GUEST_DEBUG, &debug);
  if (ret < 0)
    errx(1, "unable to set debug mode");

  on_exit(exit_handler, &cpu);
  while (1) {
    ret = ioctl(cpu.fd_vcpu, KVM_RUN, 0);

    if (ret < 0)
      warn("KVM_RUN");

    kvm_exit_handle(&cpu);
    sleep(1);
  }
}
