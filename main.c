#define _GNU_SOURCE

#include <asm/bootparam.h>
#include <err.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define MEM_SIZE (1 << 30)

int main(int argc, char **argv) {
  int ret, fd_kvm, fd_vm, fd_bz, fd_vcpu, vcpu_size;
  struct kvm_cpuid2 cpuid;
  struct kvm_sregs sregs;
  struct kvm_regs regs;
  struct stat bz_stat;

  if (argc < 2)
    errx(1, "unable to find the image");

  fd_kvm = open("/dev/kvm", O_RDWR);
  if (fd_kvm < 0)
    err(1, "unable to open /dev/kvm");

  fd_vm = ioctl(fd_kvm, KVM_CREATE_VM, 0);
  if (fd_vm < 0)
    err(1, "unable to create vm");

  fd_bz = open(argv[1], O_RDONLY);
  if (fd_bz < 0)
    err(1, "unable to open bzImage");

  ret = fstat(fd_bz, &bz_stat);
  if (ret < 0)
    err(1, "unable to stat bzImage");

  void *mem_img = mmap(NULL, bz_stat.st_size, PROT_READ | PROT_WRITE,
      MAP_PRIVATE, fd_bz, 0);

  struct setup_header *shdr = mem_img + 0x1f1;

  struct boot_params bprm = {0};
  memcpy(&bprm.hdr, shdr, sizeof(*shdr));

  void *mem_addr = mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE,
      MAP_PRIVATE, -1, 0);

  struct kvm_userspace_memory_region region = {
    .slot = 0,
    .flags = 0,
    .guest_phys_addr = 0x100000,
    .memory_size = MEM_SIZE,
    .userspace_addr = (__u64)mem_addr,
  };

  ret = ioctl(fd_vm, KVM_SET_USER_MEMORY_REGION, &region);
  if (ret < 0)
    err(1, "unable to set user memory region");

  fd_vcpu = ioctl(fd_vm, KVM_CREATE_VCPU, 0);
  if (fd_vcpu < 0)
    err(1, "unable to create vcpu");

//   ret = ioctl(fd_vcpu, KVM_GET_SUPPORTED_CPUID, &cpuid);
//   if (ret < 0)
//     err(1, "unable to get supported cpuid");
//
//   ret = ioctl(fd_vcpu, KVM_SET_CPUID2, &cpuid);
//   if (ret < 0)
//     err(1, "unable to set cpuid");

  vcpu_size = ioctl(fd_kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
  if (vcpu_size < 0)
      err(1, "KVM_GET_VCPU_MMAP_SIZE");

  struct kvm_run *run = mmap(NULL, vcpu_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd_vcpu, 0);

  ioctl(fd_vcpu, KVM_GET_SREGS, &sregs);

  struct kvm_segment segment = {
    .base = 0,
    .limit = 0xFFFFFFFF,
    .selector = 0x10,
    .present = 1,
    .type = 0xA, // RX
    .dpl = 0,
    .db = 1, // 32 bit
    .s = 1, // Code/data segment
    .l = 0, // 32 bit
    .g = 1, // 4KB
  };

  sregs.cs = segment;

  segment.selector = 0x18;
  segment.type = 0x2; // RW
  sregs.ds = sregs.es = sregs.fs = sregs.gs = sregs.ss = segment;
  sregs.cr0 |= 1; // Protected mode

  ioctl(fd_vcpu, KVM_SET_SREGS, &sregs);

  ioctl(fd_vcpu, KVM_GET_REGS, &regs);

  regs.rflags = 2;

  regs.rip = 0x100000;
  regs.rsp = &bprm;

  ioctl(fd_vcpu, KVM_SET_REGS, &regs);

  while (1) {
    ret = ioctl(fd_vcpu, KVM_RUN, 0);

    if (ret < 0)
      warn("KVM_RUN");

    switch (run->exit_reason) {
      case KVM_EXIT_HLT:
        puts("KVM_EXIT_HLT\n");
        return 0;
      case KVM_EXIT_IO:
        if (run->io.direction == KVM_EXIT_IO_OUT && run->io.size == 1 && run->io.port == 0x3f8 && run->io.count == 1)
          putchar(*(((char *)run) + run->io.data_offset));
        else
          warnx("unhandled KVM_EXIT_IO");
        break;
      case KVM_EXIT_FAIL_ENTRY:
        warnx("KVM_EXIT_FAIL_ENTRY: hardware_entry_failure_reason = 0x%llx",
            (unsigned long long)run->fail_entry.hardware_entry_failure_reason);
        break;
      case KVM_EXIT_INTERNAL_ERROR:
        warnx("KVM_EXIT_INTERNAL_ERROR: suberror = 0x%x", run->internal.suberror);
        break;
      default:
        warnx("exit_reason = 0x%x", run->exit_reason);
        break;
    }

    printf("vm exit, sleeping 1s\n");
    sleep(1);
  }
}
