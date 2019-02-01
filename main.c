#define _GNU_SOURCE

#include <err.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define MEM_SIZE (1 << 30)

int main(int argc, char **argv)
{
  int ret, fd_kvm, fd_vm;

	fd_kvm = open("/dev/kvm", O_RDWR);
	if (fd_kvm < 0) {
		err(1, "unable to open /dev/kvm");
	}

	fd_vm = ioctl(fd_kvm, KVM_CREATE_VM, 0);
	if (fd_vm < 0) {
		err(1, "unable to create vm");
	}

  if (argc < 2) {
    err(1, "unable to find the image");
  }

	void *mem_addr = mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE,
			      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	struct kvm_userspace_memory_region region = {
		.slot = 0,
		.flags = 0,
		.guest_phys_addr = 0x100000,
		.memory_size = MEM_SIZE,
		.userspace_addr = (__u64)mem_addr,
	};

	ioctl(fd_vm, KVM_SET_USER_MEMORY_REGION, &region);

	int fd_vcpu = ioctl(fd_vm, KVM_CREATE_VCPU, 0);

  struct kvm_cpuid2 cpuid;

  ioctl(fd_vcpu, KVM_GET_SUPPORTED_CPUID, &cpuid);
  ioctl(fd_vcpu, KVM_SET_CPUID2, &cpuid);

  int vcpu_size = ioctl(fd_vm, KVM_GET_VCPU_MMAP_SIZE, 0);

  void *mem_vcpu = mmap(NULL, vcpu_size, PROT_READ | PROT_WRITE,
            MAP_PRIVATE, fd_vcpu, 0);

	struct kvm_sregs sregs;
	ioctl(fd_vcpu, KVM_GET_SREGS, &sregs);

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

  sregs.cs = segment;

  segment.selector = 0x10;
  segment.type = 0x2;
  sregs.ds = sregs.es = sregs.fs = sregs.gs = sregs.ss = segment;
}
