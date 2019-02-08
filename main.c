#include <asm/bootparam.h>
#include <capstone/capstone.h>
#include <err.h>
#include <fcntl.h>
#include <getopt.h>
#include <kvm.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
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

void kvm_init(struct kvm_cpu *cpu, const char *img, const char *initrd, const char *cmdline, int debug) {
  int ret, fd_bz, fd_init, vcpu_size;
  struct kvm_pit_config pit = {0};
  struct stat bz_stat;
  struct uart_regs regs = {0};

  cpu->fd_kvm = open("/dev/kvm", O_RDWR);
  if (cpu->fd_kvm < 0)
    err(1, "unable to open /dev/kvm");

  cpu->fd_vm = ioctl(cpu->fd_kvm, KVM_CREATE_VM, 0);
  if (cpu->fd_vm < 0)
    err(1, "unable to create vm");

  ret = ioctl(cpu->fd_vm, KVM_CREATE_IRQCHIP, 0);
  if (ret < 0)
    err(1, "unable to create irqchip");

  ret = ioctl(cpu->fd_vm, KVM_CREATE_PIT2, &pit);
  if (ret < 0)
    err(1, "unable to create pit");

  fd_bz = open(img, O_RDONLY);
  if (fd_bz < 0)
    err(1, "unable to open bzImage");

  ret = fstat(fd_bz, &bz_stat);
  if (ret < 0)
    err(1, "unable to stat bzImage");

  if ((__u64)bz_stat.st_size > cpu->mem_size)
    errx(1, "no space available for the image");

  // Load kernel
  void *mem_img = mmap(NULL, bz_stat.st_size, PROT_READ | PROT_WRITE | PROT_EXEC,
      MAP_PRIVATE, fd_bz, 0);

  if (mem_img == MAP_FAILED)
    err(1, "mmap failed");

  kvm_set_mem_regions(cpu);

  kvm_setup_bprm(cpu, mem_img + 0x1f1, cmdline);

  kvm_load_kernel(cpu, mem_img, bz_stat.st_size);

  if (initrd) {
    fd_init = open(initrd, O_RDONLY);
    if (fd_init < 0)
      err(1, "unable to open initrd");

    kvm_load_initrd(cpu, fd_init, bz_stat.st_size);
  }

  cpu->fd_vcpu = ioctl(cpu->fd_vm, KVM_CREATE_VCPU, 0);
  if (cpu->fd_vcpu < 0)
    err(1, "unable to create vcpu");

  kvm_set_cpuid(cpu);

  vcpu_size = ioctl(cpu->fd_kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
  if (vcpu_size < 0)
    err(1, "unable to get vcpu mmap size");

  cpu->run = mmap(NULL, vcpu_size, PROT_READ | PROT_WRITE, MAP_SHARED, cpu->fd_vcpu, 0);

  kvm_init_regs(cpu);

  if (debug)
    kvm_set_debug(cpu);

  on_exit(exit_handler, cpu);
  cpu->serial = &regs;
  while (1) {
    ret = ioctl(cpu->fd_vcpu, KVM_RUN, 0);

    if (ret < 0)
      warn("KVM_RUN");

    kvm_exit_handle(cpu);
  }
}

int main(int argc, char **argv) {
  struct kvm_cpu cpu = {0};
  char kernel[1024] = {0};
  char *initrd = NULL;
  char cmdline[1024] = {0};

  if (cs_open(CS_ARCH_X86, CS_MODE_32, &cpu.handle) != CS_ERR_OK)
    return -1;

  if (argc < 2)
    errx(1, "unable to find the image");

  static struct option long_options[] = {
    {"initrd",  required_argument, 0, 'i'},
    {"memory",  required_argument, 0, 'i'},
    {0, 0, 0, 0}
  };

  while (1) {
    int option_index = 0;

    int c = getopt_long(argc, argv, "m:i:", long_options, &option_index);

    if (c == -1)
      break;

    switch (c) {
      case 'i':
        initrd = optarg;
        break;
      case 'm':
        cpu.mem_size = atoi(optarg);
        break;
      case 'h':
      default:
usage:
        errx (1, "usage: %s bzImage [--initrd initrd] [cmd-line]", argv[0]);
    }
  }

  if (optind < argc) {
    strcpy(kernel, argv[optind++]);
    while (optind < argc) {
      strcat(cmdline, argv[optind++]);
      strcat(cmdline, " ");
    }
  }

  if (!strcmp(kernel, ""))
    goto usage;
  if (!cpu.mem_size)
    cpu.mem_size = MEM_SIZE;

  int debug = 0;
  kvm_init(&cpu, kernel, initrd, cmdline, debug);
}

