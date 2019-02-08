#include <serial.h>
#include <stdio.h>
#include <string.h>

#define DLAB(lcr) (lcr >> 7)

void kvm_handle_serial(struct kvm_cpu *cpu) {
    void *io_data = (void *)cpu->run + cpu->run->io.data_offset;
    cpu->serial->lsr = 0x20;
    switch (cpu->run->io.direction) {
      case KVM_EXIT_IO_OUT:
        switch (cpu->run->io.port) {
          case 0x3f8:
            printf(io_data);
            break;
          case 0x3f9:
            memcpy(&cpu->serial->ier, io_data, sizeof(__u8));
            break;
          default:
            break;
        }
        break;
      case KVM_EXIT_IO_IN:
        switch (cpu->run->io.port) {
          case 0x3f9:
            memcpy(io_data, &cpu->serial->ier, sizeof(__u8));
            break;
          case 0x3fd:
            memcpy(io_data, &cpu->serial->lsr, sizeof(int));
            break;
          default:
            break;
        }
        break;
      default:
        break;
    }
}

