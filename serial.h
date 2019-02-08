#ifndef _SERIAL_H
#define _SERIAL_H

#include <linux/kvm.h>
#include <kvm.h>

struct uart_regs {
  __u8  thr;      /* Transmitter Holding Buffer */
  __u8  rbr;      /* Receiver buffer */
  __u8  dll;      /* Divisor Latch Low Byte */
  __u8  ier;      /* Interrupt Enable Register */
  __u8  dlh;      /* Divisor Latch High Byte */
  __u8  iir;      /* Interrupt Identification register */
  __u8  fcr;      /* FIFO Control register */
  __u8  lcr;      /* Line Control Register */
  __u8  mcr;      /* Modem Control Register */
  __u8  lsr;      /* Line Status Register */
  __u8  msr;      /* Modem Status Register */
  __u8  sr;       /* Scratch Register */
  __u16 io_base;
};

void kvm_handle_serial(struct kvm_cpu *cpu);

#endif
