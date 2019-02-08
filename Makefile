CC?=gcc
CFLAGS=-Wall -Wextra -std=c99 -pedantic -g3 -O0 -I.
SRC=main.c \
		kvm.c \
		serial.c
OBJ=$(SRC:.c=.o)
EXEC=my-kvm
LDFLAGS=-lcapstone

all: $(OBJ)
	$(CC) $(LDFLAGS) $(OBJ) -o $(EXEC)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

run:
	./my-kvm $1

clean:
	$(RM) $(EXEC) $(OBJ)

.PHONY: run
