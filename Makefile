CC?=gcc
CFLAGS=-Wall -Wextra -std=c99 -pedantic
SRC=main.c
OBJ=$(SRC:.c=.o)
EXEC=my-kvm

all: $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(EXEC)

run:
	./my-kvm

.PHONY:run
