CC      := gcc
CFLAGS  := -std=c11 -Wall -Wextra -pedantic -Os -Iinclude
LDFLAGS :=
TARGET  := build/pulse_kernel

CORE_SRCS   := core/pulse_kernel.c
MEM_SRCS    := memory/soil.c
BUS_SRCS    := bus/resonant.c
SRCS        := $(CORE_SRCS) $(MEM_SRCS) $(BUS_SRCS)
OBJS        := $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
