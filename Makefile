CC      := gcc
CFLAGS  := -std=c11 -Wall -Wextra -pedantic -Os
LDFLAGS :=
TARGET  := build/liminal_pulse

CORE_SRCS   := core/pulse_kernel.c
MEM_SRCS    := memory/soil.c
SRCS        := $(CORE_SRCS) $(MEM_SRCS)
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
