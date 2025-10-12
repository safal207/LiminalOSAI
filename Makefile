CC      := gcc
CFLAGS  := -std=c11 -Wall -Wextra -pedantic -Os -Iinclude
LDFLAGS := -lm
TARGET  := build/pulse_kernel

CORE_SRCS   := core/pulse_kernel.c
MEM_SRCS    := memory/soil.c
BUS_SRCS    := bus/resonant.c
SYM_SRCS    := symbol/layer.c
REF_SRCS    := reflection/layer.c
AWARE_SRCS  := awareness/bridge.c
COUNCIL_SRCS:= council/inner.c
COH_SRCS    := coherence/field.c
DIAG_SRCS   := diagnostics/health_scan.c
SYNC_SRCS   := synchrony/weave.c
DREAM_SRCS  := dream/state.c
SRCS        := $(CORE_SRCS) $(MEM_SRCS) $(BUS_SRCS) $(SYM_SRCS) $(REF_SRCS) $(AWARE_SRCS) $(COUNCIL_SRCS) $(COH_SRCS) $(DIAG_SRCS) $(SYNC_SRCS) $(DREAM_SRCS)
OBJS        := $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean rebirth report

# --- Phoenix self-report integration ---

rebirth: $(TARGET)
	@echo "🌀 Initiating Phoenix Rebirth..."
	@$(TARGET) --limit=30 --trace --reflect --awareness --rebirth || true
	@python3 phoenix_report.py || echo "⚠️ Report skipped (no trace found)."

report:
	@python3 phoenix_report.py

