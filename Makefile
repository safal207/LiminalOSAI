CC      := gcc
CFLAGS  := -std=c11 -Wall -Wextra -pedantic -Os -Iinclude
LDFLAGS := -lm
TARGET  := build/pulse_kernel
SUBSTRATE_TARGET := build/liminal_core

CORE_SRCS   := core/pulse_kernel.c
SUBSTRATE_SRCS := core/liminal_substrate.c empathic/field.c memory/emotion_memory.c council/inner.c
MEM_SRCS    := memory/soil.c memory/emotion_memory.c
BUS_SRCS    := bus/resonant.c
SYM_SRCS    := symbol/layer.c
REF_SRCS    := reflection/layer.c
AWARE_SRCS  := awareness/bridge.c
COUNCIL_SRCS:= council/inner.c
COH_SRCS    := coherence/field.c
DIAG_SRCS   := diagnostics/health_scan.c
SYNC_SRCS   := synchrony/weave.c
DREAM_SRCS  := dream/state.c
METAB_SRCS  := metabolic/flow.c
SYMBIOTIC_SRCS := symbiosis/bridge.c
EMPATHIC_SRCS := empathic/field.c
SRCS        := $(CORE_SRCS) $(MEM_SRCS) $(BUS_SRCS) $(SYM_SRCS) $(REF_SRCS) $(AWARE_SRCS) $(COUNCIL_SRCS) $(COH_SRCS) $(DIAG_SRCS) $(SYNC_SRCS) $(DREAM_SRCS) $(METAB_SRCS) $(SYMBIOTIC_SRCS) $(EMPATHIC_SRCS)
OBJS        := $(SRCS:.c=.o)
SUBSTRATE_OBJS := $(SUBSTRATE_SRCS:.c=.o)
ALL_OBJS    := $(OBJS) $(SUBSTRATE_OBJS)

all: $(TARGET) $(SUBSTRATE_TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)

$(SUBSTRATE_TARGET): $(SUBSTRATE_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(SUBSTRATE_OBJS) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(ALL_OBJS) $(TARGET) $(SUBSTRATE_TARGET)

.PHONY: all clean rebirth report report-metabolic

# --- Phoenix self-report integration ---

rebirth: $(TARGET)
	@echo "🌀 Initiating Phoenix Rebirth..."
	@$(TARGET) --limit=30 --trace --reflect --awareness --rebirth || true
	@python3 phoenix_report.py || echo "⚠️ Report skipped (no trace found)."

report:
	@python3 phoenix_report.py

report-metabolic:
	@python3 metabolic_report.py || echo "⚠️ Report skipped (no trace found)."

