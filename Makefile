CC      := gcc
INCLUDES += -Iinclude
CFLAGS  := -std=c11 -Wall -Wextra -pedantic -Os $(INCLUDES)
LDFLAGS := -lm
TARGET  := build/pulse_kernel
SUBSTRATE_TARGET := build/liminal_core

CORE_SRCS   := core/pulse_kernel.c core/trs_filter.c core/trs_adapt.c core/erb.c core/astro_sync.c
AFFINITY_SRCS := affinity/core.c
ANTICIPATION_SRCS := anticipation/v2.c
INTROSPECT_SRCS := src/introspect.c src/harmony.c src/dream_coupler.c
TUNE_SRCS := tune/autotune.c
SUBSTRATE_SRCS := core/liminal_substrate.c core/trs_filter.c core/trs_adapt.c core/erb.c core/astro_sync.c core/dream_replay.c empathic/field.c memory/emotion_memory.c council/inner.c $(AFFINITY_SRCS) $(ANTICIPATION_SRCS)
MEM_SRCS    := memory/soil.c memory/emotion_memory.c
BUS_SRCS    := bus/resonant.c
SYM_SRCS    := symbol/layer.c
REF_SRCS    := reflection/layer.c
AWARE_SRCS  := awareness/bridge.c
COUNCIL_SRCS:= council/inner.c
COH_SRCS    := coherence/field.c
COLLECTIVE_SRCS := collective/graph.c collective/memory.c
DIAG_SRCS   := diagnostics/health_scan.c
SYNC_SRCS   := synchrony/weave.c
DREAM_SRCS  := dream/state.c dream/balancer.c
METAB_SRCS  := metabolic/flow.c
SYMBIOTIC_SRCS := symbiosis/bridge.c
EMPATHIC_SRCS := empathic/field.c
MIRROR_SRCS := mirror/sympathetic.c
SUBSTRATE_SRCS += $(MIRROR_SRCS) $(COLLECTIVE_SRCS) $(INTROSPECT_SRCS) $(TUNE_SRCS)
SRCS        := $(CORE_SRCS) $(AFFINITY_SRCS) $(ANTICIPATION_SRCS) $(INTROSPECT_SRCS) $(TUNE_SRCS) $(MEM_SRCS) $(BUS_SRCS) $(SYM_SRCS) $(REF_SRCS) $(AWARE_SRCS) $(COUNCIL_SRCS) $(COH_SRCS) $(COLLECTIVE_SRCS) $(DIAG_SRCS) $(SYNC_SRCS) $(DREAM_SRCS) $(METAB_SRCS) $(SYMBIOTIC_SRCS) $(EMPATHIC_SRCS) $(MIRROR_SRCS)
OBJS        := $(SRCS:.c=.o)
SUBSTRATE_OBJS := $(SUBSTRATE_SRCS:.c=.o)
ALL_OBJS    := $(OBJS) $(SUBSTRATE_OBJS)

LONG_TRACE_DIR := diagnostics/traces
LONG_TRACE_LOG := $(LONG_TRACE_DIR)/liminal_core_long_run.log
LONG_TRACE_SUMMARY := $(LONG_TRACE_DIR)/liminal_core_long_run.txt
LONG_TRACE_JSON := $(LONG_TRACE_DIR)/liminal_core_long_run.json

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

.PHONY: all clean rebirth report report-metabolic long-run-diagnostics

# --- Phoenix self-report integration ---

rebirth: $(TARGET)
	@echo "🌀 Initiating Phoenix Rebirth..."
	@$(TARGET) --limit=30 --trace --reflect --awareness --rebirth || true
	@python3 phoenix_report.py || echo "⚠️ Report skipped (no trace found)."

report:
	@python3 phoenix_report.py

report-metabolic:
	@python3 metabolic_report.py || echo "⚠️ Report skipped (no trace found)."

long-run-diagnostics: $(SUBSTRATE_TARGET)
	@mkdir -p $(LONG_TRACE_DIR)
	@echo "🧪 Running liminal_core long-run diagnostic (60 cycles)..."
	@bash -o pipefail -c '$(SUBSTRATE_TARGET) --substrate --limit=60 --trace --symbols --reflect --awareness --anticipation --dreamsync --sync 2>&1 | tee $(LONG_TRACE_LOG)'
	@python3 diagnostics/liminal_trace_report.py --input $(LONG_TRACE_LOG) --output $(LONG_TRACE_SUMMARY) --json $(LONG_TRACE_JSON)
	@echo "📄 Saved summary → $(LONG_TRACE_SUMMARY)"

