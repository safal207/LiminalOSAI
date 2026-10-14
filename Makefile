CC      := gcc
.DEFAULT_GOAL := all
PYTHON  ?= python3
INCLUDES += -Iinclude
CFLAGS  := -std=c11 -Wall -Wextra -pedantic -Os $(INCLUDES)
LDFLAGS := -lm
ifeq ($(OS),Windows_NT)
LDFLAGS += -lws2_32
endif
TARGET  := build/pulse_kernel
SUBSTRATE_TARGET := build/liminal_core

CORE_SRCS   := core/pulse_kernel.c core/runtime/pulse_kernel_entry.c core/runtime/kernel_context.c \
               core/runtime/kernel_cli_guard.c \
               core/runtime/kernel_runtime_utils.c core/runtime/kernel_sequence.c core/runtime/kernel_sequence_cli.c \
               core/trs_filter.c core/trs_adapt.c core/erb.c core/astro_sync.c core/consent_gate.c \
               core/neural_resonance.c core/kiss_cascade.c core/vse.c core/flow_equilibrium.c core/qel.c
AFFINITY_SRCS := affinity/core.c
ANTICIPATION_SRCS := anticipation/v2.c
INTROSPECT_SRCS := src/introspect.c src/harmony.c src/dream_coupler.c
TUNE_SRCS := tune/autotune.c
SUBSTRATE_SRCS := core/liminal_substrate.c core/trs_filter.c core/trs_adapt.c core/erb.c core/astro_sync.c core/consent_gate.c \
                   core/runtime/kernel_cli_guard.c core/runtime/kernel_runtime_utils.c \
                   core/dream_replay.c core/synaptic_bridge.c core/kiss_cascade.c core/vse.c core/flow_equilibrium.c core/qel.c empathic/field.c memory/emotion_memory.c \
                   memory/soil.c bus/resonant.c council/inner.c coherence/field.c awareness/bridge.c $(AFFINITY_SRCS) $(ANTICIPATION_SRCS)
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

# Empty means automatic discovery. A focused local run may supply module names
# or test paths; validate always uses full discovery independently of this value.
PYTHON_TESTS ?=
C_TEST_NAMES := consent_gate collective_memory collective_graph anticipation_v2 kernel_runtime kernel_context qel vse
C_TEST_BINS := $(addprefix build/tests/test_,$(C_TEST_NAMES))
C_TEST_OBJS := $(addprefix tests/test_,$(addsuffix .o,$(C_TEST_NAMES)))
ALL_OBJS += $(C_TEST_OBJS)
DEPS := $(sort $(ALL_OBJS:.o=.d))

-include $(DEPS)

all: $(TARGET) $(SUBSTRATE_TARGET)

ifeq ($(OS),Windows_NT)
MKDIR_BUILD := powershell -Command "if (-not (Test-Path 'build')) { New-Item -ItemType Directory -Path 'build' }"
else
MKDIR_BUILD := mkdir -p build
endif

$(TARGET): $(OBJS)
	@$(MKDIR_BUILD)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)

$(SUBSTRATE_TARGET): $(SUBSTRATE_OBJS)
	@$(MKDIR_BUILD)
	$(CC) $(CFLAGS) $(SUBSTRATE_OBJS) -o $@ $(LDFLAGS)

core/pulse_kernel.o: core/pulse_kernel.c
	$(CC) $(CFLAGS) -MMD -MP -Dmain=pulse_kernel_core_main -c $< -o $@

tests/%.o: tests/%.c
	$(CC) $(CFLAGS) -Icore/runtime -MMD -MP -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

clean:
ifeq ($(OS),Windows_NT)
	@if exist $(TARGET) del /Q $(TARGET) 2>nul
	@if exist $(SUBSTRATE_TARGET) del /Q $(SUBSTRATE_TARGET) 2>nul
	@for %%f in ($(ALL_OBJS) $(DEPS) $(C_TEST_BINS)) do @if exist %%f del /Q %%f 2>nul
else
	rm -f $(ALL_OBJS) $(DEPS) $(TARGET) $(SUBSTRATE_TARGET) $(C_TEST_BINS)
endif

.PHONY: all clean check test test-c test-python test-python-all test-repo validate verify-core rebirth report report-metabolic long-run-diagnostics trcp-test trcp-sdk-test trcp-sim trcp-replay trcp-external

check: $(TARGET) $(SUBSTRATE_TARGET)
	@echo "🧪 Running smoke checks..."
	@$(TARGET) --dry-run --limit=2
	@$(SUBSTRATE_TARGET) --substrate --limit=2 --trace >/dev/null

build/tests:
	@mkdir -p $@

build/tests/test_consent_gate: tests/test_consent_gate.o core/consent_gate.o | build/tests
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

build/tests/test_collective_memory: tests/test_collective_memory.o collective/memory.o | build/tests
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

build/tests/test_collective_graph: tests/test_collective_graph.o collective/graph.o | build/tests
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -Wl,--wrap=calloc,--wrap=free

build/tests/test_anticipation_v2: tests/test_anticipation_v2.o anticipation/v2.o | build/tests
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

build/tests/test_kernel_runtime: tests/test_kernel_runtime.o core/runtime/kernel_runtime_utils.o core/runtime/kernel_sequence.o core/runtime/kernel_sequence_cli.o | build/tests
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

build/tests/test_kernel_context: tests/test_kernel_context.o core/runtime/kernel_context.o core/runtime/kernel_sequence.o | build/tests
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

build/tests/test_qel: tests/test_qel.o core/qel.o | build/tests
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -Wl,--wrap=fflush

build/tests/test_vse: tests/test_vse.o core/vse.o | build/tests
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -Wl,--wrap=malloc,--wrap=free,--wrap=rand

test-c: $(C_TEST_BINS)
	@set -e; for test_binary in $(C_TEST_BINS); do "$$test_binary"; done

test-python: all
	@$(PYTHON) scripts/run_python_tests.py $(PYTHON_TESTS)

test-python-all: all
	@$(PYTHON) scripts/run_python_tests.py

test: test-c test-python

validate: check test-c test-python-all

test-repo:
	@$(PYTHON) scripts/run_python_tests.py tests/test_repo_hygiene.py

trcp-test:
	@python3 -m unittest tests/test_trcp_simulator.py tests/test_trcp_codex_review.py tests/test_trcp_evidence_replay.py tests/test_trcp_contract_consumer.py tests/test_trcp_external_consumer.py tests/test_trcp_adapter_sdk.py -v

trcp-sdk-test:
	@python3 -m unittest tests/test_trcp_adapter_sdk.py -v

trcp-sim:
	@python3 scripts/run_trcp_simulator.py

trcp-replay:
	@python3 scripts/replay_trcp_evidence.py

trcp-external:
	@python3 scripts/replay_trcp_external_consumer.py

verify-core:
	@bash scripts/verify_core.sh

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
