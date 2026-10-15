#include "vse.h"

#include <assert.h>
#include <math.h>
#include <stddef.h>
#include <stdlib.h>

static unsigned malloc_count;
static unsigned free_count;
static unsigned rand_count;
static int fail_after = -1;
static void *allocations[16];

void *__real_malloc(size_t size);
void __real_free(void *pointer);
int __real_rand(void);

void *__wrap_malloc(size_t size)
{
    ++malloc_count;
    if (fail_after == 0) {
        return NULL;
    }
    if (fail_after > 0) {
        --fail_after;
    }
    void *pointer = __real_malloc(size);
    if (pointer) {
        unsigned index = 0;
        while (index < 16U && allocations[index]) {
            ++index;
        }
        assert(index < 16U);
        allocations[index] = pointer;
    }
    return pointer;
}

void __wrap_free(void *pointer)
{
    if (pointer) {
        ++free_count;
        unsigned index = 0;
        while (index < 16U && allocations[index] != pointer) {
            ++index;
        }
        assert(index < 16U);
        allocations[index] = NULL;
    }
    __real_free(pointer);
}

int __wrap_rand(void)
{
    ++rand_count;
    return __real_rand();
}

static void assert_no_allocations(void)
{
    for (unsigned index = 0; index < 16U; ++index) {
        assert(!allocations[index]);
    }
}

int main(void)
{
    VSECfg config = { .intent = 0.6f, .importance = 0.5f, .allowance = 0.2f, .temp = 0.8f };
    VSEState state = {0};
    VNode choices[7] = {
        { .p = 0.5f, .value = 1000.0f },
        { .p = 0.5f, .value = -1000.0f },
        { .p = 0.5f, .value = -1000.0f },
        { .p = 0.5f, .value = -1000.0f },
        { .p = 0.5f, .value = -1000.0f },
        { .p = 0.5f, .value = -1000.0f },
        { .p = 0.5f, .value = -1000.0f }
    };
    vse_init(config);
    assert(vse_pick(&state) == -1);
    assert(rand_count == 0U);
    vse_set_graph(choices, 3);
    assert(malloc_count == 2U);
    srand(42);
    assert(vse_pick(&state) == 0);
    assert(fabsf(state.excess - 0.3f) < 1e-6f);
    assert(fabsf(state.bias - 0.15f) < 1e-6f);

    malloc_count = free_count = rand_count = 0;
    for (unsigned cycle = 0; cycle < 128U; ++cycle) {
        vse_set_graph(choices, 3);
        assert(vse_pick(&state) == 0);
        vse_feedback(&state, 0.25f);
    }
    assert(malloc_count == 0U);
    assert(free_count == 0U);
    assert(rand_count == 128U);

    vse_set_graph(choices, 7);
    assert(malloc_count == 2U && free_count == 2U);
    assert(vse_pick(&state) == 0);
    malloc_count = free_count = 0;
    vse_set_graph(choices, 2);
    assert(vse_pick(&state) == 0);
    assert(malloc_count == 0U && free_count == 0U);

    vse_set_graph(NULL, 0);
    unsigned samples = rand_count;
    assert(vse_pick(&state) == -1);
    assert(rand_count == samples);
    assert(malloc_count == 0U && free_count == 0U);
    vse_set_graph(choices, 3);
    assert(vse_pick(&state) == 0);

    VNode larger[8] = {0};
    fail_after = 1; /* Graph allocation succeeds; workspace allocation fails. */
    vse_set_graph(larger, 8);
    assert(malloc_count == 2U && free_count == 1U);
    samples = rand_count;
    assert(vse_pick(&state) == -1);
    assert(rand_count == samples);
    fail_after = -1;
    malloc_count = free_count = 0;
    vse_set_graph(choices, 3); /* The retained capacity remains usable after failure. */
    assert(vse_pick(&state) == 0);
    assert(malloc_count == 0U && free_count == 0U);

    choices[0].p = NAN;
    choices[0].cost = -INFINITY;
    choices[0].pendulum = INFINITY;
    vse_set_graph(choices, 3);
    assert(vse_pick(&state) == 0);
    assert(isfinite(state.excess) && isfinite(state.bias));
    vse_finalize();
    assert(free_count == 2U);
    assert_no_allocations();
    vse_finalize();
    assert(free_count == 2U);
    vse_init(config);
    assert(vse_pick(&state) == -1);
    vse_set_graph(choices, 1);
    assert(vse_pick(&state) == 0);
    vse_finalize();
    assert_no_allocations();
    return 0;
}
