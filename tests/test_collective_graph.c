#include "collective.h"

#include <assert.h>
#include <limits.h>
#include <math.h>
#include <stddef.h>
#include <stdlib.h>

static int fail_after = -1;
static unsigned calloc_count;
static unsigned free_count;
static void *allocations[16];

void *__real_calloc(size_t count, size_t size);
void __real_free(void *pointer);

void *__wrap_calloc(size_t count, size_t size)
{
    ++calloc_count;
    if (fail_after == 0) {
        return NULL;
    }
    if (fail_after > 0) {
        --fail_after;
    }
    void *pointer = __real_calloc(count, size);
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

static void assert_empty(const RGraph *graph)
{
    assert(!graph->nodes && !graph->edges);
    assert(graph->n_nodes == 0 && graph->n_edges == 0);
    assert(graph->node_capacity == 0 && graph->edge_capacity == 0);
    assert(graph->group_coh == 0.0f && graph->pulse_adjust == 0.0f);
    assert(graph->integral == 0.0f && graph->last_adjust == 0.0f);
}

static void assert_no_allocations(void)
{
    for (unsigned index = 0; index < 16U; ++index) {
        assert(!allocations[index]);
    }
}

static void test_two_graph_bounds_and_valid_behavior(void)
{
    RGraph first, second;
    rgraph_init(&first, 2, 1);
    first.nodes[0].pulse = 0.2f;
    first.nodes[1].pulse = 0.4f;
    first.nodes[0].vitality = 1.0f;
    first.nodes[1].vitality = 0.5f;
    first.edges[0].a = 0;
    first.edges[0].b = 1;
    rgraph_init(&second, 3, 2); /* Previously invalidated first's only bounds. */
    for (int index = 0; index < 3; ++index) {
        second.nodes[index].pulse = index * 0.5f;
        second.nodes[index].vitality = 1.0f;
    }
    second.edges[0].a = 0;
    second.edges[0].b = 1;
    second.edges[1].a = 1;
    second.edges[1].b = 2;
    second.n_nodes = 3;
    second.n_edges = 2;

    first.n_nodes = first.n_edges = INT_MAX;
    rgraph_update_edges(&first);
    assert(first.n_nodes == 2 && first.n_edges == 1);
    assert(second.n_nodes == 3 && second.n_edges == 2);
    assert(fabsf(first.edges[0].harmony - 0.8f) < 1e-6f);
    assert(fabsf(first.edges[0].flux - 0.6f) < 1e-6f);
    rgraph_update_edges(&second);
    assert(fabsf(rgraph_compute_coh(&second) - 0.5f) < 1e-6f);

    first.n_nodes = first.n_edges = INT_MAX;
    assert(fabsf(rgraph_compute_coh(&first) - 0.8f) < 1e-6f);
    assert(first.n_nodes == 2 && first.n_edges == 1);
    first.n_nodes = first.n_edges = INT_MAX;
    assert(fabsf(rgraph_ensemble_adjust(&first, 0.9f) - 0.0032f) < 1e-6f);
    assert(first.n_nodes == 2 && first.n_edges == 1);
    assert(fabsf(rgraph_ensemble_adjust(&second, 0.8f) - 0.0096f) < 1e-6f);

    first.edges[0].b = 2; /* Outside this graph, inside the other graph. */
    first.n_nodes = INT_MAX;
    rgraph_update_edges(&first);
    assert(first.n_nodes == 2);
    assert(first.edges[0].harmony == 0.0f && first.edges[0].flux == 0.0f);
    assert(rgraph_compute_coh(&first) == 0.0f);
    assert(rgraph_ensemble_adjust(&first, 0.9f) == 0.0f);

    first.n_nodes = first.n_edges = -1;
    rgraph_update_edges(&first);
    assert(first.n_nodes == 0 && first.n_edges == 0);
    first.n_nodes = first.n_edges = -2;
    assert(rgraph_compute_coh(&first) == 0.0f);
    assert(first.n_nodes == 0 && first.n_edges == 0);
    first.n_nodes = first.n_edges = -3;
    first.integral = first.last_adjust = first.pulse_adjust = 0.5f;
    assert(rgraph_ensemble_adjust(&first, 0.9f) == 0.0f);
    assert(first.n_nodes == 0 && first.n_edges == 0);
    assert(first.integral == 0.0f && first.last_adjust == 0.0f);

    rgraph_destroy(&first);
    assert_empty(&first);
    second.n_nodes = second.n_edges = INT_MAX;
    rgraph_update_edges(&second);
    assert(second.n_nodes == 3 && second.n_edges == 2);
    assert(fabsf(rgraph_compute_coh(&second) - 0.5f) < 1e-6f);
    rgraph_destroy(&second);
    assert_empty(&second);
    unsigned released = free_count;
    rgraph_destroy(&first);
    rgraph_destroy(&second);
    assert(free_count == released);
    assert_no_allocations();
}

static void test_empty_and_failed_initialization(void)
{
    RGraph graph;
    rgraph_init(&graph, -1, -1);
    assert_empty(&graph);
    graph.n_nodes = graph.n_edges = INT_MAX;
    rgraph_update_edges(&graph);
    assert_empty(&graph);
    graph.n_nodes = graph.n_edges = INT_MAX;
    assert(rgraph_compute_coh(&graph) == 0.0f);
    assert_empty(&graph);
    graph.n_nodes = graph.n_edges = INT_MAX;
    assert(rgraph_ensemble_adjust(&graph, 1.0f) == 0.0f);
    assert_empty(&graph);
    rgraph_destroy(&graph);

    calloc_count = free_count = 0;
    fail_after = 0;
    rgraph_init(&graph, 2, 1);
    assert(calloc_count == 1U && free_count == 0U);
    assert_empty(&graph);
    rgraph_destroy(&graph);
    fail_after = 1;
    calloc_count = free_count = 0;
    rgraph_init(&graph, 2, 1);
    assert(calloc_count == 2U && free_count == 1U);
    assert_empty(&graph);
    rgraph_destroy(&graph);
    assert(free_count == 1U);
    assert_no_allocations();
    fail_after = -1;

    rgraph_init(&graph, 1, 0);
    assert(graph.nodes && !graph.edges);
    assert(graph.node_capacity == 1 && graph.edge_capacity == 0);
    graph.n_nodes = graph.n_edges = INT_MAX;
    rgraph_update_edges(&graph);
    assert(graph.n_nodes == 1 && graph.n_edges == 0);
    assert(rgraph_compute_coh(&graph) == 0.0f);
    assert(rgraph_ensemble_adjust(&graph, 1.0f) == 0.0f);
    rgraph_destroy(&graph);
    assert_empty(&graph);
    rgraph_init(&graph, 0, 1);
    assert(!graph.nodes && graph.edges);
    assert(graph.node_capacity == 0 && graph.edge_capacity == 1);
    rgraph_destroy(&graph);
    assert_no_allocations();

    rgraph_init(NULL, 2, 1);
    rgraph_destroy(NULL);
    rgraph_update_edges(NULL);
    assert(rgraph_compute_coh(NULL) == 0.0f);
    assert(rgraph_ensemble_adjust(NULL, 1.0f) == 0.0f);
}

int main(void)
{
    test_two_graph_bounds_and_valid_behavior();
    test_empty_and_failed_initialization();
    return 0;
}
