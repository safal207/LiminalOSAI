#include "collective.h"

#include <float.h>
#include <math.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static void graph_bound_counts(RGraph *g)
{
    if (!g) {
        return;
    }
    int nodes = g->nodes && g->node_capacity > 0 ? g->node_capacity : 0;
    int edges = g->edges && g->edge_capacity > 0 ? g->edge_capacity : 0;
    if (g->n_nodes < 0) {
        g->n_nodes = 0;
    } else if (g->n_nodes > nodes) {
        g->n_nodes = nodes;
    }
    if (g->n_edges < 0) {
        g->n_edges = 0;
    } else if (g->n_edges > edges) {
        g->n_edges = edges;
    }
}

void rgraph_destroy(RGraph *g)
{
    if (!g) {
        return;
    }
    free(g->nodes);
    free(g->edges);
    memset(g, 0, sizeof(*g));
}

static float clamp01(float value)
{
    if (value < 0.0f) {
        return 0.0f;
    }
    if (value > 1.0f) {
        return 1.0f;
    }
    return value;
}

void rgraph_init(RGraph *g, int nmax_nodes, int nmax_edges)
{
    if (!g) {
        return;
    }

    if (nmax_nodes < 0) {
        nmax_nodes = 0;
    }
    if (nmax_edges < 0) {
        nmax_edges = 0;
    }

    memset(g, 0, sizeof(*g));

    if (nmax_nodes > 0) {
        g->nodes = (RNode *)calloc((size_t)nmax_nodes, sizeof(RNode));
        if (!g->nodes) {
            return;
        }
        g->node_capacity = nmax_nodes;
    }
    if (nmax_edges > 0) {
        g->edges = (REdge *)calloc((size_t)nmax_edges, sizeof(REdge));
        if (!g->edges) {
            rgraph_destroy(g);
            return;
        }
        g->edge_capacity = nmax_edges;
    }
}

void rgraph_update_edges(RGraph *g)
{
    graph_bound_counts(g);
    if (!g || !g->edges || !g->nodes) {
        return;
    }

    for (int i = 0; i < g->n_edges; ++i) {
        REdge *edge = &g->edges[i];
        if (!edge) {
            continue;
        }
        if (edge->a < 0 || edge->b < 0 || edge->a >= g->n_nodes || edge->b >= g->n_nodes) {
            edge->harmony = 0.0f;
            edge->flux = 0.0f;
            continue;
        }

        const RNode *na = &g->nodes[edge->a];
        const RNode *nb = &g->nodes[edge->b];
        float pulse_diff = fabsf(na->pulse - nb->pulse);
        float harmony = 1.0f - pulse_diff;
        if (harmony < 0.0f) {
            harmony = 0.0f;
        } else if (harmony > 1.0f) {
            harmony = 1.0f;
        }
        float vitality_avg = 0.5f * (na->vitality + nb->vitality);
        if (vitality_avg < 0.0f) {
            vitality_avg = 0.0f;
        }
        float flux = vitality_avg * harmony;
        if (!isfinite(flux)) {
            flux = 0.0f;
        }

        edge->harmony = harmony;
        edge->flux = flux;
    }
}

float rgraph_compute_coh(RGraph *g)
{
    graph_bound_counts(g);
    if (!g || !g->edges) {
        if (g) {
            g->group_coh = 0.0f;
        }
        return 0.0f;
    }

    float flux_sum = 0.0f;
    float weighted_sum = 0.0f;
    for (int i = 0; i < g->n_edges; ++i) {
        const REdge *edge = &g->edges[i];
        if (!edge) {
            continue;
        }
        if (edge->flux <= 0.0f) {
            continue;
        }
        flux_sum += edge->flux;
        weighted_sum += edge->harmony * edge->flux;
    }

    if (flux_sum <= FLT_EPSILON) {
        g->group_coh = 0.0f;
        return 0.0f;
    }

    g->group_coh = clamp01(weighted_sum / flux_sum);
    return g->group_coh;
}

static float graph_total_flux(const RGraph *g)
{
    if (!g || !g->edges) {
        return 0.0f;
    }
    float total = 0.0f;
    for (int i = 0; i < g->n_edges; ++i) {
        const REdge *edge = &g->edges[i];
        if (edge) {
            total += edge->flux;
        }
    }
    return total;
}

float rgraph_ensemble_adjust(RGraph *g, float target)
{
    graph_bound_counts(g);
    if (!g) {
        return 0.0f;
    }

    if (g->n_edges <= 0) {
        g->pulse_adjust = 0.0f;
        g->last_adjust = 0.0f;
        g->integral = 0.0f;
        return 0.0f;
    }

    float total_flux = graph_total_flux(g);
    if (total_flux <= FLT_EPSILON) {
        g->pulse_adjust = 0.0f;
        g->last_adjust = 0.0f;
        g->integral = 0.0f;
        return 0.0f;
    }

    float clamped_target = clamp01(target);
    float err = clamped_target - clamp01(g->group_coh);

    const float kP = 0.12f;
    const float kI = 0.04f;

    g->integral += err;
    if (g->integral > 1.0f) {
        g->integral = 1.0f;
    } else if (g->integral < -1.0f) {
        g->integral = -1.0f;
    }

    float raw = kP * err + kI * g->integral;
    if (fabsf(err) < 0.03f) {
        raw = 0.0f;
    }

    float delta = raw - g->last_adjust;
    if (delta > 0.08f) {
        raw = g->last_adjust + 0.08f;
    } else if (delta < -0.08f) {
        raw = g->last_adjust - 0.08f;
    }

    g->pulse_adjust = 0.8f * g->last_adjust + 0.2f * raw;
    if (g->pulse_adjust > 1.0f) {
        g->pulse_adjust = 1.0f;
    } else if (g->pulse_adjust < -1.0f) {
        g->pulse_adjust = -1.0f;
    }
    g->last_adjust = g->pulse_adjust;

    return g->pulse_adjust;
}
