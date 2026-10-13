#ifndef LIMINAL_COLLECTIVE_H
#define LIMINAL_COLLECTIVE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char id[16];
    float vitality;
    float pulse;
} RNode;

typedef struct {
    int a;
    int b;
    float harmony;
    float flux;
} REdge;

typedef struct {
    RNode *nodes;
    int n_nodes;
    REdge *edges;
    int n_edges;
    float group_coh;
    float pulse_adjust;
    float integral;
    float last_adjust;
    /* Owned buffer bounds. Added fields change the C ABI: rebuild all users. */
    int node_capacity;
    int edge_capacity;
} RGraph;

/* Initialize fresh storage; destroy an initialized graph before reinitializing. */
void rgraph_init(RGraph *g, int nmax_nodes, int nmax_edges);
/* Release init-owned buffers and reset the graph; repeated calls are harmless. */
void rgraph_destroy(RGraph *g);
void rgraph_update_edges(RGraph *g);
float rgraph_compute_coh(RGraph *g);
float rgraph_ensemble_adjust(RGraph *g, float target);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_COLLECTIVE_H */
