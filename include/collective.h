#ifndef LIMINAL_INCLUDE_COLLECTIVE_H
#define LIMINAL_INCLUDE_COLLECTIVE_H

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
} RGraph;

void rgraph_init(RGraph *g, int nmax_nodes, int nmax_edges);
void rgraph_update_edges(RGraph *g);
float rgraph_compute_coh(RGraph *g);
float rgraph_ensemble_adjust(RGraph *g, float target);

#ifdef __cplusplus
}
#endif

#endif /* LIMINAL_INCLUDE_COLLECTIVE_H */
