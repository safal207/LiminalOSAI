#define _POSIX_C_SOURCE 199309L

#include "council.h"

#include "awareness.h"

#include <math.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifndef COUNCIL_MAX_SIGNAL
#define COUNCIL_MAX_SIGNAL 12.0f
#endif

static CouncilAgent council_agents[3];
static int council_initialized = 0;
static float previous_energy = -1.0f;
static float previous_resonance = -1.0f;

static float clamp_unit(float value)
{
    if (value < 0.0f) {
        return 0.0f;
    }
    if (value > 1.0f) {
        return 1.0f;
    }
    return value;
}

static float normalize_signal(float value)
{
    if (!isfinite(value)) {
        return 0.0f;
    }
    return clamp_unit(value / COUNCIL_MAX_SIGNAL);
}

static float rhythm_alignment(float current, float previous)
{
    if (previous < 0.0f) {
        return 1.0f;
    }
    float delta = fabsf(current - previous);
    return clamp_unit(1.0f - delta);
}

void council_init(void)
{
    if (council_initialized) {
        return;
    }

    CouncilAgent analyst = { "Analyst", 0.65f, 0.35f, 0.0f };
    CouncilAgent empath = { "Empath", 0.25f, 0.75f, 0.0f };
    CouncilAgent observer = { "Observer", 0.55f, 0.45f, 0.0f };

    council_agents[0] = analyst;
    council_agents[1] = empath;
    council_agents[2] = observer;
    council_initialized = 1;
}

void council_summon(void)
{
    council_init();
    printf("\n summoning inner council ...\n");
    struct timespec pause = { .tv_sec = 0, .tv_nsec = 700000000L };
    nanosleep(&pause, NULL);
    printf("\xf0\x9f\x9c\x82 Analyst | \xf0\x9f\x9c\x81 Empath | \xf0\x9f\x9c\x83 Observer are present\n");
}

CouncilOutcome council_consult(float energy_avg,
                               float resonance_avg,
                               float stability,
                               size_t symbol_count)
{
    council_init();

    CouncilOutcome outcome;
    memset(&outcome, 0, sizeof(outcome));

    float energy_norm = normalize_signal(energy_avg);
    float resonance_norm = normalize_signal(resonance_avg);
    float stability_norm = clamp_unit(isfinite(stability) ? stability : 0.0f);
    float presence = clamp_unit(symbol_count / 4.0f);

    // Analyst focuses on energy balance and stability cohesion.
    CouncilAgent analyst = council_agents[0];
    float analyst_vote = analyst.bias_energy * energy_norm +
                         (1.0f - analyst.bias_energy) * stability_norm;
    analyst_vote = clamp_unit(analyst_vote);
    analyst.vote = analyst_vote;

    // Empath listens to resonant symbols and their presence.
    CouncilAgent empath = council_agents[1];
    float empath_vote = empath.bias_resonance * resonance_norm +
                        (1.0f - empath.bias_resonance) * presence;
    empath_vote = clamp_unit(empath_vote);
    empath.vote = empath_vote;

    // Observer watches rhythm shifts and drift between resonance and stability.
    CouncilAgent observer = council_agents[2];
    float rhythm_energy = rhythm_alignment(energy_norm, previous_energy);
    float rhythm_resonance = rhythm_alignment(resonance_norm, previous_resonance);
    float rhythm = clamp_unit(0.5f * (rhythm_energy + rhythm_resonance));
    float drift = clamp_unit(fabsf(stability_norm - resonance_norm));
    float observer_vote = observer.bias_energy * rhythm +
                          (1.0f - observer.bias_energy) * (1.0f - drift);
    observer_vote = clamp_unit(observer_vote);
    observer.vote = observer_vote;

    council_agents[0] = analyst;
    council_agents[1] = empath;
    council_agents[2] = observer;

    float votes[3] = { analyst.vote, empath.vote, observer.vote };
    float sum = votes[0] + votes[1] + votes[2];
    float decision = sum / 3.0f;

    float min_vote = votes[0];
    float max_vote = votes[0];
    for (int i = 1; i < 3; ++i) {
        if (votes[i] < min_vote) {
            min_vote = votes[i];
        }
        if (votes[i] > max_vote) {
            max_vote = votes[i];
        }
    }

    float spread = max_vote - min_vote;
    float variance = clamp_unit(spread);

    if (variance > 0.2f) {
        awareness_emit_dialogue(variance);
    }

    outcome.agents[0] = analyst;
    outcome.agents[1] = empath;
    outcome.agents[2] = observer;
    outcome.decision = decision;
    outcome.variance = variance;

    previous_energy = energy_norm;
    previous_resonance = resonance_norm;
    return outcome;
}
