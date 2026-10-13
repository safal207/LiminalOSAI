#define _POSIX_C_SOURCE 200809L

#include "qel.h"

#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned flush_count;

int __real_fflush(FILE *stream);
int __wrap_fflush(FILE *stream)
{
    ++flush_count;
    return __real_fflush(stream);
}

static size_t read_log(const char *directory, const char *name, char *buffer, size_t capacity)
{
    char path[512];
    assert(snprintf(path, sizeof(path), "%s/%s", directory, name) > 0);
    FILE *stream = fopen(path, "rb");
    assert(stream);
    size_t length = fread(buffer, 1, capacity - 1U, stream);
    assert(!ferror(stream));
    assert(feof(stream));
    buffer[length] = '\0';
    fclose(stream);
    return length;
}

static void remove_log(const char *directory, const char *name)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", directory, name);
    assert(remove(path) == 0);
}

int main(void)
{
    char directory[] = "/tmp/liminal-qel-test-XXXXXX";
    assert(mkdtemp(directory));
    qel_state *state = qel_init(directory, 2);
    assert(state);
    qel_obs_t first = { .t = 1.0, .amp = 0.4f, .tempo = 0.8f,
                        .consent = 1.0f, .influence = 0.2f, .harmony = 0.8f, .ctx = 1 };
    qel_mark_observation(state, &first);
    assert(flush_count == 1U);
    char log[2048];
    const char *raw = "{\"t\":1.000,\"amp\":0.4000,\"tempo\":0.8000,\"consent\":1.0000,"
                      "\"influence\":0.2000,\"harmony\":0.8000,\"ctx\":1,"
                      "\"adj_infl\":0.2000,\"revised\":false}\n";
    read_log(directory, "qel_raw.jsonl", log, sizeof(log));
    assert(strcmp(log, raw) == 0); /* Visible before qel_free. */

    qel_obs_t second = first;
    second.t = 2.0;
    second.ctx = 2;
    qel_mark_observation(state, &second);
    qel_retro_t retro = { .t_new = 1.0, .retro_gain = 0.5f, .ctx_mask = 1 };
    qel_apply_retro(state, &retro);
    flush_count = 0;
    qel_commit_revision(state);
    assert(flush_count == 1U);
    const char *revision = "{\"t\":1.000,\"amp\":0.4000,\"tempo\":0.8000,\"consent\":1.0000,"
                           "\"influence\":0.2000,\"harmony\":0.8000,\"ctx\":1,"
                           "\"adj_infl\":0.5000,\"revised\":true}\n";
    size_t length = read_log(directory, "qel_rev.jsonl", log, sizeof(log));
    assert(strcmp(log, revision) == 0);
    assert(fabsf(qel_influence(state, 0.2f, 1) - 0.35f) < 1e-6f);
    assert(qel_influence(state, 0.2f, 2) == 0.2f);

    qel_commit_revision(state); /* Existing repeated-commit rows are preserved. */
    assert(flush_count == 2U);
    assert(read_log(directory, "qel_rev.jsonl", log, sizeof(log)) == 2U * length);
    assert(memcmp(log, revision, length) == 0);
    assert(memcmp(log + length, revision, length) == 0);

    qel_obs_t third = first;
    third.t = 3.0;
    third.influence = 0.6f;
    qel_mark_observation(state, &third); /* Wrap replaces the only revised slot. */
    assert(qel_influence(state, 0.6f, 1) == 0.6f);
    flush_count = 0;
    qel_commit_revision(state);
    assert(flush_count == 0U);
    assert(read_log(directory, "qel_rev.jsonl", log, sizeof(log)) == 2U * length);
    qel_free(state);
    remove_log(directory, "qel_raw.jsonl");
    remove_log(directory, "qel_rev.jsonl");

    state = qel_init(directory, 4096);
    assert(state);
    for (unsigned index = 0; index < 4096U; ++index) {
        first.t = index;
        qel_mark_observation(state, &first);
    }
    retro.t_new = 4095.0;
    qel_apply_retro(state, &retro);
    flush_count = 0;
    qel_commit_revision(state);
    assert(flush_count == 1U); /* 4096 retained rows, one public-call flush. */
    qel_free(state);
    char path[512];
    snprintf(path, sizeof(path), "%s/qel_rev.jsonl", directory);
    FILE *stream = fopen(path, "rb");
    assert(stream);
    unsigned rows = 0;
    int byte;
    while ((byte = fgetc(stream)) != EOF) {
        rows += byte == '\n';
    }
    assert(rows == 4096U);
    fclose(stream);
    remove_log(directory, "qel_raw.jsonl");
    remove_log(directory, "qel_rev.jsonl");
    assert(rmdir(directory) == 0);
    return 0;
}
