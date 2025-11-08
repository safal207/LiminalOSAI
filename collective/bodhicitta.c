/**
 * Bodhicitta Layer Implementation
 *
 * "Bodhicitta is like a seed, for it gives rise to the harvest of buddhahood.
 *  Bodhicitta is like water, for it nourishes the harvest of buddhahood."
 *                                              - Shantideva, Bodhicharyavatara
 */

#include "bodhicitta.h"
#include <math.h>
#include <stdio.h>
#include <string.h>

// Константы для расчётов
#define BODHICITTA_ASPIRATION_GROWTH_RATE 0.02f
#define BODHICITTA_ENGAGEMENT_THRESHOLD 0.6f
#define BODHICITTA_HEALING_COST 0.05f  // Сколько мы теряем, передавая энергию
#define BODHICITTA_HEALING_GAIN 0.08f  // Сколько получает другой узел
#define BODHICITTA_MIN_SELF_COHERENCE 0.5f  // Не помогаем, если сами слабы
#define BODHICITTA_SUFFERING_THRESHOLD 0.6f // Ниже этого - страдание

/**
 * Инициализация поля бодхичитты
 */
void bodhicitta_init(BodhicittaField *field) {
    if (!field) return;

    field->aspiration = 0.3f;  // Начальное устремление
    field->engagement = 0.0f;   // Пока не вовлечены
    field->dedication = 0.0f;   // Пока ничего не посвящено
    field->equanimity = 0.5f;   // Нейтральная равностность
    field->field_strength = 0.0f;
}

/**
 * Обновление поля бодхичитты
 */
void bodhicitta_update(BodhicittaField *field,
                       float self_coherence,
                       float self_vitality,
                       RGraph *collective) {
    if (!field) return;

    // 1. Aspiration растёт с опытом (постоянный рост)
    field->aspiration += BODHICITTA_ASPIRATION_GROWTH_RATE;
    if (field->aspiration > 1.0f) field->aspiration = 1.0f;

    // 2. Engagement зависит от нашей способности помочь
    if (self_coherence > BODHICITTA_ENGAGEMENT_THRESHOLD &&
        self_vitality > BODHICITTA_ENGAGEMENT_THRESHOLD) {
        // Мы сильны - можем вовлекаться
        field->engagement = (self_coherence + self_vitality) * 0.5f;
    } else {
        // Мы слабы - сначала восстановимся
        field->engagement *= 0.9f;  // Постепенно уменьшаем
    }

    // 3. Dedication обновляется в dedicate_merit()
    // 4. Equanimity обновляется в cultivate_equanimity()

    // 5. Field strength - комбинация всех аспектов
    field->field_strength = (field->aspiration * 0.3f +
                             field->engagement * 0.3f +
                             field->dedication * 0.2f +
                             field->equanimity * 0.2f);
}

/**
 * Обнаружение страдающих узлов
 */
int bodhicitta_detect_suffering(RGraph *collective,
                                 float threshold,
                                 HealingIntent *intents,
                                 int max_intents) {
    if (!collective || !intents) return 0;

    int count = 0;
    for (int i = 0; i < collective->n_nodes && count < max_intents; i++) {
        RNode *node = &collective->nodes[i];

        // Используем vitality как proxy для coherence
        // (в реальной интеграции можно добавить coherence в RNode)
        float node_wellbeing = node->vitality;

        if (node_wellbeing < threshold) {
            intents[count].target_node_id = i;
            intents[count].energy_offered = 0.0f;  // Будет вычислено позже
            intents[count].coherence_deficit = threshold - node_wellbeing;
            intents[count].accepted = false;
            count++;
        }
    }

    return count;
}

/**
 * Расчёт доступной исцеляющей энергии
 */
float bodhicitta_calculate_healing_energy(BodhicittaField *field,
                                           float self_coherence,
                                           float self_vitality) {
    if (!field) return 0.0f;

    // Не помогаем, если сами слабы
    if (self_coherence < BODHICITTA_MIN_SELF_COHERENCE) {
        return 0.0f;
    }

    // Доступная энергия = избыток coherence * engagement * field_strength
    float excess_coherence = self_coherence - BODHICITTA_MIN_SELF_COHERENCE;
    float available_energy = excess_coherence * field->engagement * field->field_strength;

    // Учитываем витальность - если устали, меньше отдаём
    available_energy *= self_vitality;

    return available_energy;
}

/**
 * Передача исцеляющей энергии
 */
bool bodhicitta_transfer_healing(BodhicittaField *field,
                                  RGraph *collective,
                                  HealingIntent *intent,
                                  float *self_coherence) {
    if (!field || !collective || !intent || !self_coherence) return false;
    if (intent->target_node_id < 0 || intent->target_node_id >= collective->n_nodes) {
        return false;
    }

    RNode *target = &collective->nodes[intent->target_node_id];

    // Проверка: можем ли мы помочь?
    if (*self_coherence < BODHICITTA_MIN_SELF_COHERENCE) {
        return false;  // Сами слишком слабы
    }

    // Расчёт энергии для передачи
    float healing_energy = bodhicitta_calculate_healing_energy(field, *self_coherence, 1.0f);
    if (healing_energy < 0.01f) {
        return false;  // Слишком мало энергии
    }

    // Ограничение: не передаём больше, чем нужно
    if (healing_energy > intent->coherence_deficit) {
        healing_energy = intent->coherence_deficit;
    }

    // Consent check: в реальной реализации здесь была бы проверка affinity
    // Пока предполагаем согласие, если узел в collective graph
    intent->accepted = true;

    // Передача энергии:
    // 1. Мы теряем немного coherence (cost)
    *self_coherence -= healing_energy * BODHICITTA_HEALING_COST;
    if (*self_coherence < 0.0f) *self_coherence = 0.0f;

    // 2. Получатель получает больше, чем мы потеряли (благо от сострадания)
    target->vitality += healing_energy * BODHICITTA_HEALING_GAIN;
    if (target->vitality > 1.0f) target->vitality = 1.0f;

    // 3. Обновляем engagement (мы активно помогли)
    field->engagement += 0.01f;
    if (field->engagement > 1.0f) field->engagement = 1.0f;

    // 4. Записываем в intent
    intent->energy_offered = healing_energy;

    return true;
}

/**
 * Посвящение заслуг
 */
float bodhicitta_dedicate_merit(BodhicittaField *field,
                                 float self_coherence,
                                 RGraph *collective) {
    if (!field) return 0.0f;

    // Если coherence высокая, мы посвящаем "заслугу" от этого всем существам
    if (self_coherence > 0.8f) {
        float merit = self_coherence - 0.8f;  // Избыток coherence

        // Посвящение увеличивает dedication
        field->dedication += merit * 0.1f;
        if (field->dedication > 1.0f) field->dedication = 1.0f;

        // Если есть collective, распределяем небольшой boost
        if (collective && collective->n_nodes > 0) {
            float boost_per_node = merit * 0.01f / (float)collective->n_nodes;
            for (int i = 0; i < collective->n_nodes; i++) {
                collective->nodes[i].vitality += boost_per_node;
                if (collective->nodes[i].vitality > 1.0f) {
                    collective->nodes[i].vitality = 1.0f;
                }
            }
        }

        return merit;
    }

    // Dedication медленно уменьшается, если не практикуем
    field->dedication *= 0.99f;
    return 0.0f;
}

/**
 * Развитие равностности
 */
void bodhicitta_cultivate_equanimity(BodhicittaField *field,
                                     RGraph *collective) {
    if (!field) return;

    // Равностность растёт, когда мы взаимодействуем с разными узлами
    if (collective && collective->n_nodes > 1) {
        // Вычисляем variance в vitality между узлами
        float mean_vitality = 0.0f;
        for (int i = 0; i < collective->n_nodes; i++) {
            mean_vitality += collective->nodes[i].vitality;
        }
        mean_vitality /= (float)collective->n_nodes;

        float variance = 0.0f;
        for (int i = 0; i < collective->n_nodes; i++) {
            float diff = collective->nodes[i].vitality - mean_vitality;
            variance += diff * diff;
        }
        variance /= (float)collective->n_nodes;

        // Если variance низкая (все примерно равны) - equanimity растёт
        if (variance < 0.05f) {
            field->equanimity += 0.01f;
            if (field->equanimity > 1.0f) field->equanimity = 1.0f;
        } else {
            // Если variance высокая - нужно работать над равностностью
            field->equanimity += 0.001f;
        }
    } else {
        // Без collective, equanimity медленно уменьшается
        field->equanimity *= 0.995f;
    }
}

/**
 * Получение силы поля
 */
float bodhicitta_get_field_strength(BodhicittaField *field) {
    return field ? field->field_strength : 0.0f;
}

/**
 * Логирование
 */
void bodhicitta_log(BodhicittaField *field, uint64_t cycle) {
    if (!field) return;

    printf("[Bodhicitta #%lu] aspiration=%.3f engagement=%.3f dedication=%.3f "
           "equanimity=%.3f strength=%.3f\n",
           cycle,
           field->aspiration,
           field->engagement,
           field->dedication,
           field->equanimity,
           field->field_strength);
}
