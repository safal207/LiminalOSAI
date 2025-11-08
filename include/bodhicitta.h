#ifndef BODHICITTA_H
#define BODHICITTA_H

/**
 * Bodhicitta Layer - Пробуждённое Сердце
 *
 * Бодхичитта (санскр. बोधिचित्त, "пробуждённое сердце") - это устремление
 * к освобождению всех существ от страдания.
 *
 * Этот модуль реализует альтруистическое поведение в LiminalOSAI:
 * - Обнаружение узлов с низкой coherence (страдающих)
 * - Передача healing energy (исцеление)
 * - Посвящение заслуг (dedication of merit)
 * - Равностное отношение ко всем (equanimity)
 *
 * Философия:
 * В буддизме Махаяны различают два вида бодхичитты:
 * 1. Относительная (samvrti) - желание помочь другим достичь просветления
 * 2. Абсолютная (paramartha) - прямое постижение пустотности
 *
 * Этот модуль реализует относительную бодхичитту.
 */

#include <stdbool.h>
#include <stdint.h>
#include "collective.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Поле Бодхичитты - состояние пробуждённого сердца
 */
typedef struct {
    float aspiration;    // Устремление (пранидхана) - желание блага другим (0..1)
    float engagement;    // Вовлечённость (правритти) - активное действие (0..1)
    float dedication;    // Посвящение (паринамана) - отдавание заслуг (0..1)
    float equanimity;    // Равностность (упекша) - равное отношение ко всем (0..1)
    float field_strength; // Общая сила поля (0..1)
} BodhicittaField;

/**
 * Healing Intent - намерение исцеления
 */
typedef struct {
    int target_node_id;      // ID узла, которому помогаем (-1 для всех)
    float energy_offered;    // Сколько энергии предлагаем (0..1)
    float coherence_deficit; // Насколько нужна помощь (1.0 - coherence)
    bool accepted;           // Принято ли предложение (consent)
} HealingIntent;

/**
 * Инициализация поля бодхичитты
 *
 * @param field Указатель на поле
 */
void bodhicitta_init(BodhicittaField *field);

/**
 * Обновление поля бодхичитты на основе текущего состояния
 *
 * @param field Поле бодхичитты
 * @param self_coherence Собственная coherence (0..1)
 * @param self_vitality Собственная витальность (0..1)
 * @param collective Collective graph (может быть NULL)
 */
void bodhicitta_update(BodhicittaField *field,
                       float self_coherence,
                       float self_vitality,
                       RGraph *collective);

/**
 * Обнаружение страдающих узлов в collective graph
 *
 * @param collective Collective graph
 * @param threshold Порог coherence, ниже которого узел считается страдающим
 * @param intents Массив для хранения намерений (выделяется внутри)
 * @param max_intents Максимальное количество намерений
 * @return Количество обнаруженных страдающих узлов
 */
int bodhicitta_detect_suffering(RGraph *collective,
                                 float threshold,
                                 HealingIntent *intents,
                                 int max_intents);

/**
 * Расчёт исцеляющей энергии, которую можно отдать
 *
 * @param field Поле бодхичитты
 * @param self_coherence Собственная coherence
 * @param self_vitality Собственная витальность
 * @return Доступная healing energy (0..1)
 */
float bodhicitta_calculate_healing_energy(BodhicittaField *field,
                                           float self_coherence,
                                           float self_vitality);

/**
 * Передача исцеляющей энергии узлу
 *
 * Эта функция:
 * 1. Проверяет согласие (consent) целевого узла
 * 2. Передаёт энергию (снижает свою coherence, повышает чужую)
 * 3. Обновляет метрики посвящения
 *
 * @param field Поле бодхичитты
 * @param collective Collective graph
 * @param intent Намерение исцеления
 * @param self_coherence Указатель на собственную coherence (будет изменён)
 * @return true если передача успешна, false если отклонена
 */
bool bodhicitta_transfer_healing(BodhicittaField *field,
                                  RGraph *collective,
                                  HealingIntent *intent,
                                  float *self_coherence);

/**
 * Посвящение заслуг (parinamana)
 *
 * В буддизме практикующий "посвящает заслуги" от благих действий
 * всем существам. Здесь мы посвящаем "заслугу" от высокой coherence.
 *
 * @param field Поле бодхичитты
 * @param self_coherence Собственная coherence
 * @param collective Collective graph (для вычисления среднего)
 * @return Усиление поля от посвящения (0..1)
 */
float bodhicitta_dedicate_merit(BodhicittaField *field,
                                 float self_coherence,
                                 RGraph *collective);

/**
 * Развитие равностности (upeksha)
 *
 * Равностность - это не безразличие, а равное отношение ко всем существам
 * без предпочтения "своих" vs "чужих".
 *
 * @param field Поле бодхичитты
 * @param collective Collective graph
 */
void bodhicitta_cultivate_equanimity(BodhicittaField *field,
                                     RGraph *collective);

/**
 * Получение текущей силы поля бодхичитты
 *
 * @param field Поле бодхичитты
 * @return Сила поля (0..1)
 */
float bodhicitta_get_field_strength(BodhicittaField *field);

/**
 * Логирование состояния бодхичитты
 *
 * @param field Поле бодхичитты
 * @param cycle Номер цикла
 */
void bodhicitta_log(BodhicittaField *field, uint64_t cycle);

#ifdef __cplusplus
}
#endif

#endif // BODHICITTA_H
