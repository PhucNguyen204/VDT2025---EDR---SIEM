#ifndef SIGMA_ENGINE_H
#define SIGMA_ENGINE_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t* matched_rules_ptr;
    size_t matched_rules_len;
    size_t nodes_evaluated;
    size_t primitive_evaluations;
    int error_code;
} CEngineResult;

// Function declarations
void* sigma_engine_create(char** rules_ptr, size_t rules_len);
CEngineResult sigma_engine_evaluate(void* engine_ptr, char* json_event);
void sigma_engine_free_result(size_t* matched_rules_ptr, size_t matched_rules_len);
void sigma_engine_destroy(void* engine_ptr);
int sigma_engine_stats(void* engine_ptr, size_t* rule_count, size_t* node_count, size_t* primitive_count);

#endif // SIGMA_ENGINE_H
