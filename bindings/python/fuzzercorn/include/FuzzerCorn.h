#ifndef FUZZER_CORN_H
#define FUZZER_CORN_H

#include <stdint.h>
#include <stdlib.h>

#include "unicorn/unicorn.h"

#if defined(_WIN32)
#define FUZZER_INTERFACE_VISIBILITY __declspec(dllexport)
#else
#define FUZZER_INTERFACE_VISIBILITY __attribute__((visibility("default")))
#endif

#define FUZZERCORN_MIN_UC_VERSION 0x02000005

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef enum FuzzerCornError {
    FUZZERCORN_ERR_OK = 0,
    FUZZERCORN_ERR_CALLED_TWICE,
    FUZZERCORN_ERR_MEM,
    FUZZERCORN_ERR_ARG,
    FUZZERCORN_ERR_UC_VER,
    FUZZERCORN_ERR_UC_ERR,
} FuzzerCornError;

typedef int (*FuzzerCornInitialize)(uc_engine *Uc, int *Argc, char ***Argv, void *UserData);

typedef bool (*FuzzerCornPlaceInputCallback)(uc_engine *Uc, const uint8_t *Data,
                                  size_t Size, void *UserData);

typedef bool (*FuzzerCornValidateCallback)(uc_engine *Uc, uc_err UcErr,
                                           const uint8_t *Data, size_t Size,
                                           void *UserData);

typedef size_t (*FuzzerCornMutatorCallback)(uc_engine *Uc, uint8_t *Data,
                                            size_t Size, size_t MaxSize,
                                            unsigned int Seed, void *UserData);

typedef size_t (*FuzzerCornCrossOverCallback)(uc_engine *Uc,
    const uint8_t *Data1, size_t Size1, const uint8_t *Data2, size_t Size2,
    uint8_t *Out, size_t MaxOutSize, unsigned int Seed, void *UserData);

FUZZER_INTERFACE_VISIBILITY FuzzerCornError
FuzzerCornFuzz(uc_engine *Uc, int *Argc, char ***Argv, 
               uint64_t *Exits, size_t ExitCount,
               FuzzerCornPlaceInputCallback Input,
               FuzzerCornInitialize Init,
               FuzzerCornValidateCallback Validate,
               FuzzerCornMutatorCallback Mutate,
               FuzzerCornCrossOverCallback Cross,
               void *UserData, bool AlwaysValidate,
               int *ExitCode, size_t CounterCount);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif