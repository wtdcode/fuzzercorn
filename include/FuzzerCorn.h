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

// Called once per process to initialize everything before fuzzing.
typedef int (*FuzzerCornInitialize)(uc_engine *Uc, int *Argc, char ***Argv,
                                    void *UserData);

// Called everytime before starting Unicorn.
typedef bool (*FuzzerCornPlaceInputCallback)(uc_engine *Uc, const uint8_t *Data,
                                             size_t Size, void *UserData);

// Validate whether a Unicorn error is a crash.
typedef bool (*FuzzerCornValidateCallback)(uc_engine *Uc, uc_err UcErr,
                                           const uint8_t *Data, size_t Size,
                                           void *UserData);

// Used to mutate input **in-place**.
typedef size_t (*FuzzerCornMutatorCallback)(uc_engine *Uc, uint8_t *Data,
                                            size_t Size, size_t MaxSize,
                                            unsigned int Seed, void *UserData);

// Usede to cross over input and write to Out.
typedef size_t (*FuzzerCornCrossOverCallback)(
    uc_engine *Uc, const uint8_t *Data1, size_t Size1, const uint8_t *Data2,
    size_t Size2, uint8_t *Out, size_t MaxOutSize, unsigned int Seed,
    void *UserData);

// Specify a range of code to instrument.
typedef struct {
  uint64_t begin;
  uint64_t end;
} InstrumentRange;

// The main entry point of the fuzzer.
// Note this function should be called only **ONCE** per process.
//
// @Uc: The Unicorn instance.
// @Argc: A pointer to argc.
// @Argv: A pointer to argv array.
// @Input: The Callback to place input. If it returns false, the unicorn won't
// be
//         started. Users also may use this to implement custom fuzzing logic,
//         for example starting fuzzer in the callback. Always return 0.
// @Init: The Callback to initialize before fuzzing. Only called once and should
// always
//        return 0 whatever happens.
// @Validate: Validate if an error is a crash. Only get called if unicorn
// returns an
//            error by default. If @AlwaysValidate is set to true, it would be
//            called everytime the emulation is done.
// @Mutate: Mutate the input **in-place**. Note that setting this pointer to
// non-null but
//          don't provide any implementation may have side-effects. If you would
//          not like to mutate, set it to nullptr.
// @Cross: Combines two input to new output.
// @Ranges: Specify the ranges the fuzzer is interested. Only the code within
// the ranges
//          would be intrumented. Setting this to nullptr will get all code
//          instrumented.
// @UserData: User provided data and will be passed to callbacls.
// @AlwaysValidate: see @Validate.
// @ExitCode: The program (fuzzer) exit code. Should be returned as the exit
// code of the
//            outer program.
// @CounterCount: The coverage map size. Reduce this can speedup the fuzzing but
// may cause
//                more conflicts.
FUZZER_INTERFACE_VISIBILITY FuzzerCornError FuzzerCornFuzz(
    uc_engine *Uc, int *Argc, char ***Argv, uint64_t *Exits, size_t ExitCount,
    FuzzerCornPlaceInputCallback Input, FuzzerCornInitialize Init,
    FuzzerCornValidateCallback Validate, FuzzerCornMutatorCallback Mutate,
    FuzzerCornCrossOverCallback Cross, InstrumentRange *Ranges,
    size_t RangeCount, void *UserData, bool AlwaysValidate, int *ExitCode,
    size_t CounterCount);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif