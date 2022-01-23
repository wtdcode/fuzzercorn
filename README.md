# Fuzzercorn

libfuzzer bindings for Unicorn.

## API

```C
// The main entry point of the fuzzer.
// Note this function should be called only **ONCE** per process.
//
// @Uc: The Unicorn instance.
// @Argc: A pointer to argc.
// @Argv: A pointer to argv array.
// @Input: The Callback to place input. If it returns false, the unicorn won't be
//         started. Users also may use this to implement custom fuzzing logic, for
//         example starting fuzzer in the callback. Always return 0.
// @Init: The Callback to initialize before fuzzing. Only called once and should always
//        return 0 whatever happens.
// @Validate: Validate if an error is a crash. Only get called if unicorn returns an
//            error by default. If @AlwaysValidate is set to true, it would be called
//            everytime the emulation is done.
// @Mutate: Mutate the input **in-place**. Note that setting this pointer to non-null but
//          don't provide any implementation may have side-effects. If you would not like to
//          mutate, set it to nullptr.
// @Cross: Combines two input to new output.
// @Ranges: Specify the ranges the fuzzer is interested. Only the code within the ranges
//          would be intrumented. Setting this to nullptr will get all code instrumented.
// @UserData: User provided data and will be passed to callbacls.
// @AlwaysValidate: see @Validate.
// @ExitCode: The program (fuzzer) exit code. Should be returned as the exit code of the
//            outer program.
// @CounterCount: The coverage map size. Reduce this can speedup the fuzzing but may cause
//                more conflicts.
FUZZER_INTERFACE_VISIBILITY FuzzerCornError FuzzerCornFuzz(
    uc_engine *Uc, int *Argc, char ***Argv, FuzzerCornPlaceInputCallback Input,
    FuzzerCornInitialize Init, FuzzerCornValidateCallback Validate,
    FuzzerCornMutatorCallback Mutate, FuzzerCornCrossOverCallback Cross,
    InstrumentRange *Ranges, size_t RangeCount, void *UserData,
    bool AlwaysValidate, int *ExitCode, size_t CounterCount);
```