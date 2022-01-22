#include "FuzzerCorn.h"
#include "LibFuzzer.h"

#include <vector>

#ifndef likely
#ifndef _MSC_VER
#if __GNUC__ < 3
#define __builtin_expect(x, n) (x)
#endif

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define likely(x) (x)
#define unlikely(x) (x)
#endif
#endif

class FuzzerCorn {

public:
  static FuzzerCorn &Get() { return FuzzerCorn::fuzzer; }

  bool IsFuzzing() { return this->IsFuzzing_; }

  FuzzerCornError
  Fuzz(uc_engine *Uc, uint64_t *Exits, size_t ExitCount,
       FuzzerCornInitialize Init, FuzzerCornPlaceInputCallback Input,
       FuzzerCornValidateCallback Validate, FuzzerCornMutatorCallback Mutate,
       FuzzerCornCrossOverCallback Cross, void *UserData, bool AlwaysValidate,
       int *Argc, char ***Argv, int *ExitCode, size_t CounterCount) {
    InitializeCallback InitCb = Init ? InitializeCallbackWrapper_ : nullptr;
    CustomMutatorCallback MutCb = Mutate ? MutateCallbackWrapper_ : nullptr;
    CustomCrossOverCallback CrossCb =
        Cross ? CrossOverCallbackWrapper_ : nullptr;

    this->IsFuzzing_ = true;
    this->AlwaysValidate_ = AlwaysValidate;
    this->Init_ = Init;
    this->Input_ = Input;
    this->Validate_ = Validate;
    this->Mutate_ = Mutate;
    this->Cross_ = Cross;
    this->CounterCount = CounterCount;
    this->Counters.resize(CounterCount);
    this->Uc_ = Uc;
    this->PrevLoc_ = 0;

    if (unlikely(this->UcSetup_(Exits, ExitCount) != FUZZERCORN_ERR_OK)) {
      return FUZZERCORN_ERR_UC_ERR;
    }

    *ExitCode = LLVMFuzzerRunDriver(
        Argc, Argv, TestOneInputCallbackWrapper_, InitCb, MutCb, CrossCb,
        (uint8_t *)&this->Counters[0], CounterCount);

    return FUZZERCORN_ERR_OK;
  }

private:
  FuzzerCorn() {}
  ~FuzzerCorn() {}
  FuzzerCorn(const FuzzerCorn &) = delete;
  FuzzerCorn *operator=(const FuzzerCorn &) = delete;

  static int InitializeCallbackWrapper_(int *Argc, char ***Argv) {
    FuzzerCorn &fuzzer = FuzzerCorn::Get();

    return fuzzer.Init_(fuzzer.Uc_, Argc, Argv, fuzzer.UserData_);
  }

  static size_t MutateCallbackWrapper_(uint8_t *Data, size_t Size,
                                       size_t MaxSize, unsigned int Seed) {
    FuzzerCorn &fuzzer = FuzzerCorn::Get();

    return fuzzer.Mutate_(fuzzer.Uc_, Data, Size, MaxSize, Seed,
                          fuzzer.UserData_);
  }

  static size_t CrossOverCallbackWrapper_(const uint8_t *Data1, size_t Size1,
                                          const uint8_t *Data2, size_t Size2,
                                          uint8_t *Out, size_t MaxOutSize,
                                          unsigned int Seed) {
    FuzzerCorn &fuzzer = FuzzerCorn::Get();

    return fuzzer.Cross_(fuzzer.Uc_, Data1, Size1, Data2, Size2, Out,
                         MaxOutSize, Seed, fuzzer.UserData_);
  }

  static int TestOneInputCallbackWrapper_(const uint8_t *Data, size_t Size) {
    FuzzerCorn &fuzzer = FuzzerCorn::Get();
    uint64_t PC;
    uc_err Err;

    if (!(fuzzer.Input_ &&
          fuzzer.Input_(fuzzer.Uc_, Data, Size, fuzzer.UserData_))) {
      return 0;
    }

    PC = fuzzer.GetPc_();

    Err = uc_emu_start(fuzzer.Uc_, PC, 0, 0, 0);

    if (unlikely(Err != UC_ERR_OK) || fuzzer.AlwaysValidate_) {
      if (!fuzzer.Validate_ ||
          (fuzzer.Validate_ &&
           fuzzer.Validate_(fuzzer.Uc_, Err, Data, Size, fuzzer.UserData_))) {
        std::abort();
      }
    }

    return 0;
  }

  static void UcHookBlock_(uc_engine *Uc, uint64_t Address, uint32_t Size,
                           void *UserData) {
    FuzzerCorn *fuzzer = (FuzzerCorn *)UserData;
    uint64_t CurLoc =
        ((Address >> 4) ^ (Address << 8)) & (fuzzer->CounterCount - 7);
    uint8_t *Counters = &fuzzer->Counters[0];

    Counters[CurLoc ^ fuzzer->PrevLoc_]++;
    fuzzer->PrevLoc_ = CurLoc >> 1;
  }

  uint64_t GetPc_() {
    uc_arch Arch;
    uc_mode Mode;
    uint64_t PC = 0;

    uc_ctl_get_arch(this->Uc_, &Arch);
    uc_ctl_get_mode(this->Uc_, &Mode);

    if (Arch == UC_ARCH_X86) {
      if (Mode == UC_MODE_32) {
        uc_reg_read(this->Uc_, UC_X86_REG_EIP, &PC);
      } else if (Mode == UC_MODE_16) {
        uc_reg_read(this->Uc_, UC_X86_REG_IP, &PC);
      } else {
        uc_reg_read(this->Uc_, UC_X86_REG_RIP, &PC);
      }
    } else if (Arch == UC_ARCH_ARM) {
      uint64_t CPSR = 0;
      uc_reg_read(this->Uc_, UC_ARM_REG_PC, &PC);

      // check for thumb mode
      uc_reg_read(this->Uc_, UC_ARM_REG_CPSR, &CPSR);
      if (CPSR & 0x20) {
        // thumb mode, the address should end with 1
        PC |= 1;
      }

    } else if (Arch == UC_ARCH_RISCV) {
      uc_reg_read(this->Uc_, UC_RISCV_REG_PC, &PC);
    } else if (Arch == UC_ARCH_MIPS) {
      uc_reg_read(this->Uc_, UC_MIPS_REG_PC, &PC);
    } else if (Arch == UC_ARCH_PPC) {
      uc_reg_read(this->Uc_, UC_PPC_REG_PC, &PC);
    } else if (Arch == UC_ARCH_SPARC) {
      uc_reg_read(this->Uc_, UC_SPARC_REG_PC, &PC);
    } else if (Arch == UC_ARCH_M68K) {
      uc_reg_read(this->Uc_, UC_M68K_REG_PC, &PC);
    }

    return PC;
  }

  FuzzerCornError UcSetup_(uint64_t *Exits, size_t ExitCount) {
    uc_err Err;
    uint32_t Ver;
    std::vector<uint64_t> V;

    Ver = uc_version(NULL, NULL);

    // We need at least Unicorn 2.0.0rc5
    if (Ver < FUZZERCORN_MIN_UC_VERSION) {
      return FUZZERCORN_ERR_UC_VER;
    }

    // For coverage.
    Err = uc_hook_add(this->Uc_, &this->H1_, UC_HOOK_BLOCK,
                      (void *)UcHookBlock_, (void *)this, 1, 0);
    if (unlikely(Err)) {
      return FUZZERCORN_ERR_UC_ERR;
    }

    // Seems that we don't need to cache TB?
    // In default persistent mode:
    //    The TB will be cached automatically.
    //
    // In the fork mode:
    //    TODO!

    if (ExitCount == 0) {
        return FUZZERCORN_ERR_OK;
    }

    Err = uc_ctl_exits_enable(this->Uc_);
    if (unlikely(Err)) {
      return FUZZERCORN_ERR_UC_ERR;
    }

    // Setup exits.
    V.assign(Exits, Exits + ExitCount);
    Err = uc_ctl_set_exits(this->Uc_, (uint64_t *)&V[0], ExitCount);
    if (unlikely(Err)) {
      return FUZZERCORN_ERR_UC_ERR;
    }

    return FUZZERCORN_ERR_OK;
  }

private:
  static FuzzerCorn fuzzer;

  bool IsFuzzing_;
  bool AlwaysValidate_;
  void *UserData_;
  uc_engine *Uc_;
  FuzzerCornInitialize Init_;
  FuzzerCornPlaceInputCallback Input_;
  FuzzerCornValidateCallback Validate_;
  FuzzerCornMutatorCallback Mutate_;
  FuzzerCornCrossOverCallback Cross_;

  std::vector<uint8_t> Counters;
  size_t CounterCount; // For faster access
  uint64_t PrevLoc_;
  uc_hook H1_;
};

FuzzerCorn FuzzerCorn::fuzzer;

FuzzerCornError FuzzerCornFuzz(
    uc_engine *Uc, int *Argc, char ***Argv, uint64_t *Exits, size_t ExitCount,
    FuzzerCornPlaceInputCallback Input, FuzzerCornInitialize Init, 
    FuzzerCornValidateCallback Validate, FuzzerCornMutatorCallback Mutate,
    FuzzerCornCrossOverCallback Cross, void *UserData, bool AlwaysValidate,
    int *ExitCode, size_t CounterCount) {
  FuzzerCorn &fuzzer = FuzzerCorn::Get();

  if (unlikely(fuzzer.IsFuzzing())) {
    *ExitCode = 0;
    return FUZZERCORN_ERR_CALLED_TWICE;
  }

  if (unlikely(!Uc)) {
    *ExitCode = 0;
    return FUZZERCORN_ERR_ARG;
  }

  if (unlikely(!Validate)) {
    *ExitCode = 0;
    return FUZZERCORN_ERR_ARG;
  }

  if (unlikely(AlwaysValidate && !Validate)) {
    *ExitCode = 0;
    return FUZZERCORN_ERR_ARG;
  }

  if (CounterCount & (CounterCount - 1)) {
    *ExitCode = 0;
    return FUZZERCORN_ERR_ARG;
  }

  return fuzzer.Fuzz(Uc, Exits, ExitCount, Init, Input, Validate, Mutate, Cross,
                     UserData, AlwaysValidate, Argc, Argv, ExitCode,
                     CounterCount);
}