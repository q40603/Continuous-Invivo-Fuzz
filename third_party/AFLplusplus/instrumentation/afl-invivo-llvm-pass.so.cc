/*
   american fuzzy lop++ - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com>,
              Adrian Herrera <adrian.herrera@anu.edu.au>,
              Michal Zalewski

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   NGRAM previous location coverage comes from Adrian Herrera.

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2022 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.

 */

#define AFL_LLVM_PASS

#include "config.h"
#include "debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <list>
#include <string>
#include <fstream>
#include <sys/time.h>

#include "llvm/Config/llvm-config.h"

#include "llvm/Pass.h"


// new pass manager
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/PassManager.h"


#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/MathExtras.h"



#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/CFG.h"



#include "llvm/IR/IRBuilder.h"

#include "afl-llvm-common.h"
#include "llvm-alternative-coverage.h"


#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include <iostream>

using namespace llvm;
using namespace std;

namespace {

/* use new pass manager */
class AFLCoverage : public PassInfoMixin<AFLCoverage> {

    public:
    AFLCoverage() {

        initInstrumentList();

    }
/* use new pass manager */
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);


    protected:
        uint32_t    ngram_size = 0;
        uint32_t    ctx_k = 0;
        uint32_t    map_size = MAP_SIZE;
        uint32_t    function_minimum_size = 1;
        const char *ctx_str = NULL, *caller_str = NULL, *skip_nozero = NULL;
        const char *use_threadsafe_counters = nullptr;

};

}  // namespace

#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {LLVM_PLUGIN_API_VERSION, "AFLCoverage", "v0.1",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {

  #if 1
    #if LLVM_VERSION_MAJOR <= 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
    #endif
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {

                  MPM.addPass(AFLCoverage());

                });

  /* TODO LTO registration */
  #else
            using PipelineElement = typename PassBuilder::PipelineElement;
            PB.registerPipelineParsingCallback([](StringRef          Name,
                                                  ModulePassManager &MPM,
                                                  ArrayRef<PipelineElement>) {

              if (Name == "AFLCoverage") {

                MPM.addPass(AFLCoverage());
                return true;

              } else {

                return false;

              }

            });

  #endif

          }};

}

#else

char AFLCoverage::ID = 0;
#endif

/* needed up to 3.9.0 */
#if LLVM_VERSION_MAJOR == 3 && \
    (LLVM_VERSION_MINOR < 9 || \
     (LLVM_VERSION_MINOR == 9 && LLVM_VERSION_PATCH < 1))
uint64_t PowerOf2Ceil(unsigned in) {

  uint64_t in64 = in - 1;
  in64 |= (in64 >> 1);
  in64 |= (in64 >> 2);
  in64 |= (in64 >> 4);
  in64 |= (in64 >> 8);
  in64 |= (in64 >> 16);
  in64 |= (in64 >> 32);
  return in64 + 1;

}

#endif








/* #if LLVM_VERSION_STRING >= "4.0.1" */
#if LLVM_VERSION_MAJOR >= 5 || \
    (LLVM_VERSION_MAJOR == 4 && LLVM_VERSION_PATCH >= 1)
  #define AFL_HAVE_VECTOR_INTRINSICS 1
#endif

#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
PreservedAnalyses AFLCoverage::run(Module &M, ModuleAnalysisManager &MAM) {

#else
bool AFLCoverage::runOnModule(Module &M) {

#endif

  LLVMContext &C = M.getContext();

  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
#ifdef AFL_HAVE_VECTOR_INTRINSICS
  IntegerType *IntLocTy =
      IntegerType::getIntNTy(C, sizeof(PREV_LOC_T) * CHAR_BIT);
#endif
  struct timeval  tv;
  struct timezone tz;
  u32             rand_seed;
  unsigned int    cur_loc = 0;

#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
  auto PA = PreservedAnalyses::all();
#endif

  /* Setup random() so we get Actually Random(TM) outputs from AFL_R() */
  gettimeofday(&tv, &tz);
  rand_seed = tv.tv_sec ^ tv.tv_usec ^ getpid();
  AFL_SR(rand_seed);

  /* Show a banner */

  setvbuf(stdout, NULL, _IONBF, 0);

  if (getenv("AFL_DEBUG")) debug = 1;

  if ((isatty(2) && !getenv("AFL_QUIET")) || getenv("AFL_DEBUG") != NULL) {

    SAYF(cCYA "afl-invivo-llvm-pass" VERSION cRST
              " by <lszekeres@google.com> and <adrian.herrera@anu.edu.au> and <quentin.cs09@nycu.edu.tw>\n");

  } else

    be_quiet = 1;

  /*
    char *ptr;
    if ((ptr = getenv("AFL_MAP_SIZE")) || (ptr = getenv("AFL_MAPSIZE"))) {

      map_size = atoi(ptr);
      if (map_size < 8 || map_size > (1 << 29))
        FATAL("illegal AFL_MAP_SIZE %u, must be between 2^3 and 2^30",
    map_size); if (map_size % 8) map_size = (((map_size >> 3) + 1) << 3);

    }

  */

  /* Decide instrumentation ratio */

  char *       inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

  }

#if LLVM_VERSION_MAJOR < 9
  char *neverZero_counters_str = getenv("AFL_LLVM_NOT_ZERO");
#endif
  skip_nozero = getenv("AFL_LLVM_SKIP_NEVERZERO");
  use_threadsafe_counters = getenv("AFL_LLVM_THREADSAFE_INST");

  if ((isatty(2) && !getenv("AFL_QUIET")) || !!getenv("AFL_DEBUG")) {

    if (use_threadsafe_counters) {

      // disabled unless there is support for other modules as well
      // (increases documentation complexity)
      /*      if (!getenv("AFL_LLVM_NOT_ZERO")) { */

      skip_nozero = "1";
      SAYF(cCYA "afl-invivo-llvm-pass" VERSION cRST " using thread safe counters\n");

      /*

            } else {

              SAYF(cCYA "afl-invivo-llvm-pass" VERSION cRST
                        " using thread safe not-zero-counters\n");

            }

      */

    } else {

      SAYF(cCYA "afl-invivo-llvm-pass" VERSION cRST
                " using non-thread safe instrumentation\n");

    }

  }

  unsigned PrevLocSize = 0;
  unsigned PrevCallerSize = 0;
  unsigned exec_ngram_size = 64;
  unsigned HistSize = exec_ngram_size -1;

  VectorType *ExecTy = NULL;
  ExecTy = VectorType::get(IntLocTy, exec_ngram_size, false );


  char *ngram_size_str = getenv("AFL_LLVM_NGRAM_SIZE");
  if (!ngram_size_str) ngram_size_str = getenv("AFL_NGRAM_SIZE");
  char *ctx_k_str = getenv("AFL_LLVM_CTX_K");
  if (!ctx_k_str) ctx_k_str = getenv("AFL_CTX_K");
  ctx_str = getenv("AFL_LLVM_CTX");
  caller_str = getenv("AFL_LLVM_CALLER");

  bool instrument_ctx = ctx_str || caller_str;

#ifdef AFL_HAVE_VECTOR_INTRINSICS
  /* Decide previous location vector size (must be a power of two) */
  VectorType *PrevLocTy = NULL;

  if (ngram_size_str)
    if (sscanf(ngram_size_str, "%u", &ngram_size) != 1 || ngram_size < 2 ||
        ngram_size > NGRAM_SIZE_MAX)
      FATAL(
          "Bad value of AFL_NGRAM_SIZE (must be between 2 and NGRAM_SIZE_MAX "
          "(%u))",
          NGRAM_SIZE_MAX);

  if (ngram_size == 1) ngram_size = 0;
  if (ngram_size)
    PrevLocSize = ngram_size - 1;
  else
    PrevLocSize = 1;

  /* Decide K-ctx vector size (must be a power of two) */
  VectorType *PrevCallerTy = NULL;

  if (ctx_k_str)
    if (sscanf(ctx_k_str, "%u", &ctx_k) != 1 || ctx_k < 1 || ctx_k > CTX_MAX_K)
      FATAL("Bad value of AFL_CTX_K (must be between 1 and CTX_MAX_K (%u))",
            CTX_MAX_K);

  if (ctx_k == 1) {

    ctx_k = 0;
    instrument_ctx = true;
    caller_str = ctx_k_str;  // Enable CALLER instead

  }

  if (ctx_k) {

    PrevCallerSize = ctx_k;
    instrument_ctx = true;

  }

#else
  if (ngram_size_str)
  #ifndef LLVM_VERSION_PATCH
    FATAL(
        "Sorry, NGRAM branch coverage is not supported with llvm version "
        "%d.%d.%d!",
        LLVM_VERSION_MAJOR, LLVM_VERSION_MINOR, 0);
  #else
    FATAL(
        "Sorry, NGRAM branch coverage is not supported with llvm version "
        "%d.%d.%d!",
        LLVM_VERSION_MAJOR, LLVM_VERSION_MINOR, LLVM_VERSION_PATCH);
  #endif
  if (ctx_k_str)
  #ifndef LLVM_VERSION_PATCH
    FATAL(
        "Sorry, K-CTX branch coverage is not supported with llvm version "
        "%d.%d.%d!",
        LLVM_VERSION_MAJOR, LLVM_VERSION_MINOR, 0);
  #else
    FATAL(
        "Sorry, K-CTX branch coverage is not supported with llvm version "
        "%d.%d.%d!",
        LLVM_VERSION_MAJOR, LLVM_VERSION_MINOR, LLVM_VERSION_PATCH);
  #endif
  PrevLocSize = 1;
#endif

#ifdef AFL_HAVE_VECTOR_INTRINSICS
  int PrevLocVecSize = PowerOf2Ceil(PrevLocSize);
  if (ngram_size)
    PrevLocTy = VectorType::get(IntLocTy, PrevLocVecSize
  #if LLVM_VERSION_MAJOR >= 12
                                ,
                                false
  #endif
    );
#endif

#ifdef AFL_HAVE_VECTOR_INTRINSICS
  int PrevCallerVecSize = PowerOf2Ceil(PrevCallerSize);
  if (ctx_k)
    PrevCallerTy = VectorType::get(IntLocTy, PrevCallerVecSize
  #if LLVM_VERSION_MAJOR >= 12
                                   ,
                                   false
  #endif
    );
#endif
  // Constant *const_array = ConstantDataArray::getString(M.getContext(), "redis");
  // //ArrayType* ArrayTy_0 = ArrayType::get(PointerType::get(Int8Ty, 0), 40);
  //   GlobalVariable* program_name = new GlobalVariable(
  //     /*Module=*/M, 
  //   /*Type=*/const_array->getType(),
  //   /*isConstant=*/true,
  //   /*Linkage=*/GlobalValue::ExternalLinkage,
  //   /*Initializer=*/const_array,
  //   /*Name=*/"program_name");
    //program_name->setAlignment(MaybeAlign(8));
    
    // program_name->setInitializer(const_array_4);
  /* Get globals for the SHM region and the previous location. Note that
     __afl_prev_loc is thread-local. */

  GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");
  GlobalVariable *AFLPrevLoc;
  GlobalVariable *AFLPrevCaller;
  GlobalVariable *AFLContext = NULL;
  GlobalVariable *Invivo_edge;
  // GlobalVariable *Invivo_exec_path;
  // GlobalVariable *Invivo_exec_path_Idx;


  if (ctx_str || caller_str)
#if defined(__ANDROID__) || defined(__HAIKU__)
    AFLContext = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_ctx");
#else
    AFLContext = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_ctx", 0,
        GlobalVariable::GeneralDynamicTLSModel, 0, false);
#endif

#ifdef AFL_HAVE_VECTOR_INTRINSICS
  if (ngram_size)
  #if defined(__ANDROID__) || defined(__HAIKU__)
    AFLPrevLoc = new GlobalVariable(
        M, PrevLocTy, /* isConstant */ false, GlobalValue::ExternalLinkage,
        /* Initializer */ nullptr, "__afl_prev_loc");
  #else
    AFLPrevLoc = new GlobalVariable(
        M, PrevLocTy, /* isConstant */ false, GlobalValue::ExternalLinkage,
        /* Initializer */ nullptr, "__afl_prev_loc",
        /* InsertBefore */ nullptr, GlobalVariable::GeneralDynamicTLSModel,
        /* AddressSpace */ 0, /* IsExternallyInitialized */ false);
  #endif
  else
#endif
#if defined(__ANDROID__) || defined(__HAIKU__)
    AFLPrevLoc = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc");
#else
  AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc", 0,
      GlobalVariable::GeneralDynamicTLSModel, 0, false);
#endif

Invivo_edge = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "_invivo_edge", 0 , GlobalVariable::GeneralDynamicTLSModel);

// Invivo_exec_path = new GlobalVariable(
//         M, ExecTy, /* isConstant */ false, GlobalValue::ExternalLinkage,
//         /* Initializer */ nullptr, "Invivo_exec_path",
//         /* InsertBefore */ nullptr, GlobalVariable::GeneralDynamicTLSModel,
//         /* AddressSpace */ 0, /* IsExternallyInitialized */ false);
        
// Invivo_exec_path_Idx = new GlobalVariable(
//       M, Int32Ty, /* isConstant */ false, GlobalValue::ExternalLinkage,
//       /* Initializer */ nullptr, "Invivo_exec_path_idx",
//       /* InsertBefore */ nullptr, GlobalVariable::GeneralDynamicTLSModel,
//       /* AddressSpace */ 0, /* IsExternallyInitialized */ false); 



#ifdef AFL_HAVE_VECTOR_INTRINSICS
  if (ctx_k)
  #if defined(__ANDROID__) || defined(__HAIKU__)
    AFLPrevCaller = new GlobalVariable(
        M, PrevCallerTy, /* isConstant */ false, GlobalValue::ExternalLinkage,
        /* Initializer */ nullptr, "__afl_prev_caller");
  #else
    AFLPrevCaller = new GlobalVariable(
        M, PrevCallerTy, /* isConstant */ false, GlobalValue::ExternalLinkage,
        /* Initializer */ nullptr, "__afl_prev_caller",
        /* InsertBefore */ nullptr, GlobalVariable::GeneralDynamicTLSModel,
        /* AddressSpace */ 0, /* IsExternallyInitialized */ false);
  #endif
  else
#endif
#if defined(__ANDROID__) || defined(__HAIKU__)
    AFLPrevCaller =
        new GlobalVariable(M, Int32Ty, false, GlobalValue::ExternalLinkage, 0,
                           "__afl_prev_caller");
#else
  AFLPrevCaller = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_caller",
      0, GlobalVariable::GeneralDynamicTLSModel, 0, false);
#endif





#ifdef AFL_HAVE_VECTOR_INTRINSICS
  /* Create the vector shuffle mask for updating the previous block history.
     Note that the first element of the vector will store cur_loc, so just set
     it to undef to allow the optimizer to do its thing. */

  SmallVector<Constant *, 32> PrevLocShuffle = {UndefValue::get(Int32Ty)};

  for (unsigned I = 0; I < PrevLocSize - 1; ++I)
    PrevLocShuffle.push_back(ConstantInt::get(Int32Ty, I));

  for (int I = PrevLocSize; I < PrevLocVecSize; ++I)
    PrevLocShuffle.push_back(ConstantInt::get(Int32Ty, PrevLocSize));

  Constant *PrevLocShuffleMask = ConstantVector::get(PrevLocShuffle);

  Constant *                  PrevCallerShuffleMask = NULL;
  SmallVector<Constant *, 32> PrevCallerShuffle = {UndefValue::get(Int32Ty)};

  if (ctx_k) {

    for (unsigned I = 0; I < PrevCallerSize - 1; ++I)
      PrevCallerShuffle.push_back(ConstantInt::get(Int32Ty, I));

    for (int I = PrevCallerSize; I < PrevCallerVecSize; ++I)
      PrevCallerShuffle.push_back(ConstantInt::get(Int32Ty, PrevCallerSize));

    PrevCallerShuffleMask = ConstantVector::get(PrevCallerShuffle);

  }

#endif




  // Invivo hook Network I/O
  string hook_read_function = string("BSA_hook_read");
  string hook_recv_function = string("BSA_hook_recv");
  string hook_recvmsg_function = string("BSA_hook_recvmsg");
  string hook_recvfrom_function = string("BSA_hook_recvfrom");


  // Invivo pthread_create handler
  string pthread_create_function = string("pthread_create");

  // ready to hook function
  string read_function = string("read");
  string write_function = string("write");
  string scanf_function = string("__isoc99_scanf");
  string recv_function = string("recv");
  string recvmsg_function = string("recvmsg");
  string recvfrom_function = string("recvfrom");
  string send_function = string("send");
  string sendto_function = string("sendto");
  string sendmsg_function = string("sendmsg");
  string writev_function = string("writev");
  string close_function = string("close");
  string accept_function = string("accept");
  string accept4_function = string("accept4");
  string free_function = string("free");
  string calloc_function = string("calloc");
  string malloc_function = string("malloc");
  string realloc_function = string("realloc");
  string reallocarray_function = string("reallocarray");
  string memcpy_function = string("memcpy");
  string memmove_function = string("memmove");
  string memchr_function = string("memchr");
  string memrchr_function = string("memrchr");
  string rawmemchr_function = string("rawmemchr");
  string memset_function = string("memset");
  string memcmp_function = string("memcmp");
  string strcpy_function = string("strcpy");
  string strncpy_function = string("strncpy");
  string strlen_function = string("strlen");
  string strcat_function = string("strcat");
  string strncat_function = string("strncat");
  string strncmp_function = string("strncmp");
  string strcmp_function = string("strcmp");
  string strcasecmp_function = string("strcasecmp");
  string strncasecmp_function = string("strncasecmp");

  string strspn_function = string("strspn");
  string strcspn_function = string("strcspn");
  string strcoll_function = string("strcoll");

  string strxfrm_function = string("strxfrm");
  string strstr_function = string("strstr");
  string strcasestr_function = string("strcasestr");
  string strchr_function = string("strchr");
  string strrchr_function = string("strrchr");

  string strpbrk_function = string("strpbrk");
  string strtok_function = string("strtok");
  string strtok_r_function = string("strtok_r");

  auto callee_checkpoint = M.getOrInsertFunction(
    "BSA_checkpoint",
    Type::getVoidTy(M.getContext()), 
    Type::getInt32Ty(M.getContext()),
    Type::getInt8PtrTy(M.getContext())
    ).getCallee();

  if (getenv("NOFORK")){
      callee_checkpoint = M.getOrInsertFunction(
        "BSA_checkpoint_nofork",
        Type::getVoidTy(M.getContext()), 
        Type::getInt32Ty(M.getContext()),
        Type::getInt8PtrTy(M.getContext())
        ).getCallee();
  }

  auto callee_incr_sense = M.getOrInsertFunction(
    "incr_sensitive_count",
    Type::getVoidTy(M.getContext())
    ).getCallee();

  // auto callee_incr_mem_op = M.getOrInsertFunction(
  //   "incr_mem_oper",
  //   Type::getVoidTy(M.getContext())
  //   ).getCallee();

  // auto callee_incr_str = M.getOrInsertFunction(
  //   "incr_str_oper",
  //   Type::getVoidTy(M.getContext())
  //   ).getCallee();

  auto callee_append_bbid = M.getOrInsertFunction(
        "append_bbid_to_exec",
        Type::getVoidTy(M.getContext()), 
        Type::getInt32Ty(M.getContext())
        ).getCallee();

  auto callee_check_exit = M.getOrInsertFunction(
        "BSA_check_exit",
        Type::getVoidTy(M.getContext())
        ).getCallee();
  // auto callee_extract_dict = M.getOrInsertFunction(
  //   "BSA_extract_dict",
  //   Type::getVoidTy(M.getContext()),
  //   Type::getInt8PtrTy(M.getContext()),
  //   Type::getInt8PtrTy(M.getContext())
  //   ).getCallee();
  
  //Function *open = cast<Function>(callee_checkpoint);
  Function *Fun = cast<Function>(callee_checkpoint);
  Function *Fun_trace_sense = cast<Function>(callee_incr_sense);
  // Function *Fun_trace_mem_op = cast<Function>(callee_incr_mem_op);
  // Function *Fun_trace_str_op = cast<Function>(callee_incr_str);
  Function *Fun_append_bbid = cast<Function>(callee_append_bbid);
  Function *Fun_check_exit = cast<Function>(callee_check_exit);
  //Function *Fun_extract_dict = cast<Function>(callee_extract_dict);
  //auto Fun = dyn_cast<Constant>(callee_checkpoint.getCallee());

  Type* char_arr_type = Type::getInt8PtrTy(M.getContext());

  // other constants we need
  ConstantInt *One = ConstantInt::get(Int8Ty, 1);

  Value *   PrevCtx = NULL;     // CTX sensitive coverage
  LoadInst *PrevCaller = NULL;  // K-CTX coverage


  int hook_mode= 0;
  if(getenv("HOOK")){
    hook_mode = 1;
  }
  int fuzz_entry_mode = 0;
  if(getenv("ENTRY")){
    fuzz_entry_mode = 1;
  }

  int sec_fun_mode = 0;
  if(getenv("SEC")){
    sec_fun_mode = 1;
  }

  int exec_trace_mode = 0;
  if(getenv("EXEC")){
    exec_trace_mode = 1;
  }

  int extract_dict_mode = 0;
  if(getenv("DICT")){
    extract_dict_mode = 1;
  }    

  if(getenv("ALL")){
    hook_mode = 1;
    fuzz_entry_mode = 1;
    sec_fun_mode = 1;
    exec_trace_mode = 1;
    //extract_dict_mode = 1;
  }
  /* Instrument all the things! */

  int inst_blocks = 0;
  scanForDangerousFunctions(&M);
  std::string func_name;
  for (auto &F : M) {

    int has_calls = 0;
    if(F.isIntrinsic()) continue;
    if(F.isDeclaration()){
        func_name = F.getName().str();
        // OKF("f = %s\n", func_name.c_str());
        //if (func_name == pthread_create_function) F.setName("BSA_pthread_create");
        if(hook_mode){
          if (func_name == read_function ) F.setName("BSA_hook_read"); 
          else if(func_name == write_function) F.setName("BSA_hook_write"); 
          else if(func_name == writev_function) F.setName("BSA_hook_writev");
          else if(func_name == recvmsg_function) F.setName("BSA_hook_recvmsg");
          else if(func_name == recvfrom_function) F.setName("BSA_hook_recvfrom");
          else if(func_name == recv_function)  F.setName("BSA_hook_recv");
          else if(func_name == send_function)  F.setName("BSA_hook_send");
          else if(func_name == sendto_function)  F.setName("BSA_hook_sendto");
          else if(func_name == sendmsg_function)  F.setName("BSA_hook_sendmsg");
          else if(func_name == close_function) F.setName("BSA_hook_close");
          else if(func_name == accept_function) F.setName("BSA_hook_accept");
          else if(func_name == accept4_function) F.setName("BSA_hook_accept4");
        }

        // else if(func_name == free_function) F.setName("BSA_hook_free");
        // else if(func_name == calloc_function) F.setName("BSA_hook_calloc");
        // else if(func_name == malloc_function) F.setName("BSA_hook_malloc");
        // else if(func_name == realloc_function) F.setName("BSA_hook_realloc");
        // else if(func_name == reallocarray_function) F.setName("BSA_hook_reallocarray");
        // else if(func_name == memcpy_function) F.setName("BSA_hook_memcpy");
        // else if(func_name == memmove_function) F.setName("BSA_hook_memmove");
        // else if(func_name == memchr_function) F.setName("BSA_hook_memchr");
        // else if(func_name == memrchr_function) F.setName("BSA_hook_memrchr");
        // else if(func_name == rawmemchr_function) F.setName("BSA_hook_rawmemchr");
        // else if(func_name == memset_function) F.setName("BSA_hook_memset");
        // else if(func_name == memcmp_function) F.setName("BSA_hook_memcmp");
        // else if(func_name == strcpy_function) F.setName("BSA_hook_strcpy");
        // else if(func_name == strncpy_function) F.setName("BSA_hook_strncpy");
        // else if(func_name == strlen_function) F.setName("BSA_hook_strlen");
        // else if(func_name == strcat_function) F.setName("BSA_hook_strcat");
        // else if(func_name == strncat_function) F.setName("BSA_hook_strncat");
        if(extract_dict_mode){
          if(func_name == strncmp_function) F.setName("BSA_hook_strncmp");
          else if(func_name == strcmp_function) F.setName("BSA_hook_strcmp");
          else if(func_name == strcasecmp_function) F.setName("BSA_hook_strcasecmp");
          else if(func_name == strncasecmp_function) F.setName("BSA_hook_strncasecmp");
          else if(func_name == strspn_function) F.setName("BSA_hook_strspn");
          else if(func_name == strcspn_function) F.setName("BSA_hook_strcspn");
          else if(func_name == strcoll_function) F.setName("BSA_hook_strcoll");
          else if(func_name == strxfrm_function) F.setName("BSA_hook_strxfrm");
          else if(func_name == strstr_function) F.setName("BSA_hook_strstr");
          else if(func_name == strcasestr_function) F.setName("BSA_hook_strcasestr");
          else if(func_name == strpbrk_function) F.setName("BSA_hook_strpbrk");
          else if(func_name == strtok_function) F.setName("BSA_hook_strtok");
          else if(func_name == strtok_r_function) F.setName("BSA_hook_strtok_r");
        }

        // else if(func_name == strchr_function) F.setName("BSA_hook_strchr");
        // else if(func_name == strrchr_function) F.setName("BSA_hook_strrchr");
        // // else{
        //   fprintf(stderr, "bypass FUNCTION: %s (%zu)\n", F.getName().str().c_str(),
        //           F.size());          
        // }
    }

    if (!isInInstrumentList(&F, MNAME)) { continue; }
    //OKF("f = %s\n", func_name.c_str());
    if (F.size() < function_minimum_size) { continue; }




    //invivo IV_checkpoint
    int firstBB = 1;


    std::list<Value *> todo;
    for (auto &BB : F) {

      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<>          IRB(&(*IP));
      //CallInst * call_instr = dyn_cast<CallInst>(IP);
      



      // Context sensitive coverage
      if (instrument_ctx && &BB == &F.getEntryBlock()) {

#ifdef AFL_HAVE_VECTOR_INTRINSICS
        if (ctx_k) {

          PrevCaller = IRB.CreateLoad(
  #if LLVM_VERSION_MAJOR >= 14
              PrevCallerTy,
  #endif
              AFLPrevCaller);
          PrevCaller->setMetadata(M.getMDKindID("nosanitize"),
                                  MDNode::get(C, None));
          PrevCtx =
              IRB.CreateZExt(IRB.CreateXorReduce(PrevCaller), IRB.getInt32Ty());

        } else

#endif
        {

          // load the context ID of the previous function and write to to a
          // local variable on the stack
          LoadInst *PrevCtxLoad = IRB.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
              IRB.getInt32Ty(),
#endif
              AFLContext);
          PrevCtxLoad->setMetadata(M.getMDKindID("nosanitize"),
                                   MDNode::get(C, None));
          PrevCtx = PrevCtxLoad;

        }

        // does the function have calls? and is any of the calls larger than one
        // basic block?
        for (auto &BB_2 : F) {

          if (has_calls) break;
          for (auto &IN : BB_2) {

            CallInst *callInst = nullptr;
            if ((callInst = dyn_cast<CallInst>(&IN))) {

              Function *Callee = callInst->getCalledFunction();
              if (!Callee || Callee->size() < function_minimum_size)
                continue;
              else {

                has_calls = 1;
                break;

              }

            }

          }

        }

        // if yes we store a context ID for this function in the global var
        if (has_calls) {

          Value *NewCtx = ConstantInt::get(Int32Ty, AFL_R(map_size));
#ifdef AFL_HAVE_VECTOR_INTRINSICS
          if (ctx_k) {

            Value *ShuffledPrevCaller = IRB.CreateShuffleVector(
                PrevCaller, UndefValue::get(PrevCallerTy),
                PrevCallerShuffleMask);
            Value *UpdatedPrevCaller = IRB.CreateInsertElement(
                ShuffledPrevCaller, NewCtx, (uint64_t)0);

            StoreInst *Store =
                IRB.CreateStore(UpdatedPrevCaller, AFLPrevCaller);
            Store->setMetadata(M.getMDKindID("nosanitize"),
                               MDNode::get(C, None));

          } else

#endif
          {

            if (ctx_str) NewCtx = IRB.CreateXor(PrevCtx, NewCtx);
            StoreInst *StoreCtx = IRB.CreateStore(NewCtx, AFLContext);
            StoreCtx->setMetadata(M.getMDKindID("nosanitize"),
                                  MDNode::get(C, None));

          }

        }

      }

      if (AFL_R(100) >= inst_ratio) continue;

      /* Make up cur_loc */

      // cur_loc++;
      cur_loc = AFL_R(map_size);


      int has_network_io = 0;
      //for (auto &BB_3 : F) {
        
        // if (has_calls) break;
        for (auto &IN : BB) {

          CallInst *callInst = nullptr;
          if ((callInst = dyn_cast<CallInst>(&IN))) {

            Function *Callee = callInst->getCalledFunction();
            
            if (!Callee)// || Callee->size() < function_minimum_size)
              continue;

        
            else {
              if(Callee->getName().startswith("llvm")) continue;

              std::string call_func_name = Callee->getName().str();
              //OKF(" - call %s", call_func_name.c_str()); 
              if(
                call_func_name == read_function || call_func_name == hook_read_function || 
                call_func_name == recv_function || call_func_name == hook_recv_function ||
                call_func_name == recvmsg_function || call_func_name == hook_recvmsg_function ||
                call_func_name == recvfrom_function || call_func_name == hook_recvfrom_function
              ){
                //OKF("call %s\n", call_func_name.c_str());
                has_network_io = 1;
              }
            }

          }

        }

      //}


      if(fuzz_entry_mode){
        IRB.CreateCall(Fun_check_exit);
        if(has_network_io){
          Value *val[2];
          val[0] = llvm::ConstantInt::get(llvm::Type::getInt32Ty(M.getContext()), cur_loc);
          val[1] = IRB.CreateGlobalStringPtr(F.getName().str().c_str());
          IRB.CreateCall(Fun,val);
          OKF("Inserting IV_Fuzz_Entry to %s (%zu)", F.getName().str().c_str(), F.size());
        }
      }

      

      if(firstBB){
        if(exec_trace_mode){
          Value *vall[1];
          vall[0] = llvm::ConstantInt::get(llvm::Type::getInt32Ty(M.getContext()), cur_loc);
          IRB.CreateCall(Fun_append_bbid,vall);
        }
        if(sec_fun_mode){
          if(strstr(F.getName().str().c_str(), "alloc") || strstr(F.getName().str().c_str(), "free")){
            IRB.CreateCall(Fun_trace_sense);
          }
          if(strstr(F.getName().str().c_str(), "mem")){
            IRB.CreateCall(Fun_trace_sense);
          }
          if(strstr(F.getName().str().c_str(), "str")){
            
            int char_cnt = 0;
            for(auto arg = F.arg_begin(); arg != F.arg_end(); ++arg) {
                if(char_arr_type == (*arg).getType()){
                  char_cnt ++;
                  errs()<<F.getName().str().c_str()<<" "<< (*arg) << "\n";
                }
                  
            }
            if(char_cnt >0){
              IRB.CreateCall(Fun_trace_sense);
            }
          }
        }


        // if(char_cnt == 2 && (strstr(F.getName().str().c_str(), "cmp"))){
        //   auto * voidTy = Type::getVoidTy(M.getContext());
        //   auto * int8PtrTy = Type::getInt8PtrTy(M.getContext());
        //   auto * helperTy = FunctionType::get(voidTy, { int8PtrTy}, false);
        //   auto helper = M.getOrInsertFunction("BSA_extract_dict", helperTy);
        //   std::vector<Value *> call_args = {call_instr->getOperand(1)};

        //   IRBuilder<> builder(call_instr);
        //   builder.CreateCall(helper, call_args);
        //   //errs()<<F.getName().str().c_str()<<" " << call_instr->getOperand(0) << " " << call_instr->getOperand(1)  <<  "\n";
        //   //builder.CreateCall(Fun_extract_dict, {call_instr->getOperand(0), call_instr->getOperand(1)});
        //   //errs<<(&(*IP))->getOperand(0)->getType()<<" "<<(&(*IP))->getOperand(1)->getType()<<"\n";
        // }

        firstBB = 0 ;
      }





/* There is a problem with Ubuntu 18.04 and llvm 6.0 (see issue #63).
   The inline function successors() is not inlined and also not found at runtime
   :-( As I am unable to detect Ubuntu18.04 heree, the next best thing is to
   disable this optional optimization for LLVM 6.0.0 and Linux */
#if !(LLVM_VERSION_MAJOR == 6 && LLVM_VERSION_MINOR == 0) || !defined __linux__
      // only instrument if this basic block is the destination of a previous
      // basic block that has multiple successors
      // this gets rid of ~5-10% of instrumentations that are unnecessary
      // result: a little more speed and less map pollution
      int more_than_one = -1;
      // fprintf(stderr, "BB %u: ", cur_loc);
      for (pred_iterator PI = pred_begin(&BB), E = pred_end(&BB); PI != E;
           ++PI) {

        BasicBlock *Pred = *PI;

        int count = 0;
        if (more_than_one == -1) more_than_one = 0;
        // fprintf(stderr, " %p=>", Pred);

        for (succ_iterator SI = succ_begin(Pred), E = succ_end(Pred); SI != E;
             ++SI) {

          BasicBlock *Succ = *SI;

          // if (count > 0)
          //  fprintf(stderr, "|");
          if (Succ != NULL) count++;
          // fprintf(stderr, "%p", Succ);

        }

        if (count > 1) more_than_one = 1;

      }

      // fprintf(stderr, " == %d\n", more_than_one);
      if (F.size() > 1 && more_than_one != 1) {

        // in CTX mode we have to restore the original context for the caller -
        // she might be calling other functions which need the correct CTX
        if (instrument_ctx && has_calls) {

          Instruction *Inst = BB.getTerminator();
          if (isa<ReturnInst>(Inst) || isa<ResumeInst>(Inst)) {

            IRBuilder<> Post_IRB(Inst);

            StoreInst *RestoreCtx;
  #ifdef AFL_HAVE_VECTOR_INTRINSICS
            if (ctx_k)
              RestoreCtx = IRB.CreateStore(PrevCaller, AFLPrevCaller);
            else
  #endif
              RestoreCtx = Post_IRB.CreateStore(PrevCtx, AFLContext);
            RestoreCtx->setMetadata(M.getMDKindID("nosanitize"),
                                    MDNode::get(C, None));

          }

        }

        continue;

      }

#endif

      ConstantInt *CurLoc;

#ifdef AFL_HAVE_VECTOR_INTRINSICS
      if (ngram_size)
        CurLoc = ConstantInt::get(IntLocTy, cur_loc);
      else
#endif
        CurLoc = ConstantInt::get(Int32Ty, cur_loc);

      /* Load prev_loc */

      LoadInst *PrevLoc;

      if (ngram_size) {

        PrevLoc = IRB.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
            PrevLocTy,
#endif
            AFLPrevLoc);

      } else {

        PrevLoc = IRB.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
            IRB.getInt32Ty(),
#endif
            AFLPrevLoc);

      }

      PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *PrevLocTrans;

#ifdef AFL_HAVE_VECTOR_INTRINSICS
      /* "For efficiency, we propose to hash the tuple as a key into the
         hit_count map as (prev_block_trans << 1) ^ curr_block_trans, where
         prev_block_trans = (block_trans_1 ^ ... ^ block_trans_(n-1)" */

      if (ngram_size)
        PrevLocTrans =
            IRB.CreateZExt(IRB.CreateXorReduce(PrevLoc), IRB.getInt32Ty());
      else
#endif
        PrevLocTrans = PrevLoc;

      if (instrument_ctx)
        PrevLocTrans =
            IRB.CreateZExt(IRB.CreateXor(PrevLocTrans, PrevCtx), Int32Ty);
      else
        PrevLocTrans = IRB.CreateZExt(PrevLocTrans, IRB.getInt32Ty());

      /* Load SHM pointer */

      LoadInst *MapPtr = IRB.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
          PointerType::get(Int8Ty, 0),
#endif
          AFLMapPtr);
      MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      Value *MapPtrIdx;
#ifdef AFL_HAVE_VECTOR_INTRINSICS
      if (ngram_size)
        MapPtrIdx = IRB.CreateGEP(
            Int8Ty, MapPtr,
            IRB.CreateZExt(
                IRB.CreateXor(PrevLocTrans, IRB.CreateZExt(CurLoc, Int32Ty)),
                Int32Ty));
      else
#endif
        MapPtrIdx = IRB.CreateGEP(
#if LLVM_VERSION_MAJOR >= 14
            Int8Ty,
#endif
            MapPtr, IRB.CreateXor(PrevLocTrans, CurLoc));

      /* Update bitmap */

      if (use_threadsafe_counters) {                              /* Atomic */

        IRB.CreateAtomicRMW(llvm::AtomicRMWInst::BinOp::Add, MapPtrIdx, One,
#if LLVM_VERSION_MAJOR >= 13
                            llvm::MaybeAlign(1),
#endif
                            llvm::AtomicOrdering::Monotonic);
        /*

                }

        */

      } else {

        LoadInst *Counter = IRB.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
            IRB.getInt8Ty(),
#endif
            MapPtrIdx);
        Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        Value *Incr = IRB.CreateAdd(Counter, One);

#if LLVM_VERSION_MAJOR >= 9
        if (!skip_nozero) {

#else
        if (neverZero_counters_str != NULL) {

#endif
          /* hexcoder: Realize a counter that skips zero during overflow.
           * Once this counter reaches its maximum value, it next increments to
           * 1
           *
           * Instead of
           * Counter + 1 -> Counter
           * we inject now this
           * Counter + 1 -> {Counter, OverflowFlag}
           * Counter + OverflowFlag -> Counter
           */

          ConstantInt *Zero = ConstantInt::get(Int8Ty, 0);
          auto         cf = IRB.CreateICmpEQ(Incr, Zero);
          auto         carry = IRB.CreateZExt(cf, Int8Ty);
          Incr = IRB.CreateAdd(Incr, carry);

        }

        IRB.CreateStore(Incr, MapPtrIdx)
            ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      }                                                  /* non atomic case */

      /* Update prev_loc history vector (by placing cur_loc at the head of the
         vector and shuffle the other elements back by one) */

      StoreInst *Store;

#ifdef AFL_HAVE_VECTOR_INTRINSICS
      if (ngram_size) {

        Value *ShuffledPrevLoc = IRB.CreateShuffleVector(
            PrevLoc, UndefValue::get(PrevLocTy), PrevLocShuffleMask);
        Value *UpdatedPrevLoc = IRB.CreateInsertElement(
            ShuffledPrevLoc, IRB.CreateLShr(CurLoc, (uint64_t)1), (uint64_t)0);

        Store = IRB.CreateStore(UpdatedPrevLoc, AFLPrevLoc);
        Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      } else

#endif
      {

        Store = IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1),
                                AFLPrevLoc);
        Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      }



      /* Update Invivo_path*/
      LoadInst *InvivoPrevEdge = IRB.CreateLoad(Invivo_edge);
      InvivoPrevEdge->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *PrevAFLedgeCasted = IRB.CreateZExt(InvivoPrevEdge, IRB.getInt32Ty());
      Value *ShiftedPrevAFLedge = IRB.CreateLShr(PrevAFLedgeCasted, 1);
      Value *NewInvivoPrevEdge = IRB.CreateXor(ShiftedPrevAFLedge, ConstantInt::get((llvm::Type*)IntegerType::getInt32Ty(C), cur_loc));
      IRB.CreateStore(NewInvivoPrevEdge, Invivo_edge);


      /* Update exec path*/
      // LoadInst *EdgeHistPtr = IRB.CreateLoad(Invivo_exec_path);
      // EdgeHistPtr->setMetadata(M.getMDKindID("nosanitize"),
      //                          MDNode::get(C, None));

      // LoadInst *EdgeHistIdx = IRB.CreateLoad(Invivo_exec_path_Idx);
      // EdgeHistIdx->setMetadata(M.getMDKindID("nosanitize"),
      //                          MDNode::get(C, None));

      // Value *EdgeHistPtrIdx = IRB.CreateGEP(EdgeHistPtr, EdgeHistIdx);

      // Value *CurEdge = IRB.CreateXor(CurLoc, PrevLoc);

      // // LoadInst *OldestEdge = IRB.CreateLoad(EdgeHistPtrIdx);
      // // OldestEdge->setMetadata(M.getMDKindID("nosanitize"),
      // //                         MDNode::get(C, None));

      // /* Update the accumulation of the previous edges with the current edge */

      // //Value *NewPrevEdgeAcc = IRB.CreateXor(PrevEdgeAccRightShift, CurEdge);

      // /* Remove the oldest edge from the accumulated previous edges. This can be
      //    done by right-shifting the oldest edge by the size of the history
      //    circular buffer (because this is the number of times that the previous
      //    edges have been shifted) and xor-ing the result with the accumulator */

      // // NewPrevEdgeAcc = IRB.CreateXor(
      // //     NewPrevEdgeAcc, IRB.CreateLShr(OldestEdge, (uint64_t)HistSize));

      // // IRB.CreateStore(NewPrevEdgeAcc, AFLPrevEdgeAcc)
      // //     ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      // /* Store the current edge in edge history circular buffer, overwritting
      //    the oldest edge */

      // IRB.CreateStore(CurEdge, EdgeHistPtrIdx)
      //     ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      // /* Update the edge history circulr buffer index. Just use modulo to
      //    ensure that the index wraps around apppropriately */

      // Value *NewEdgeHistIdx = IRB.CreateURem(
      //     IRB.CreateAdd(EdgeHistIdx, ConstantInt::get(Int32Ty, 1)),
      //     ConstantInt::get(Int32Ty, HistSize));

      // IRB.CreateStore(NewEdgeHistIdx, Invivo_exec_path_Idx)
      //     ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      // in CTX mode we have to restore the original context for the caller -
      // she might be calling other functions which need the correct CTX.
      // Currently this is only needed for the Ubuntu clang-6.0 bug
      if (instrument_ctx && has_calls) {

        Instruction *Inst = BB.getTerminator();
        if (isa<ReturnInst>(Inst) || isa<ResumeInst>(Inst)) {

          IRBuilder<> Post_IRB(Inst);

          StoreInst *RestoreCtx;
#ifdef AFL_HAVE_VECTOR_INTRINSICS
          if (ctx_k)
            RestoreCtx = IRB.CreateStore(PrevCaller, AFLPrevCaller);
          else
#endif
            RestoreCtx = Post_IRB.CreateStore(PrevCtx, AFLContext);
          RestoreCtx->setMetadata(M.getMDKindID("nosanitize"),
                                  MDNode::get(C, None));

        }

      }

      inst_blocks++;

    }

#if 0
    if (use_threadsafe_counters) {                       /*Atomic NeverZero */
      // handle the list of registered blocks to instrument
      for (auto val : todo) {

        /* hexcoder: Realize a thread-safe counter that skips zero during
         * overflow. Once this counter reaches its maximum value, it next
         * increments to 1
         *
         * Instead of
         * Counter + 1 -> Counter
         * we inject now this
         * Counter + 1 -> {Counter, OverflowFlag}
         * Counter + OverflowFlag -> Counter
         */

        /* equivalent c code looks like this
         * Thanks to
         https://preshing.com/20150402/you-can-do-any-kind-of-atomic-read-modify-write-operation/

            int old = atomic_load_explicit(&Counter, memory_order_relaxed);
            int new;
            do {

                 if (old == 255) {

                   new = 1;

                 } else {

                   new = old + 1;

                 }

            } while (!atomic_compare_exchange_weak_explicit(&Counter, &old, new,

         memory_order_relaxed, memory_order_relaxed));

         */

        Value *              MapPtrIdx = val;
        Instruction *        MapPtrIdxInst = cast<Instruction>(val);
        BasicBlock::iterator it0(&(*MapPtrIdxInst));
        ++it0;
        IRBuilder<> IRB(&(*it0));

        // load the old counter value atomically
        LoadInst *Counter = IRB.CreateLoad(
  #if LLVM_VERSION_MAJOR >= 14
        IRB.getInt8Ty(),
  #endif
        MapPtrIdx);
        Counter->setAlignment(llvm::Align());
        Counter->setAtomic(llvm::AtomicOrdering::Monotonic);
        Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        BasicBlock *BB = IRB.GetInsertBlock();
        // insert a basic block with the corpus of a do while loop
        // the calculation may need to repeat, if atomic compare_exchange is not
        // successful

        BasicBlock::iterator it(*Counter);
        it++;  // split after load counter
        BasicBlock *end_bb = BB->splitBasicBlock(it);
        end_bb->setName("injected");

        // insert the block before the second half of the split
        BasicBlock *do_while_bb =
            BasicBlock::Create(C, "injected", end_bb->getParent(), end_bb);

        // set terminator of BB from target end_bb to target do_while_bb
        auto term = BB->getTerminator();
        BranchInst::Create(do_while_bb, BB);
        term->eraseFromParent();

        // continue to fill instructions into the do_while loop
        IRB.SetInsertPoint(do_while_bb, do_while_bb->getFirstInsertionPt());

        PHINode *PN = IRB.CreatePHI(Int8Ty, 2);

        // compare with maximum value 0xff
        auto *Cmp = IRB.CreateICmpEQ(Counter, ConstantInt::get(Int8Ty, -1));

        // increment the counter
        Value *Incr = IRB.CreateAdd(Counter, One);

        // select the counter value or 1
        auto *Select = IRB.CreateSelect(Cmp, One, Incr);

        // try to save back the new counter value
        auto *CmpXchg = IRB.CreateAtomicCmpXchg(
            MapPtrIdx, PN, Select, llvm::AtomicOrdering::Monotonic,
            llvm::AtomicOrdering::Monotonic);
        CmpXchg->setAlignment(llvm::Align());
        CmpXchg->setWeak(true);
        CmpXchg->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        // get the result of trying to update the Counter
        Value *Success =
            IRB.CreateExtractValue(CmpXchg, ArrayRef<unsigned>({1}));
        // get the (possibly updated) value of Counter
        Value *OldVal =
            IRB.CreateExtractValue(CmpXchg, ArrayRef<unsigned>({0}));

        // initially we use Counter
        PN->addIncoming(Counter, BB);
        // on retry, we use the updated value
        PN->addIncoming(OldVal, do_while_bb);

        // if the cmpXchg was not successful, retry
        IRB.CreateCondBr(Success, end_bb, do_while_bb);

      }

    }

#endif

  }

  /*
    // This is currently disabled because we not only need to create/insert a
    // function (easy), but also add it as a constructor with an ID < 5

    if (getenv("AFL_LLVM_DONTWRITEID") == NULL) {

      // yes we could create our own function, insert it into ctors ...
      // but this would be a pain in the butt ... so we use afl-llvm-rt.o

      Function *f = ...

      if (!f) {

        fprintf(stderr,
                "Error: init function could not be created (this should not
    happen)\n"); exit(-1);

      }

      ... constructor for f = 4

      BasicBlock *bb = &f->getEntryBlock();
      if (!bb) {

        fprintf(stderr,
                "Error: init function does not have an EntryBlock (this should
    not happen)\n"); exit(-1);

      }

      BasicBlock::iterator IP = bb->getFirstInsertionPt();
      IRBuilder<>          IRB(&(*IP));

      if (map_size <= 0x800000) {

        GlobalVariable *AFLFinalLoc = new GlobalVariable(
            M, Int32Ty, true, GlobalValue::ExternalLinkage, 0,
            "__afl_final_loc");
        ConstantInt *const_loc = ConstantInt::get(Int32Ty, map_size);
        StoreInst *  StoreFinalLoc = IRB.CreateStore(const_loc, AFLFinalLoc);
        StoreFinalLoc->setMetadata(M.getMDKindID("nosanitize"),
                                     MDNode::get(C, None));

      }

    }

  */

  /* Say something nice. */

  if (!be_quiet) {

    if (!inst_blocks)
      WARNF("No instrumentation targets found.");
    else {

      char modeline[100];
      snprintf(modeline, sizeof(modeline), "%s%s%s%s%s%s",
               getenv("AFL_HARDEN") ? "hardened" : "non-hardened",
               getenv("AFL_USE_ASAN") ? ", ASAN" : "",
               getenv("AFL_USE_MSAN") ? ", MSAN" : "",
               getenv("AFL_USE_CFISAN") ? ", CFISAN" : "",
               getenv("AFL_USE_TSAN") ? ", TSAN" : "",
               getenv("AFL_USE_UBSAN") ? ", UBSAN" : "");
      OKF("Instrumented %d locations (%s mode, ratio %u%%).", inst_blocks,
          modeline, inst_ratio);

    }

  }

#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
  return PA;
#else
  return true;
#endif

}

#if LLVM_VERSION_MAJOR < 11                         /* use old pass manager */
static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLCoverage());

}

static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_OptimizerLast, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
#endif

