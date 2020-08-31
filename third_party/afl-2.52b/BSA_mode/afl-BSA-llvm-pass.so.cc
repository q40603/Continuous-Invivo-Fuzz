/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.

 */

#define AFL_LLVM_PASS

#include "../config.h"
#include "../debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <map>
#include <fstream>

#include "llvm/Pass.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

using namespace llvm;


namespace {

  class AFLCoverage : public ModulePass {

    public:

      static char ID;
      AFLCoverage() : ModulePass(ID) { }

      bool runOnModule(Module &M) override;

      // StringRef getPassName() const override {
      //  return "American Fuzzy Lop Instrumentation";
      // }

  };

}


char AFLCoverage::ID = 0;
int is_config = 0;

using namespace std;

map<string, int> entry_map;

llvm::cl::opt<std::string> config_path("config", llvm::cl::desc("Specify the config file of entry"), llvm::cl::value_desc("config_file") );    

/*
 * 0: set entry everywhere
 * 1: set entry at Function beginning
 * 2: set entry at specific function
 * */
llvm::cl::opt<std::string> level("level", llvm::cl::desc("Specify the level of entry"), llvm::cl::value_desc("level") );    

bool AFLCoverage::runOnModule(Module &M) {

  LLVMContext &C = M.getContext();

  // IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
  // IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

  int entry_level = 0;
  if (level != "")
    entry_level = std::stoi(level);
  
  /* Show a banner */
  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET")) {

    SAYF(cCYA "afl-BSA-llvm-pass " cBRI VERSION cRST " by <x3639026@google.com>\n");

  } else be_quiet = 1;

  /* Decide instrumentation ratio */
  string tmp;
  char* inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

  }

  /* Get globals for the SHM region and the previous location. Note that
     __afl_prev_loc is thread-local. */
  
  /* Config file supply */
  if(config_path != ""){
    fstream config_istream(config_path.c_str(), ios::in);
    while(config_istream >> tmp){
      if (entry_map.find(tmp) == entry_map.end())
        entry_map[tmp] = 0;
      }
    llvm::errs() << "Following entry points: \n\n";
    for(std::map<string, int>::iterator it = entry_map.begin(); it != entry_map.end(); it++){
        llvm::errs() << "\t" << it->first << "\n";
    }
    llvm::errs() << "\n";
    is_config = 1;
  }else{
      llvm::errs() << "No config" << "\n";
  }


  /* Instrument all the things! */
  int inst_blocks = 0;
    
  string read_function = string("read");
  string write_function = string("write");
  string scanf_function = string("__isoc99_scanf");
  string recv_function = string("recv");
  string writev_function = string("writev");

  GlobalVariable *BSA_state; 
  GlobalVariable *BSA_fuzz_req; 

  BSA_state = new GlobalVariable(M, (llvm::Type*)IntegerType::getInt32Ty(C), false, GlobalValue::ExternalLinkage, 0, "BSA_state",  nullptr, GlobalValue::GeneralDynamicTLSModel); 

  GlobalVariable *AFLPrevLoc = new GlobalVariable(M, (llvm::Type*)IntegerType::getInt32Ty(C), false, GlobalValue::ExternalLinkage, 0,  "_afl_prev_loc");

  BSA_fuzz_req = new GlobalVariable(M, (llvm::Type*)IntegerType::getInt32Ty(C), false, GlobalValue::ExternalLinkage, 0, "BSA_fuzz_req" ); 
  
  Constant* callee_checkpoint = M.getOrInsertFunction("BSA_checkpoint",
                    Type::getVoidTy(M.getContext()), 
                    Type::getInt32Ty(M.getContext()),NULL);
  
  Constant* callee_log = M.getOrInsertFunction("_afl_maybe_log",
                    Type::getVoidTy(M.getContext()), 
                    Type::getInt32Ty(M.getContext()),NULL);

  for (auto &F : M){
    int is_entry = 1;
    if(F.isIntrinsic()) continue;
    else if(F.isDeclaration()){
        std::string func_name = F.getName().str();
        if (func_name == read_function ) F.setName("BSA_hook_read"); 
        else if(func_name == write_function) F.setName("BSA_hook_write"); 
        //else if(func_name == scanf_function) F.setName("BSA_hook_scanf");
        else if(func_name == recv_function)  F.setName("BSA_hook_recv");
        else if(func_name == writev_function) F.setName("BSA_hook_writev");
        //else fprintf(stderr, "Bypass %s\n", F.getName().str().c_str());
    }
    for (auto &BB : F) {
      
      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<> IRB(&(*IP));
      
      if (AFL_R(100) >= inst_ratio) continue;

      /* Make up cur_loc */

      unsigned int cur_loc = AFL_R(MAP_SIZE);
      
   	  Value *args[2];
      args[0] = llvm::ConstantInt::get(llvm::Type::getInt32Ty(M.getContext()), cur_loc);

    /* //Future improvement 
	  BasicBlock* new_BB = BasicBlock::Create(C, "new_entry", &F, &BB);
      BasicBlock* log_BB = BasicBlock::Create(C, "log_BB", &F, &BB);
      BasicBlock* temp_BB = BasicBlock::Create(C, "temp_BB", &F, &BB);

      IRBuilder<> log_builder(log_BB); 
      IRBuilder<> new_entry_builder(new_BB);
      LoadInst *load_state = new_entry_builder.CreateLoad(BSA_state);
      Value* BSA_state_value = IRB.CreateZExt(load_state, IRB.getInt32Ty());
      Value* cmp_ret = new_entry_builder.CreateICmpEQ(BSA_state_value, new_entry_builder.getInt32(1), "is_fuzz");    
      new_entry_builder.CreateCondBr(cmp_ret, log_BB, temp_BB); 
	  log_builder.CreateCall(callee_log,args);
      log_builder.CreateBr(temp_BB);
     
      
      for (auto&I: BB){
          PHINode *phinode = NULL;
          if((phinode = dyn_cast<PHINode,Instruction>(&I))){
                for(auto it=phinode->block_begin();it!=phinode->block_end();it++){
                    if(*it==ori_predecessor){
                        *it=new_predecessor;                                                      
                    }                          
                }
          } 
      }
      // logging     
      LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
      Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());
      Value *ShiftedPrevLoc = IRB.CreateLShr(PrevLocCasted, 1);
      Value *NewPrevLoc = IRB.CreateXor(ShiftedPrevLoc, ConstantInt::get((llvm::Type*)IntegerType::getInt32Ty(C), cur_loc));
       StoreInst *Store =
          IRB.CreateStore(NewPrevLoc, AFLPrevLoc);
*/
              
            
      if (is_config && entry_level == 2){
		if (entry_map.find(F.getName().str()) == entry_map.end()){
            is_entry = 0;
        }
      }
      else if (entry_level == 0){
      		is_entry = 1;
      }
      args[1] = llvm::ConstantInt::get(llvm::Type::getInt32Ty(M.getContext()), is_entry);
      	
      IRB.CreateCall(callee_checkpoint,args);
      is_entry = 0;
      
      
      inst_blocks++;
    }

  }

  /* Say something nice. */

  if (!be_quiet) {

    if (!inst_blocks) WARNF("No instrumentation targets found.");
    else OKF("Instrumented %u locations (%s mode, ratio %u%%).",
             inst_blocks, getenv("AFL_HARDEN") ? "hardened" :
             ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN")) ?
              "ASAN/MSAN" : "non-hardened"), inst_ratio);

  }

  return true;

}


static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLCoverage());

}


static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_OptimizerLast, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
