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
#include<iostream>
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
// static std::string map_file_path="/root/pure-ftpd/entryId_to_funcName_table";
using namespace std;

map<string, int> entry_map;

llvm::cl::opt<std::string> config_path("config", llvm::cl::desc("Specify the config file of entry"), llvm::cl::value_desc("config_file") );    

/*
 * 0: set entry everywhere
 * 1: set entry at Function beginning
 * 2: set entry at specific function
 * */
llvm::cl::opt<std::string> level("level", llvm::cl::desc("Specify the level of entry"), llvm::cl::value_desc("level") );    
//add eval mode feature
llvm::cl::opt<std::string> mode("mode", llvm::cl::desc("Specify the mode of program"),llvm::cl::value_desc("mode"));
//
bool AFLCoverage::runOnModule(Module &M) {
    std::ofstream fp;
  LLVMContext &C = M.getContext();

  IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
//int mode_v=0;
  // int entry_level = 0;
  int entry_level = 1;
  if (level != "")
    entry_level = std::stoi(level);
  

  //add eval mode
  mode="eval";
  if(mode!=""){
      //mode_v=std::stoi(mode);
    fp.open(mode.c_str(),ios::out|ios::app);
    std::cout<<"open"<<mode<<std::endl;
    if(!fp.is_open()){
        FATAL("can not open %s\n",mode.c_str());
        exit(-1);
    }
  }

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
  // config_path = "/root/eval/ntp-4.2.8p8/entry.conf";
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
  string recvmsg_function = string("recvmsg");
  string recvfrom_function = string("recvfrom");
  string send_function = string("send");
  string sendto_function = string("sendto");
  string sendmsg_function = string("sendmsg");
  string writev_function = string("writev");
  string close_function = string("close");
  string accept_function = string("accept");
  string accept4_function = string("accept4");

  //add eval mode feature to add new global var record the map from entry id to function name
  /*if(mode!=""){
      if(mode=="eval"){
        GlobalVariable *BSA_eid_fname_map;
        Type* char_pt=(llvm::Type*)PointerType::get(IntegerType::get(C,8),0);
        ArrayType* array_t=ArrayType::get(char_pt,MAP_SIZE);
        BSA_eid_fname_map=new GlobalVariable(M,(llvm::Type*)array_t,false,GlobalValue::ExternalLinkage,0,"BSA_eid2fname");
      }
  }*/
  //
  GlobalVariable *BSA_state; 
  GlobalVariable *BSA_fuzz_req; 

  BSA_state = new GlobalVariable(M, (llvm::Type*)IntegerType::getInt32Ty(C), false, GlobalValue::ExternalLinkage, 0, "BSA_state",  nullptr, GlobalValue::GeneralDynamicTLSModel); 

  GlobalVariable *AFLMapPtr =
    new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                       GlobalValue::ExternalLinkage, 0, "_afl_area_ptr");


  GlobalVariable *AFLPrevLoc = new GlobalVariable(M, (llvm::Type*)IntegerType::getInt32Ty(C), false, GlobalValue::ExternalLinkage, 0,  "_afl_prev_loc");
  GlobalVariable *AFLEdge = new GlobalVariable(M, (llvm::Type*)IntegerType::getInt32Ty(C), false, GlobalValue::ExternalLinkage, 0,  "_afl_edge");

  BSA_fuzz_req = new GlobalVariable(M, (llvm::Type*)IntegerType::getInt32Ty(C), false, GlobalValue::ExternalLinkage, 0, "BSA_fuzz_req" ); 
  
  Constant* callee_checkpoint = M.getOrInsertFunction("BSA_checkpoint",
                    Type::getVoidTy(M.getContext()), 
                    Type::getInt32Ty(M.getContext()),NULL);
  
  Constant* callee_log = M.getOrInsertFunction("tiny_afl_maybe_log",
                    Type::getVoidTy(M.getContext()), 
                    Type::getInt32Ty(M.getContext()),NULL);

  //global array
  //std::vector<llvm::Constant*> eid2fname_map(MAP_SIZE);
  //
  for (auto &F : M){
      //std::string func_name=F.getName().str();
    int is_entry = 1;
    if(F.isIntrinsic()) continue;
    else if(F.isDeclaration()){
        std::string func_name = F.getName().str();
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
        //else fprintf(stderr, "Bypass %s\n", F.getName().str().c_str());

        //eval mode
        
        //
    }
    bool first = true;
    for (auto &BB : F) {
      

      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<> IRB(&(*IP));
      
      if (AFL_R(100) >= inst_ratio) continue;

      /* Make up cur_loc */
      unsigned int cur_loc = AFL_R(MAP_SIZE);
      ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

      if(!first){
        LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
        PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));


        LoadInst *AFLPrevEdge = IRB.CreateLoad(AFLEdge);
        AFLPrevEdge->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));


        
        Value *PrevAFLedgeCasted = IRB.CreateZExt(AFLPrevEdge, IRB.getInt32Ty());

        LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
        MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        Value *MapPtrIdx =
        IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevAFLedgeCasted, CurLoc));

        LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
        Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *Incr = IRB.CreateAdd(Counter, llvm::ConstantInt::get(Int8Ty, 1));
        IRB.CreateStore(Incr, MapPtrIdx)
            ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        
        StoreInst *Store =
            IRB.CreateStore(llvm::ConstantInt::get(Int32Ty, cur_loc >> 1), AFLEdge);

        Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());
        Value *ShiftedPrevLoc = IRB.CreateLShr(PrevLocCasted, 1);
        Value *NewPrevLoc = IRB.CreateXor(ShiftedPrevLoc, ConstantInt::get((llvm::Type*)IntegerType::getInt32Ty(C), cur_loc));
        IRB.CreateStore(NewPrevLoc, AFLPrevLoc);

        // Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        



        // Value *args_maybe[1];
        // args_maybe[0] = llvm::ConstantInt::get(llvm::Type::getInt32Ty(M.getContext()), cur_loc);
        // IRB.CreateCall(callee_log,args_maybe);


        continue;

      }


      
      //eval mode
        //std::cout<<"instrument "<<std::hex<<cur_loc<<" "<<F.getName().str()<<std::endl;
        //fp<<std::hex<<cur_loc<<" "<<F.getName().str()<<std::endl;
      //if(is_entry==1){

          
      //}
            /*//construct func_name array
            std::string func_name=F.getName().str();
            std::vector<llvm::Constant *> f_name(func_name.length());
            auto char_t=llvm::IntegerType::get(M.getContext(),8);
            for(unsigned int i=0;i<func_name.length();i++){
                f_name[i]=llvm::ConstantInt::get(char_t,func_name[i]);
            }
            f_name.push_back(llvm::ConstantInt::get(char_t,0));
            auto string_t=llvm::ArrayType::get(char_t,f_name.size());
            eid2fname_map[cur_loc]=llvm::ConstantArray::get(string_t,f_name);*/
      //}
   	  Value *args[2];
      
      args[0] = llvm::ConstantInt::get(llvm::Type::getInt32Ty(M.getContext()), cur_loc);
      

      // if(!first){
      //   IRB.CreateCall(callee_log,args_maybe);
      //   inst_blocks++;
      //   continue;
      // }


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
        // if(F.getName().str() == "socket_bucket_read"){
        //   is_entry = 1;
        // }
        // else{
        //   is_entry = 0;
        // }
        //if(is_entry){
          fp<<is_entry<<"  "<<cur_loc<<" ";
          fp<<M.getSourceFileName()<<"      "<<F.getName().str()<<"\n";
          llvm::errs()<<cur_loc<<" "<<M.getSourceFileName()<<"      "<<F.getName().str()<<"\n";
        //}
          
      // if(F.getName().str() == "read_network_packet"){
      //   llvm::errs()<<cur_loc<<" "<<M.getSourceFileName()<<"      "<<F.getName().str()<<"\n";
      //   is_entry = 1;
      // }
      args[1] = llvm::ConstantInt::get(llvm::Type::getInt32Ty(M.getContext()), is_entry);
      // auto char_t=llvm::IntegerType::get(M.getContext(),8);
      // auto string_t=llvm::ArrayType::get(char_t,f_name.size());
      IRB.CreateCall(callee_checkpoint,args);
      is_entry = 0;
      
      
      inst_blocks++;
      first = false;
    }

  }
        //  auto char_t=llvm::IntegerType::get(M.getContext(),8);
        //auto string_t=llvm::ArrayType::get(char_t,f_name.size());

  /*  Type* char_pt=(llvm::Type*)PointerType::get(IntegerType::get(C,8),0);
  auto eid2fname_map_t=llvm::ArrayType::get(char_pt,MAP_SIZE);
  if(mode=="eval"){
        GlobalVariable *BSA_eid_fname_map;
        BSA_eid_fname_map=new GlobalVariable(M,(llvm::Type*)eid2fname_map_t,true,GlobalValue::ExternalLinkage,llvm::ConstantArray::get(eid2fname_map_t,eid2fname_map),"BSA_eid2fname");
  }*/
    
  /* Say something nice. */

  if (!be_quiet) {

    if (!inst_blocks) WARNF("No instrumentation targets found.");
    else OKF("Instrumented %u locations (%s mode, ratio %u%%).",
             inst_blocks, getenv("AFL_HARDEN") ? "hardened" :
             ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN")) ?
              "ASAN/MSAN" : "non-hardened"), inst_ratio);

  }
  if(mode!=""){
      fp.close();
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