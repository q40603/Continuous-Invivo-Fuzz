#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Attributes.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Support/Debug.h"
#include "llvm/IR/LegacyPassManager.h"

#include <unistd.h>
#include <iostream>
#include <fstream>
#include <cstdio>
#include <cstdlib>
#include <map>

using namespace llvm;
using namespace std;


namespace {

struct TraceFunction : public ModulePass {
    static char ID;
    TraceFunction() :  ModulePass(ID) {}
    
    string read_function = string("read");
    string write_function = string("write");
    string scanf_function = string("__isoc99_scanf");
    string recv_function = string("recv");
    string writev_function = string("writev");

    GlobalVariable *BSA_state; 
    GlobalVariable *BSA_fuzz_req; 

    uint64_t id = 0;
    bool runOnModule(Module &M) override {
        
        LLVMContext &C = M.getContext();
        BSA_state = new GlobalVariable(M, (llvm::Type*)IntegerType::getInt32Ty(C), false, GlobalValue::ExternalLinkage, 0, "BSA_state" ); 
        BSA_fuzz_req = new GlobalVariable(M, (llvm::Type*)IntegerType::getInt32Ty(C), false, GlobalValue::ExternalLinkage, 0, "BSA_fuzz_req" ); 

        for(auto& F:M){
            if(F.isIntrinsic()) continue;
            else if(F.isDeclaration()){
                string func_name = F.getName().str();
                if (func_name == read_function ) F.setName("BSA_hook_read"); 
                else if(func_name == write_function) F.setName("BSA_hook_write"); 
                else if(func_name == scanf_function) F.setName("BSA_hook_scanf");
                else if(func_name == recv_function)  F.setName("BSA_hook_recv");
                else if(func_name == writev_function) F.setName("BSA_hook_writev");
                else fprintf(stderr, "Bypass %s\n", F.getName().str().c_str());
            }
            else{
                instrumented_codes(&M, &F);
            }               
        }
        return true;
    }
    
    void instrumented_codes(Module *M, Function *F){

         
        string func_name = F->getName().str();
        Constant* callee = M->getOrInsertFunction("BSA_checkpoint",
                    Type::getVoidTy(M->getContext()), 
                    Type::getInt32Ty(M->getContext()),NULL);
        
        
        BasicBlock& old_BB = F->getEntryBlock();
        /*
        BasicBlock* new_BB = BasicBlock::Create(M->getContext(), "new_entry", F, &F->getEntryBlock());
        BasicBlock* log_BB = BasicBlock::Create(M->getContext(), "log_BB", F, &old_BB);

        IRBuilder<> log_builder(log_BB); 
        IRBuilder<> new_entry_builder(new_BB);

        LoadInst *load_state = new_entry_builder.CreateLoad(BSA_state);
        load_state->setMetadata(M->getMDKindID("nosanitize"), MDNode::get(M->getContext(), None));

        LoadInst *load_fuzz_req = new_entry_builder.CreateLoad(BSA_fuzz_req);
        load_fuzz_req->setMetadata(M->getMDKindID("nosanitize"), MDNode::get(M->getContext(), None));
        Value *and_result = new_entry_builder.CreateOr(load_state, load_fuzz_req);

        Value* cmp_ret = new_entry_builder.CreateICmpEQ(and_result, new_entry_builder.getInt32(1), "is_fuzz");    
        new_entry_builder.CreateCondBr(cmp_ret, log_BB, &old_BB); 
        */
        Value *args[1];
        args[0] = llvm::ConstantInt::get(llvm::Type::getInt32Ty(M->getContext()), id);

        /* Log_BB */
        /*
        if (func_name == string("ngx_unix_recv")){
            args[1] = llvm::ConstantInt::get(llvm::Type::getInt32Ty(M->getContext()), 1);
        }
        else
            args[1] = llvm::ConstantInt::get(llvm::Type::getInt32Ty(M->getContext()), 0);
        */
        
        IRBuilder<> log_builder(F->getEntryBlock().getFirstNonPHI()); 
        log_builder.CreateCall(callee,args);
        //log_builder.CreateBr(&old_BB);

        id++;

    }

    
};
}
char TraceFunction::ID = 0;
static RegisterPass<TraceFunction> X("BSA", "TraceFunctionPass",
                             false /* Only looks at CFG */,
                             false /* Analysis Pass */);

