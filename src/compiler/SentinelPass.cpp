#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {

struct SentinelPass : public PassInfoMixin<SentinelPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM) {
    LLVMContext &Ctx = M.getContext();
    IRBuilder<> Builder(Ctx);

    // Types for the Policy Structure
    // LLVM 15+ Opaque Pointers: Use PointerType::getUnqual(Ctx)
    Type *VoidPtrTy = PointerType::getUnqual(Ctx);
    Type *Int64Ty = Type::getInt64Ty(Ctx);

    // Struct: { i8* Site, i8* Function, i64 Size }
    StructType *PolicyEntryTy = StructType::create(Ctx, "struct.SentinelEntry");
    PolicyEntryTy->setBody({VoidPtrTy, VoidPtrTy, Int64Ty});

    std::vector<Constant *> PolicyEntries;
    std::vector<Instruction *> Syscalls;

    // 1. Identify Syscalls (Collect first to avoid iterator invalidation)
    for (Function &F : M) {
      if (F.isDeclaration())
        continue;

      for (BasicBlock &BB : F) {
        for (Instruction &I : BB) {
          bool IsSyscall = false;

          if (auto *CI = dyn_cast<CallInst>(&I)) {
            if (CI->isInlineAsm()) {
              auto *IA = cast<InlineAsm>(CI->getCalledOperand());
              if (StringRef(IA->getAsmString()).contains("syscall")) {
                IsSyscall = true;
              }
            } else if (Function *CalledF = CI->getCalledFunction()) {
              StringRef Name = CalledF->getName();
              // We trap 'write' wrapper too, treating the call instructions as
              // the site. But for Phase 1.2 strictness, we focus on inline
              // syscalls or known wrappers.
              if (Name == "syscall" || Name == "__sys_write" ||
                  Name == "write" || Name == "__libc_write") {
                IsSyscall = true;
              }
            }
          }

          if (IsSyscall) {
            Syscalls.push_back(&I);
          }
        }
      }
    }

    // 2. Instrument (Split Block + Create Label)
    bool Modified = !Syscalls.empty();

    for (Instruction *I : Syscalls) {
      BasicBlock *OldBB = I->getParent();
      Function *F = OldBB->getParent();

      // Split: NewBB starts EXACTLY at 'I' (the syscall/call instruction)
      // splitBasicBlock moves 'I' and subsequent instructions into NewBB.
      BasicBlock *NewBB = OldBB->splitBasicBlock(I, "sentinel_site");

      errs() << "[Sentinel] Captured precise syscall site in: " << F->getName()
             << "\n";

      // Create Entry: { BlockAddress(NewBB), FuncAddress, 0 }
      // BlockAddress resolves to the address of the first instruction in NewBB.
      Constant *SiteLabel = BlockAddress::get(NewBB);

      // Opaque Pointers: Check if cast is needed for Function Pointer
      Constant *FuncPtr = F;
      if (FuncPtr->getType() != VoidPtrTy)
        FuncPtr = ConstantExpr::getBitCast(FuncPtr, VoidPtrTy);

      Constant *Size = ConstantInt::get(Int64Ty, 0);

      Constant *Entry =
          ConstantStruct::get(PolicyEntryTy, {SiteLabel, FuncPtr, Size});
      PolicyEntries.push_back(Entry);
    }

    // Step B: Create the Global Policy Array (Always, even if empty)
    if (PolicyEntries.empty()) {
      errs() << "[Sentinel] No syscalls found. Creating dummy entry to prevent "
                "stripping.\n";
      Constant *NullPtr = Constant::getNullValue(VoidPtrTy);
      Constant *Zero = ConstantInt::get(Int64Ty, 0);
      Constant *Dummy =
          ConstantStruct::get(PolicyEntryTy, {NullPtr, NullPtr, Zero});
      PolicyEntries.push_back(Dummy);
    }

    ArrayType *ArrayTy = ArrayType::get(PolicyEntryTy, PolicyEntries.size());
    Constant *ArrayInit = ConstantArray::get(ArrayTy, PolicyEntries);

    GlobalVariable *PolicyTable =
        new GlobalVariable(M, ArrayTy, true, GlobalValue::ExternalLinkage,
                           ArrayInit, "__sentinel_policy");

    PolicyTable->setSection(".sentinel");
    PolicyTable->setAlignment(Align(16));

    if (!PolicyEntries.empty()) {
      errs() << "[Sentinel] Injected " << PolicyEntries.size()
             << " precise entries into .sentinel section.\n";
    }

    // 3. Inject Signature Placeholder (Reserve space for Signing Tool)
    // 256 bytes for RSA-2048 signature.
    ArrayType *SigType = ArrayType::get(Type::getInt8Ty(Ctx), 256);
    Constant *SigInit = ConstantAggregateZero::get(SigType);
    GlobalVariable *SigVar =
        new GlobalVariable(M, SigType, false, GlobalValue::ExternalLinkage,
                           SigInit, "__sentinel_signature");
    SigVar->setSection(".signature");
    // SigVar->setUsedWithNoInlining(true); // Method does not exist in LLVM 15

    // Handle Name Collision with 'extern' declaration in C
    // If victim.c defines 'extern char __sentinel_signature[];', LLVM creates a
    // declaration. Our 'new GlobalVariable' above will be renamed to
    // '__sentinel_signature.2'. We must find the declaration, replace uses, and
    // assume the name.
    if (SigVar->getName() != "__sentinel_signature") {
      GlobalVariable *OldVar = M.getGlobalVariable("__sentinel_signature");
      if (OldVar) {
        // Replace references (e.g. in main's inline asm) with new var
        // Cast NewVar to OldVar's type if needed (Opaque Pointers -> just ptr)

        // For Opaque Pointers (LLVM 15), types are implicit in instructions.
        // But Value->getType() is still a PointerType.
        // If they match (both ptr), direct replacement.
        if (OldVar->getType() == SigVar->getType()) {
          OldVar->replaceAllUsesWith(SigVar);
        } else {
          // Should not happen with minimal opaque pointers, but for safety:
          // ConstantExpr::getBitCast(SigVar, OldVar->getType())
          // But BitCast is deprecated for opaque.
          OldVar->replaceAllUsesWith(SigVar);
        }
        OldVar->eraseFromParent();
        SigVar->setName("__sentinel_signature");
      }
    }

    // Add to llvm.used to prevent compiler stripping
    GlobalVariable *LLVMUsed = M.getGlobalVariable("llvm.used");
    std::vector<Constant *> UsedArray;
    if (LLVMUsed) {
      ConstantArray *CA = cast<ConstantArray>(LLVMUsed->getInitializer());
      for (unsigned i = 0; i < CA->getNumOperands(); ++i) {
        UsedArray.push_back(CA->getOperand(i));
      }
      LLVMUsed->eraseFromParent();
    }
    // Cast SigVar to i8* (void*) for llvm.used
    // LLVM 15+ Opaque Pointers: Use PointerType::getUnqual(Ctx)
    Constant *SigCast =
        ConstantExpr::getBitCast(SigVar, PointerType::getUnqual(Ctx));
    UsedArray.push_back(SigCast);

    // Also add PolicyTable to llvm.used so it isn't stripped
    if (PolicyTable) {
      Constant *PolicyCast =
          ConstantExpr::getBitCast(PolicyTable, PointerType::getUnqual(Ctx));
      UsedArray.push_back(PolicyCast);
    }

    ArrayType *ATy =
        ArrayType::get(PointerType::getUnqual(Ctx), UsedArray.size());
    GlobalVariable *NewUsed =
        new GlobalVariable(M, ATy, false, GlobalValue::AppendingLinkage,
                           ConstantArray::get(ATy, UsedArray), "llvm.used");
    NewUsed->setSection("llvm.metadata");

    return Modified ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }
};

} // namespace

// Registration
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "SentinelPass", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineStartEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel Level) {
                  MPM.addPass(SentinelPass());
                });
          }};
}
