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

#include <regex>
#include <set>
#include <string>

using namespace llvm;

namespace {

// Comprehensive list of libc syscall wrappers we should track.
// These are functions that ultimately invoke 'syscall' on the user's behalf.
static bool isKnownSyscallWrapper(StringRef Name) {
  // POSIX I/O
  if (Name == "write" || Name == "read" || Name == "open" ||
      Name == "close" || Name == "lseek")
    return true;
  // GNU/glibc internal wrappers
  if (Name == "__write" || Name == "__read" || Name == "__open" ||
      Name == "__close")
    return true;
  if (Name == "__libc_write" || Name == "__libc_read" ||
      Name == "__libc_open" || Name == "__libc_close")
    return true;
  if (Name == "__sys_write" || Name == "__sys_read")
    return true;
  // Generic syscall()
  if (Name == "syscall")
    return true;
  // File operations
  if (Name == "openat" || Name == "fstat" || Name == "stat" ||
      Name == "lstat" || Name == "fstatat")
    return true;
  // Process
  if (Name == "fork" || Name == "vfork" || Name == "clone" ||
      Name == "execve" || Name == "execveat")
    return true;
  // Memory mapping
  if (Name == "mmap" || Name == "munmap" || Name == "mprotect" ||
      Name == "mremap" || Name == "brk")
    return true;
  // Network
  if (Name == "socket" || Name == "connect" || Name == "bind" ||
      Name == "listen" || Name == "accept" || Name == "accept4" ||
      Name == "send" || Name == "sendto" || Name == "recv" ||
      Name == "recvfrom" || Name == "sendmsg" || Name == "recvmsg")
    return true;
  // Dangerous
  if (Name == "ptrace" || Name == "kill" || Name == "tkill" ||
      Name == "tgkill")
    return true;
  // Signal
  if (Name == "sigaction" || Name == "rt_sigaction" ||
      Name == "rt_sigprocmask")
    return true;
  // Buffered I/O (indirectly invoke syscalls via libc)
  if (Name == "printf" || Name == "fprintf" || Name == "vprintf" ||
      Name == "vfprintf" || Name == "sprintf" || Name == "snprintf" ||
      Name == "dprintf")
    return true;
  if (Name == "puts" || Name == "fputs" || Name == "putchar" ||
      Name == "fputc" || Name == "putc")
    return true;
  if (Name == "fwrite" || Name == "fread" || Name == "fflush")
    return true;
  if (Name == "fopen" || Name == "fclose" || Name == "fdopen" ||
      Name == "freopen")
    return true;
  if (Name == "fgets" || Name == "fgetc" || Name == "getchar" ||
      Name == "getline" || Name == "getdelim")
    return true;
  if (Name == "perror")
    return true;
  return false;
}

// Phase 3: Map known wrapper to its primary x86-64 syscall number.
// Returns -1 if unknown or may invoke multiple different syscalls.
static int64_t getSyscallNumberForWrapper(StringRef Name) {
  // POSIX I/O
  if (Name == "write" || Name == "__write" || Name == "__libc_write") return 1;
  if (Name == "read" || Name == "__read" || Name == "__libc_read") return 0;
  if (Name == "open" || Name == "__open" || Name == "__libc_open") return 2;
  if (Name == "close" || Name == "__close" || Name == "__libc_close") return 3;
  if (Name == "lseek") return 8;
  if (Name == "openat") return 257;
  if (Name == "fstat") return 5;
  if (Name == "stat") return 4;
  if (Name == "lstat") return 6;
  if (Name == "fstatat") return 262;
  // Process
  if (Name == "fork") return 57;
  if (Name == "vfork") return 58;
  if (Name == "clone") return 56;
  if (Name == "execve") return 59;
  if (Name == "execveat") return 322;
  // Memory
  if (Name == "mmap") return 9;
  if (Name == "munmap") return 11;
  if (Name == "mprotect") return 10;
  if (Name == "mremap") return 25;
  if (Name == "brk") return 12;
  // Network
  if (Name == "socket") return 41;
  if (Name == "connect") return 42;
  if (Name == "bind") return 49;
  if (Name == "listen") return 50;
  if (Name == "accept") return 43;
  if (Name == "accept4") return 288;
  if (Name == "send" || Name == "sendto") return 44;
  if (Name == "recv" || Name == "recvfrom") return 45;
  if (Name == "sendmsg") return 46;
  if (Name == "recvmsg") return 47;
  // Dangerous
  if (Name == "ptrace") return 101;
  if (Name == "kill") return 62;
  if (Name == "tkill") return 200;
  if (Name == "tgkill") return 234;
  // Signal
  if (Name == "sigaction" || Name == "rt_sigaction") return 13;
  if (Name == "rt_sigprocmask") return 14;
  // Generic syscall / buffered I/O — may invoke multiple syscalls
  return -1;
}

// Phase 3: Extract syscall number from inline asm by finding the RAX
// input constraint ("a" / "{ax}" / "{rax}") and returning its constant value.
// Returns -1 if the value cannot be determined at compile time.
static int64_t extractSyscallNumberFromAsm(CallInst *CI) {
  auto *IA = cast<InlineAsm>(CI->getCalledOperand());
  auto Constraints =
      InlineAsm::ParseConstraints(IA->getConstraintString());
  unsigned argIdx = 0;
  for (const auto &C : Constraints) {
    if (C.Type == InlineAsm::isOutput) {
      if (C.isIndirect)
        argIdx++; // Indirect outputs consume an argument slot
    } else if (C.Type == InlineAsm::isInput) {
      for (const auto &Code : C.Codes) {
        if (Code == "a" || Code == "{ax}" || Code == "{rax}" ||
            Code == "{eax}") {
          if (argIdx < CI->arg_size()) {
            if (auto *CInt =
                    dyn_cast<ConstantInt>(CI->getArgOperand(argIdx)))
              return CInt->getSExtValue();
          }
          return -1; // RAX input is not a compile-time constant
        }
      }
      argIdx++;
    }
  }
  return -1; // No RAX input constraint found
}

struct SentinelPass : public PassInfoMixin<SentinelPass> {

  // Detect obfuscated syscall instructions in inline asm.
  // Catches .byte 0x0f, 0x05 and variants that bypass the "syscall" string match.
  static bool containsObfuscatedSyscall(StringRef AsmStr) {
    std::string S = AsmStr.str();
    // Pattern 1: .byte with hex 0x0f ... 0x05 (any separator)
    //   .byte 0x0f, 0x05   .byte 0xf,0x5   .byte 0x0f;.byte 0x05
    std::regex HexPat(R"(\.byte\s+0x0?[fF]\s*[,;]\s*\.?b?y?t?e?\s*0x0?5)",
                      std::regex::icase);
    if (std::regex_search(S, HexPat))
      return true;
    // Pattern 2: .byte with decimal 15, 5
    std::regex DecPat(R"(\.byte\s+15\s*[,;]\s*\.?b?y?t?e?\s*5\b)",
                      std::regex::icase);
    if (std::regex_search(S, DecPat))
      return true;
    // Pattern 3: raw escape sequences (\x0f\x05)
    if (S.find("\\x0f\\x05") != std::string::npos)
      return true;
    if (S.find("\\x0F\\x05") != std::string::npos)
      return true;
    return false;
  }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM) {
    LLVMContext &Ctx = M.getContext();
    IRBuilder<> Builder(Ctx);

    // Types for the Policy Structure
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
              StringRef AsmStr = IA->getAsmString();
              // Detect inline 'syscall' or 'int $0x80' instructions
              if (AsmStr.contains("syscall") || AsmStr.contains("int $0x80") ||
                  AsmStr.contains("int $$0x80") || AsmStr.contains("svc #0") ||
                  AsmStr.contains("svc 0")) {
                IsSyscall = true;
              }
              // Detect obfuscated syscall: .byte 0x0f, 0x05 and variants
              if (!IsSyscall && containsObfuscatedSyscall(AsmStr)) {
                errs() << "[Sentinel] WARNING: Obfuscated syscall detected in "
                       << F.getName() << " via .byte encoding!\n";
                IsSyscall = true;
              }
            } else if (Function *CalledF = CI->getCalledFunction()) {
              if (isKnownSyscallWrapper(CalledF->getName()))
                IsSyscall = true;
            }
            // Also catch indirect calls through function pointers — mark them
            // for conservative policy. (Only if the call target is not resolved)
            // NOTE: We intentionally skip indirect calls for now to avoid
            // false positives. They should be handled in Phase 3.
          }

          if (IsSyscall) {
            Syscalls.push_back(&I);
          }
        }
      }
    }

    // 2. Instrument (Split Block + Create Label)
    bool Modified = !Syscalls.empty();

    // Collect external function imports for per-app libc filtering.
    // Any referenced declaration (external function) is an import —
    // covers direct calls AND address-taken function pointers.
    std::set<std::string> ExternalImports;
    for (auto &F : M) {
      if (F.isDeclaration() && F.hasName() && !F.use_empty()) {
        StringRef Name = F.getName();
        // Skip LLVM/compiler intrinsics (llvm.*, __cxa_*, __stack_chk_*)
        if (Name.starts_with("llvm."))
          continue;
        ExternalImports.insert(Name.str());
      }
    }

    // CFI entry tracking: {site_addr, func_start, func_size}
    struct CFIInfo {
      Constant *SiteLabel;
      Constant *FuncPtr;
      uint64_t FuncSize;
    };
    std::vector<CFIInfo> CFIEntries;

    for (Instruction *I : Syscalls) {
      BasicBlock *OldBB = I->getParent();
      Function *F = OldBB->getParent();

      // Split: NewBB starts EXACTLY at 'I' (the syscall/call instruction)
      // splitBasicBlock moves 'I' and subsequent instructions into NewBB.
      BasicBlock *NewBB = OldBB->splitBasicBlock(I, "sentinel_site");

      // Phase 3: Extract syscall number for this site
      int64_t SyscallNr = -1;
      if (auto *CI = dyn_cast<CallInst>(I)) {
        if (CI->isInlineAsm()) {
          SyscallNr = extractSyscallNumberFromAsm(CI);
        } else if (Function *CalledF = CI->getCalledFunction()) {
          SyscallNr = getSyscallNumberForWrapper(CalledF->getName());
        }
      }

      if (SyscallNr >= 0)
        errs() << "[Sentinel] Captured syscall site in " << F->getName()
               << " (nr=" << SyscallNr << ")\n";
      else
        errs() << "[Sentinel] Captured syscall site in " << F->getName()
               << " (nr=any)\n";

      // Create Entry: { BlockAddress, FuncAddress, EncodedSyscallNr }
      // Encoding: 0 = unspecified (any), >0 = (syscall_nr + 1)
      Constant *SiteLabel = BlockAddress::get(NewBB);

      Constant *FuncPtr = F;
      if (FuncPtr->getType() != VoidPtrTy)
        FuncPtr = ConstantExpr::getBitCast(FuncPtr, VoidPtrTy);

      int64_t EncodedNr = (SyscallNr >= 0) ? (SyscallNr + 1) : 0;
      Constant *NrConst = ConstantInt::get(Int64Ty, EncodedNr);

      Constant *Entry =
          ConstantStruct::get(PolicyEntryTy, {SiteLabel, FuncPtr, NrConst});
      PolicyEntries.push_back(Entry);

      // Collect CFI info: function size for generalized caller validation
      // The function size is available at IR level from the Function object.
      // We store {SiteLabel, FuncPtr, estimated_func_size} — the actual
      // size is finalized at link time, but IR-level instruction count
      // gives a useful upper bound scaled by avg instruction size.
      CFIEntries.push_back({SiteLabel, FuncPtr, 0}); // Size filled at link
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
    // 64 bytes for Ed25519 signature.
    ArrayType *SigType = ArrayType::get(Type::getInt8Ty(Ctx), 64);
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

    // 4. Emit .sentinel_imports — external function call list for per-app
    //    libc filtering. Format: null-terminated strings concatenated.
    //    Loader uses this to restrict libc whitelist to reachable functions.
    GlobalVariable *ImportsVar = nullptr;
    if (!ExternalImports.empty()) {
      std::string ImportBlob;
      for (const auto &Name : ExternalImports) {
        ImportBlob += Name;
        ImportBlob.push_back('\0');
      }

      Constant *ImportsInit = ConstantDataArray::getString(Ctx, ImportBlob,
                                                           false);
      ImportsVar = new GlobalVariable(M, ImportsInit->getType(), true,
                                      GlobalValue::ExternalLinkage,
                                      ImportsInit, "__sentinel_imports");
      ImportsVar->setSection(".sentinel_imports");
      ImportsVar->setAlignment(Align(1));

      Constant *ImportsCast =
          ConstantExpr::getBitCast(ImportsVar, PointerType::getUnqual(Ctx));
      UsedArray.push_back(ImportsCast);

      errs() << "[Sentinel] Emitted " << ExternalImports.size()
             << " external imports into .sentinel_imports section.\n";
    }

    // 5. Emit .sentinel_cfi — per-site caller ranges for generalized CFI.
    //    Format: array of { void *site, void *func_start, void *func_start }
    //    At runtime, the loader reads func symbol sizes from the ELF to
    //    compute [func_start, func_start+size) as the valid caller range.
    //    Here we store {site, func, func} as the linker resolves addresses.
    GlobalVariable *CfiVar = nullptr;
    if (!CFIEntries.empty()) {
      StructType *CfiEntryTy = StructType::create(Ctx, "struct.SentinelCFI");
      CfiEntryTy->setBody({VoidPtrTy, VoidPtrTy});

      std::vector<Constant *> CfiConsts;
      for (auto &E : CFIEntries) {
        Constant *FPtr = E.FuncPtr;
        if (FPtr->getType() != VoidPtrTy)
          FPtr = ConstantExpr::getBitCast(FPtr, VoidPtrTy);
        Constant *C = ConstantStruct::get(CfiEntryTy, {E.SiteLabel, FPtr});
        CfiConsts.push_back(C);
      }

      ArrayType *CfiArrTy = ArrayType::get(CfiEntryTy, CfiConsts.size());
      Constant *CfiInit = ConstantArray::get(CfiArrTy, CfiConsts);
      CfiVar = new GlobalVariable(M, CfiArrTy, true,
                                  GlobalValue::ExternalLinkage,
                                  CfiInit, "__sentinel_cfi");
      CfiVar->setSection(".sentinel_cfi");
      CfiVar->setAlignment(Align(16));

      Constant *CfiCast =
          ConstantExpr::getBitCast(CfiVar, PointerType::getUnqual(Ctx));
      UsedArray.push_back(CfiCast);

      errs() << "[Sentinel] Emitted " << CFIEntries.size()
             << " CFI entries into .sentinel_cfi section.\n";
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
