	.file	"victim.c"
	.text
	.globl	safe_logger                     # -- Begin function safe_logger
	.p2align	4
	.type	safe_logger,@function
safe_logger:                            # @safe_logger
	.cfi_startproc
# %bb.0:
.Ltmp0:                                 # Block address taken
# %bb.1:
	leaq	.L.str(%rip), %rsi
	movl	$1, %eax
	movl	$1, %edi
	movl	$5, %edx
	#APP
	syscall
	#NO_APP
	retq
.Lfunc_end0:
	.size	safe_logger, .Lfunc_end0-safe_logger
	.cfi_endproc
                                        # -- End function
	.globl	unsafe                          # -- Begin function unsafe
	.p2align	4
	.type	unsafe,@function
unsafe:                                 # @unsafe
	.cfi_startproc
# %bb.0:
.Ltmp1:                                 # Block address taken
# %bb.1:
	leaq	.L.str.1(%rip), %rsi
	movl	$1, %eax
	movl	$1, %edi
	movl	$7, %edx
	#APP
	syscall
	#NO_APP
	retq
.Lfunc_end1:
	.size	unsafe, .Lfunc_end1-unsafe
	.cfi_endproc
                                        # -- End function
	.globl	main                            # -- Begin function main
	.p2align	4
	.type	main,@function
main:                                   # @main
	.cfi_startproc
# %bb.0:
	pushq	%rax
	.cfi_def_cfa_offset 16
	movq	__sentinel_signature@GOTPCREL(%rip), %rax
	#APP
	#NO_APP
	callq	safe_logger
	callq	unsafe
	xorl	%eax, %eax
	popq	%rcx
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end2:
	.size	main, .Lfunc_end2-main
	.cfi_endproc
                                        # -- End function
	.type	.L.str,@object                  # @.str
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
	.asciz	"SAFE\n"
	.size	.L.str, 6

	.type	.L.str.1,@object                # @.str.1
.L.str.1:
	.asciz	"UNSAFE\n"
	.size	.L.str.1, 8

	.type	__sentinel_policy,@object       # @__sentinel_policy
	.section	.sentinel,"aw",@progbits
	.globl	__sentinel_policy
	.p2align	4, 0x0
__sentinel_policy:
	.quad	.Ltmp0
	.quad	safe_logger
	.quad	0                               # 0x0
	.quad	.Ltmp1
	.quad	unsafe
	.quad	0                               # 0x0
	.size	__sentinel_policy, 48

	.type	__sentinel_signature.2,@object  # @__sentinel_signature.2
	.section	.signature,"awR",@progbits,unique,1
	.globl	__sentinel_signature.2
	.p2align	4, 0x0
__sentinel_signature.2:
	.zero	256
	.size	__sentinel_signature.2, 256

	.ident	"clang version 21.1.8 (Fedora 21.1.8-4.fc43)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
	.addrsig_sym safe_logger
	.addrsig_sym unsafe
	.addrsig_sym __sentinel_signature
	.addrsig_sym __sentinel_signature.2
