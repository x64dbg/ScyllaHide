include ksamd64.inc

extern InstrumentationCallback:near

.code
InstrumentationCallbackAsm proc

	cmp eax, 0			; STATUS_SUCCESS
	jne ReturnToCaller

	push rax ; return value
	push rcx
	push rbx
	push rbp
	push rdi
	push rsi
	push rsp
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15

	sub rsp, 20h
	mov rcx, r10
	mov rdx, rax
	call InstrumentationCallback
	add rsp, 20h

	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop rsp
	pop rsi
	pop rdi
	pop rbp
	pop rbx
	pop rcx
	add rsp, 8 ; preserve new rax

ReturnToCaller:
	jmp r10

InstrumentationCallbackAsm endp

end
