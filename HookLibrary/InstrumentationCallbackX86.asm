include CallConv.inc
.model flat

extern _InstrumentationCallback@8:near

.code
_InstrumentationCallbackAsm proc

	cmp eax, 0			; STATUS_SUCCESS
	jne ReturnToCaller

	pushad

	push eax
	push ecx
	call _InstrumentationCallback@8
	
	pop edi
	pop esi
	pop ebp
	add esp, 4
	pop ebx
	pop edx
	pop ecx
	add esp, 4 ; preserve new eax

ReturnToCaller:
	jmp ecx

_InstrumentationCallbackAsm endp

end
