#pragma once

#include <ntdll/ntdll.h>

// Hackplementation of thread local storage without using the CRT or LdrpAllocateTls

static constexpr ULONG_PTR TebAllocationSize = (sizeof(TEB) + PAGE_SIZE - 1) & (~(PAGE_SIZE - 1));

#ifdef _WIN64
// On x64 we can freely write past the end of the TEB since 2 zeroed pages are allocated for it. Leave some headroom for the TEB to grow in future Windows versions
static constexpr LONG_PTR TebPadding = 0x200; // +512
#else
// On x86 and Wow64 we have a problem because sizeof(TEB) == PAGE_SIZE == TebAllocationSize, i.e. there are no spare zeroes past the end of the TEB, at least on Win 10.
// Instead abuse the SpareBytes field for this. Because (1) this field has a slightly different offset on different versions of Windows (+1AC for 7 vs +1B9 for 10),
// and (2) this field is not pointer-aligned, round the address up to pointer alignment. The offset is negative from the end since we are writing to the TEB, not past it
static constexpr LONG_PTR TebPaddingFromEnd = (static_cast<LONG_PTR>(TebAllocationSize) - FIELD_OFFSET(TEB, SpareBytes)); // 4096 - 441 = 3655
static constexpr LONG_PTR TebPadding = ((-1 * TebPaddingFromEnd) + static_cast<LONG_PTR>(alignof(PVOID)) - 1) & (~(static_cast<LONG_PTR>(alignof(PVOID)) - 1)); // ALIGN_UP(-1 * 3655, PVOID) = -3652
static_assert(TebPadding == -3652, "You touched ntdll.h didn't you?");
#endif

// To create a TLS variable, declare it here
enum class TlsVariable : ULONG_PTR
{
	InstrumentationCallbackDisabled, // The only TLS variable we currently actually use...
	MaxTlsVariable // Must be last
};

template<TlsVariable Variable>
struct TebOffset
{
	constexpr static ULONG_PTR Value = (static_cast<LONG_PTR>(sizeof(TEB)) + TebPadding) + (static_cast<ULONG_PTR>(Variable) * alignof(PVOID));
};

static_assert(TebOffset<TlsVariable::MaxTlsVariable>::Value <= TebAllocationSize - sizeof(PVOID), "TLS variable offsets exceed TEB allocation size");
static_assert(static_cast<ULONG_PTR>(TlsVariable::MaxTlsVariable) - 1 <= 5, "All out of TEB SpareBytes, find some new field to abuse"); // Only really applies to x86, but check on both

FORCEINLINE
volatile
LONG*
TlsGetInstrumentationCallbackDisabled(
	)
{
	return reinterpret_cast<volatile LONG*>(reinterpret_cast<ULONG_PTR>(NtCurrentTeb()) + TebOffset<TlsVariable::InstrumentationCallbackDisabled>::Value);
}
