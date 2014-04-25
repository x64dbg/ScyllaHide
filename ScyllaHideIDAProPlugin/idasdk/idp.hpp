/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2008 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _IDP_HPP
#define _IDP_HPP
#pragma pack(push, 1)           // IDA uses 1 byte alignments!

//
//      This file contains definition of the interface to IDP modules
//      The interface consists of 2 structures:
//        - definition of target assembler      name: ash
//        - definition of current processor     name: ph
//      These structures contain information about processor features,
//      function pointers, etc.

#include <fpro.h>
#include <nalt.hpp>
#include <segment.hpp>
#include <funcs.hpp>
#include <ua.hpp>
class member_t;                // #include <struct.hpp>
class mvm_t;                   // not used
typedef int help_t;

// The interface version number. It must match the version number on the
// IDA modules.

#define IDP_INTERFACE_VERSION 76        // This will not change anymore.
                                        // Use IDA_SDK_VERSION from pro.h

#define NEXTEAS_ANSWER_SIZE 32  // Size of the output array for calc_next_eas.
//-----------------------------------------------------------------------
// AbstractRegister and WorkReg are deprecated!
class WorkReg;

struct AbstractRegister
{
  virtual uval_t idaapi value(void) const = 0;
  virtual bool idaapi isDef(void) const = 0;
};

struct rginfo           // this structure is used only when detailed
{                       // information on processor register is needed.
                        // Actually is used only for 80x86 processors.
  AbstractRegister  *low;
  AbstractRegister *high;
  AbstractRegister *word;
};

//-----------------------------------------------------------------------
typedef struct          // structure used to describe byte streams
{                       // (for "ret" instruction and empirics)
  uchar len;
  uchar *bytes;
} bytes_t;


//-----------------------------------------------------------------------
//      keyword - keyword encoutered in IDA.CFG file
//                if NULL, then a dialog form should be displayed
//      value_type - type of value of the keyword
#define IDPOPT_STR 1    // string constant (char *)
#define IDPOPT_NUM 2    // number (uval_t *)
#define IDPOPT_BIT 3    // bit, yes/no (int *)
#define IDPOPT_FLT 4    // float (double *)
#define IDPOPT_I64 5    // 64bit number (int64 *)
//      value   - pointer to value
// returns:
#define IDPOPT_OK       NULL            // ok
#define IDPOPT_BADKEY   ((char*)1)      // illegal keyword
#define IDPOPT_BADTYPE  ((char*)2)      // illegal type of value
#define IDPOPT_BADVALUE ((char*)3)      // illegal value (bad range, for example)
//      otherwise return pointer to an error message
typedef const char *(idaapi set_options_t)(const char *keyword, int value_type,
                                            const void *value);

// Read any config file in the cfg subdirectory
idaman bool ida_export read_user_config_file(const char *file,
                                             set_options_t *callback,
                                             const char *macroname = NULL);

//-----------------------------------------------------------------------
// IDA uses internal representation of processor instructions.
// Definition of all internal instructions are kept in special arrays.
// One of such arrays describes instruction names are features.

struct instruc_t         // structure used in ins.cpp
{                        // names and features of all instructions
  const char *name;
  uint32 feature;
#define CF_STOP 0x00001  // Instruction doesn't pass execution to the
                         // next instruction
#define CF_CALL 0x00002  // CALL instruction (should make a procedure here)
#define CF_CHG1 0x00004  // The instruction modifies the first operand
#define CF_CHG2 0x00008  // The instruction modifies the second operand
#define CF_CHG3 0x00010  // The instruction modifies the third operand
#define CF_CHG4 0x00020  // The instruction modifies 4 operand
#define CF_CHG5 0x00040  // The instruction modifies 5 operand
#define CF_CHG6 0x00080  // The instruction modifies 6 operand
#define CF_USE1 0x00100  // The instruction uses value of the first operand
#define CF_USE2 0x00200  // The instruction uses value of the second operand
#define CF_USE3 0x00400  // The instruction uses value of the third operand
#define CF_USE4 0x00800  // The instruction uses value of the 4 operand
#define CF_USE5 0x01000  // The instruction uses value of the 5 operand
#define CF_USE6 0x02000  // The instruction uses value of the 6 operand
#define CF_JUMP 0x04000  // The instruction passes execution using indirect
                         // jump or call (thus needs additional analysis)
#define CF_SHFT 0x08000  // Bit-shift instruction (shl,shr...)
#define CF_HLL  0x10000  // Instruction may be present in a high level
                         // language function.
};

idaman bool ida_export InstrIsSet(int icode,int bit); // does the specified instruction
                                                      // have the specified feature?

idaman bool ida_export is_call_insn(ea_t ea);
idaman bool ida_export is_ret_insn(ea_t ea, bool strict=true);
idaman bool ida_export is_indirect_jump_insn(ea_t ea);
idaman bool ida_export is_basic_block_end(bool call_insn_stops_block); // in:cmd

//-----------------------------------------------------------------------
// Structures related to checkarg_dispatch()

// This structure is used as a parameter for chkarg_preline()
// It contains pointers to output buffers.
// All buffers are initialized with empty strings before
// calling chkarg_preline().
typedef struct
{
    char  *iaflg;   // flag of indirect addressing ([] in x86 or ()/@ in pdp11)
                    // This is not an array but a single byte.
                    // 0-no indirection, 1-operand uses indirection
    char  *prefix;  // place for all prefixes (near, far, word ptr, etc.)
    char  *seg;     // place for segment descriptor substring (e.g. 'es:')
    char  *reg;     // place for register's part (e.g. eax*8+edx)
    char  *offset;  // place for all others (label names, constant, etc.)
#define PRELINE_SIZE 100 // all output arrays are 100 bytes long
} s_preline;

#ifdef __BORLANDC__
#pragma option push -b-
#endif

// Operation binary codes
// The kernel replaces all operations in the operand by binary code
// from the following enumeration.
// The order of operations is FIXED!
enum ca_operation_t ENUM_SIZE(char) {
  ca_lev_on   = 020,  // (
  ca_lev_off  = 1,    // )
  ca_not      = 2,    // ~              (NOT in x86 assembler)
  ca_minus    = 3,    // -
  ca_plus     = 4,    // +
#define CA_PLUS_STR     "\4"
  ca_mod      = 5,    // %              (MOD in x86 assembler)
  ca_div_u    = 6,    // / (unsigned)   (not implemented in x86 assembler)
  ca_div      = 7,    // /
  ca_mul      = 010,  // *
  ca_and      = 011,  // &
  ca_or       = 012,  // |
  ca_xor      = 013,  // ^
  ca_shl      = 014,  // <<
  ca_shr      = 015,  // >>
        // end of current implementation of 'operdim' table
//  ca_RESERVED_1 = 016,
//  ca_RESERVED_2 = 017,
  ca_UN_MSK   = 020,
  ca_not_UN   = ca_UN_MSK | ca_not,     // 022
  ca_minus_UN = ca_UN_MSK | ca_minus,   // 023
  ca_h_delim  = 037,  // delimeter for holerite constant
};

// Command codes for ash.checkarg_dispatch()
enum _chkarg_cmd ENUM_SIZE(uchar) {
  chkarg_atomprefix = 1,   // Scan the operand for special prefixes like SEG, OFFSET, SIZE, etc.
                           // arguments: char **operand, char *flgoff
#define CA_PRF_NONE       0     // operand no have prefixes (unknown)
#define CA_PRF_SEG        -1    // is segment reference (x86: seg arg)
#define CA_PRF_OFFSET     1     // is offset to (x86: offset arg)
#define CA_PRF_SIZE       2     // request size of (x86: SIZE name)
  chkarg_preline    = 2,   // Parse operand string to and fill the s_preline structure
                           // arguments: char *operstr, s_preline *S
  chkarg_operseg    = 3,   // Get the default segment for the specified operand
                           // arguments: char *outseg, int opernum
  chkarg_cmpseg     = 4,   // Check if the selectors are interchangeable
                           // arguments: sel_t sel1, sel_t sel2
  chkarg_gettable   = 5    // Request the operation mnemonic table
                           // arguments: NULL, char * const **outptr
                           // This callback must be implemented
};

#ifdef __BORLANDC__
#pragma option pop
#endif

//=====================================================================
//
//      This structure describes the target assembler.
//      An IDP module may have several target assemblers.
//      In this case you should create a structure for each supported
//      assembler.
//
struct asm_t
{
  uint32 flag;                           // Assembler features:
#define AS_OFFST      0x00000001L       // offsets are 'offset xxx' ?
#define AS_COLON      0x00000002L       // create colons after data names ?
#define AS_UDATA      0x00000004L       // can use '?' in data directives

#define AS_2CHRE      0x00000008L       // double char constants are: "xy
#define AS_NCHRE      0x00000010L       // char constants are: 'x
#define AS_N2CHR      0x00000020L       // can't have 2 byte char consts

                                        // ASCII directives:
#define AS_1TEXT      0x00000040L       //   1 text per line, no bytes
#define AS_NHIAS      0x00000080L       //   no characters with high bit
#define AS_NCMAS      0x00000100L       //   no commas in ascii directives

#define AS_HEXFM      0x00000E00L       // format of hex numbers:
#define ASH_HEXF0     0x00000000L       //   34h
#define ASH_HEXF1     0x00000200L       //   h'34
#define ASH_HEXF2     0x00000400L       //   34
#define ASH_HEXF3     0x00000600L       //   0x34
#define ASH_HEXF4     0x00000800L       //   $34
#define ASH_HEXF5     0x00000A00L       //   <^R   > (radix)
#define AS_DECFM      0x00003000L       // format of dec numbers:
#define ASD_DECF0     0x00000000L       //   34
#define ASD_DECF1     0x00001000L       //   #34
#define ASD_DECF2     0x00002000L       //   34.
#define ASD_DECF3     0x00003000L       //   .34
#define AS_OCTFM      0x0001C000L       // format of octal numbers:
#define ASO_OCTF0     0x00000000L       //   123o
#define ASO_OCTF1     0x00004000L       //   0123
#define ASO_OCTF2     0x00008000L       //   123
#define ASO_OCTF3     0x0000C000L       //   @123
#define ASO_OCTF4     0x00010000L       //   o'123
#define ASO_OCTF5     0x00014000L       //   123q
#define ASO_OCTF6     0x00018000L       //   ~123
#define AS_BINFM      0x000E0000L       // format of binary numbers:
#define ASB_BINF0     0x00000000L       //   010101b
#define ASB_BINF1     0x00020000L       //   ^B010101
#define ASB_BINF2     0x00040000L       //   %010101
#define ASB_BINF3     0x00060000L       //   0b1010101
#define ASB_BINF4     0x00080000L       //   b'1010101
#define ASB_BINF5     0x000A0000L       //   b'1010101'

#define AS_UNEQU      0x00100000L       // replace undefined data items
                                        // with EQU (for ANTA's A80)
#define AS_ONEDUP     0x00200000L       // One array definition per line
#define AS_NOXRF      0x00400000L       // Disable xrefs during the output file generation
#define AS_XTRNTYPE   0x00800000L       // Assembler understands type of extrn
                                        // symbols as ":type" suffix
#define AS_RELSUP     0x01000000L       // Checkarg: 'and','or','xor' operations
                                        // with addresses are possible
#define AS_LALIGN     0x02000000L       // Labels at "align" keyword
                                        // are supported.
#define AS_NOCODECLN  0x04000000L       // don't create colons after code names
#define AS_NOTAB      0x08000000L       // Disable tabulation symbols during the output file generation
#define AS_NOSPACE    0x10000000L       // No spaces in expressions
#define AS_ALIGN2     0x20000000L       // .align directive expects an exponent rather than a power of 2
                                        // (.align 5 means to align at 32byte boundary)
#define AS_ASCIIC     0x40000000L       // ascii directive accepts C-like
                                        // escape sequences (\n,\x01 and similar)
#define AS_ASCIIZ     0x80000000L       // ascii directive inserts implicit
                                        // zero byte at the end

  uint16 uflag;                         // user defined flags (local only for IDP)
                                        // you may define and use your own bits
  const char *name;                     // Assembler name (displayed in menus)
  help_t help;                          // Help screen number, 0 - no help
  const char **header;                  // array of automatically generated header lines
                                        // they appear at the start of disassembled text
  const uint16 *badworks;               // array of unsupported instructions
                                        // (array of cmd.itype, zero terminated)
  const char *origin;                   // org directive
  const char *end;                      // end directive
  const char *cmnt;                     // comment string (see also cmnt2)
  char ascsep;                          // ASCII string delimiter
  char accsep;                          // ASCII char constant delimiter
  const char *esccodes;                 // ASCII special chars
                                        // (they can't appear in character and
                                        // ascii constants)
//
//      Data representation (db,dw,...):
//
  const char *a_ascii;                  // ASCII string directive
  const char *a_byte;                   // byte directive
  const char *a_word;                   // word directive
  const char *a_dword;                  // NULL if not allowed
  const char *a_qword;                  // NULL if not allowed
  const char *a_oword;                  // NULL if not allowed
  const char *a_float;                  // float;  4bytes; NULL if not allowed
  const char *a_double;                 // double; 8bytes; NULL if not allowed
  const char *a_tbyte;                  // long double;    NULL if not allowed
  const char *a_packreal;               // packed decimal real NULL if not allowed
  const char *a_dups;                   // array keyword. the following
                                        // sequences may appear:
                                        //      #h - header
                                        //      #d - size
                                        //      #v - value
                                        //      #s(b,w,l,q,f,d,o) - size specifiers
                                        //                        for byte,word,
                                        //                            dword,qword,
                                        //                            float,double,oword
  const char *a_bss;                    // uninitialized data directive
                                        // should include '%s' for the
                                        // size of data
  const char *a_equ;                    // 'equ' Used if AS_UNEQU is set
  const char *a_seg;                    // 'seg ' prefix (example: push seg seg001)

//
//  Pointer to checkarg_dispatch() function. If NULL, checkarg won't be called.
//
  bool (idaapi* checkarg_dispatch)(void *a1, void *a2, uchar cmd);
  void *_UNUSED1_was_atomprefix;
  void *_UNUSED2_was_checkarg_operations;

//
// translation to use in character and string constants.
// usually 1:1, i.e. trivial translation (may specify NULL)
//
  const uchar *XlatAsciiOutput;         // If specified, must be 256 chars long
  const char *a_curip;                  // current IP (instruction pointer)
                                        // symbol in assembler
  void (idaapi *func_header)(func_t *); // generate function header lines
                                        // if NULL, then function headers
                                        // are displayed as normal lines
  void (idaapi *func_footer)(func_t *); // generate function footer lines
                                        // if NULL, then a comment line
                                        // is displayed
  const char *a_public;                 // "public" name keyword. NULL-gen default, ""-do not generate
  const char *a_weak;                   // "weak"   name keyword. NULL-gen default, ""-do not generate
  const char *a_extrn;                  // "extrn"  name keyword
  const char *a_comdef;                 // "comm" (communal variable)
//
// Get name of type of item at ea or id.
// (i.e. one of: byte,word,dword,near,far,etc...)
//
  ssize_t (idaapi *get_type_name)(flags_t flag,
                                  ea_t ea_or_id,
                                  char *buf,
                                  size_t bufsize);

  const char *a_align;                  // "align" keyword

// Left and right braces used in complex expressions

  char lbrace;
  char rbrace;

  const char *a_mod;    // %  mod     assembler time operation
  const char *a_band;   // &  bit and assembler time operation
  const char *a_bor;    // |  bit or  assembler time operation
  const char *a_xor;    // ^  bit xor assembler time operation
  const char *a_bnot;   // ~  bit not assembler time operation
  const char *a_shl;    // << shift left assembler time operation
  const char *a_shr;    // >> shift right assembler time operation
  const char *a_sizeof_fmt; // size of type (format string)

  uint32 flag2;
#define AS2_BRACE     0x00000001        // Use braces for all expressions
#define AS2_STRINV    0x00000002        // For processors with bytes bigger than 8 bits:
                                        //  invert the meaning of inf.wide_high_byte_first
                                        //  for text strings
#define AS2_BYTE1CHAR 0x00000004        // One symbol per processor byte
                                        // Meaningful only for wide byte processors
#define AS2_IDEALDSCR 0x00000008        // Description of struc/union is in
                                        // the 'reverse' form (keyword before name)
                                        // the same as in borland tasm ideal
#define AS2_TERSESTR  0x00000010        // 'terse' structure initialization form
                                        // NAME<fld,fld,...> is supported
#define AS2_COLONSUF  0x00000020        // addresses may have ":xx" suffix
                                        // this suffix must be ignored when extracting
                                        // the address under the cursor
  const char *cmnt2;                    // comment close string (usually NULL)
                                        // this is used to denote a string which
                                        // closes comments, for example, if the
                                        // comments are represented with (* ... *)
                                        // then cmnt = "(*" and cmnt2 = "*)"
  const char *low8;     // low8 operation, should contain %s for the operand
  const char *high8;    // high8
  const char *low16;    // low16
  const char *high16;   // high16
  const char *a_include_fmt;            // the include directive (format string)
  const char *a_vstruc_fmt;             // if a named item is a structure and displayed
                                        // in the verbose (multiline) form then display the name
                                        // as printf(a_strucname_fmt, typename)
                                        // (for asms with type checking, e.g. tasm ideal)
  const char *a_3byte;                  // 3-byte data
  const char *a_rva;                    // 'rva' keyword for image based offsets
                                        // (see nalt.hpp, REFINFO_RVA)
};

#ifdef NO_OBSOLETE_FUNCS
#define OBSOLETE(event) obsolete_ ## event
#else
#define OBSOLETE(event) event
#endif
//=====================================================================
//
//      This structure describes a processor module (IDP)
//      An IDP file may have only one such structure called LPH.
//      The kernel will copy it to 'ph' structure and use 'ph'.
//

struct processor_t
{
  int version;                  // Expected kernel version,
                                //   should be IDP_INTERFACE_VERSION
  int id;                       // IDP id
#define PLFM_386        0       // Intel 80x86
#define PLFM_Z80        1       // 8085, Z80
#define PLFM_I860       2       // Intel 860
#define PLFM_8051       3       // 8051
#define PLFM_TMS        4       // Texas Instruments TMS320C5x
#define PLFM_6502       5       // 6502
#define PLFM_PDP        6       // PDP11
#define PLFM_68K        7       // Motoroal 680x0
#define PLFM_JAVA       8       // Java
#define PLFM_6800       9       // Motorola 68xx
#define PLFM_ST7        10      // SGS-Thomson ST7
#define PLFM_MC6812     11      // Motorola 68HC12
#define PLFM_MIPS       12      // MIPS
#define PLFM_ARM        13      // Advanced RISC Machines
#define PLFM_TMSC6      14      // Texas Instruments TMS320C6x
#define PLFM_PPC        15      // PowerPC
#define PLFM_80196      16      // Intel 80196
#define PLFM_Z8         17      // Z8
#define PLFM_SH         18      // Renesas (formerly Hitachi) SuperH
#define PLFM_NET        19      // Microsoft Visual Studio.Net
#define PLFM_AVR        20      // Atmel 8-bit RISC processor(s)
#define PLFM_H8         21      // Hitachi H8/300, H8/2000
#define PLFM_PIC        22      // Microchip's PIC
#define PLFM_SPARC      23      // SPARC
#define PLFM_ALPHA      24      // DEC Alpha
#define PLFM_HPPA       25      // Hewlett-Packard PA-RISC
#define PLFM_H8500      26      // Hitachi H8/500
#define PLFM_TRICORE    27      // Tasking Tricore
#define PLFM_DSP56K     28      // Motorola DSP5600x
#define PLFM_C166       29      // Siemens C166 family
#define PLFM_ST20       30      // SGS-Thomson ST20
#define PLFM_IA64       31      // Intel Itanium IA64
#define PLFM_I960       32      // Intel 960
#define PLFM_F2MC       33      // Fujistu F2MC-16
#define PLFM_TMS320C54  34      // Texas Instruments TMS320C54xx
#define PLFM_TMS320C55  35      // Texas Instruments TMS320C55xx
#define PLFM_TRIMEDIA   36      // Trimedia
#define PLFM_M32R       37      // Mitsubishi 32bit RISC
#define PLFM_NEC_78K0   38      // NEC 78K0
#define PLFM_NEC_78K0S  39      // NEC 78K0S
#define PLFM_M740       40      // Mitsubishi 8bit
#define PLFM_M7700      41      // Mitsubishi 16bit
#define PLFM_ST9        42      // ST9+
#define PLFM_FR         43      // Fujitsu FR Family
#define PLFM_MC6816     44      // Motorola 68HC16
#define PLFM_M7900      45      // Mitsubishi 7900
#define PLFM_TMS320C3   46      // Texas Instruments TMS320C3
#define PLFM_KR1878     47      // Angstrem KR1878
#define PLFM_AD218X     48      // Analog Devices ADSP 218X
#define PLFM_OAKDSP     49      // Atmel OAK DSP
#define PLFM_TLCS900    50      // Toshiba TLCS-900
#define PLFM_C39        51      // Rockwell C39
#define PLFM_CR16       52      // NSC CR16
#define PLFM_MN102L00   53      // Panasonic MN10200
#define PLFM_TMS320C1X  54      // Texas Instruments TMS320C1x
#define PLFM_NEC_V850X  55      // NEC V850 and V850ES/E1/E2
#define PLFM_SCR_ADPT   56      // Processor module adapter for processor modules written in scripting languages
#define PLFM_EBC        57      // EFI Bytecode
#define PLFM_MSP430     58      // Texas Instruments MSP430
#define PLFM_SPU        59      // Cell Broadband Engine Synergistic Processor Unit
#define PLFM_DALVIK     60      // Android Dalvik Virtual Machine
#define PLFM_65C816     61      // 65802/65816
#define PLFM_M16C       62      // Renesas M16C

                                // Numbers above 0x8000 are reserved
                                // for the third-party modules

  uint32 flag;                  // Processor features
#define PR_SEGS       0x000001  // has segment registers?
#define PR_USE32      0x000002  // supports 32-bit addressing?
#define PR_DEFSEG32   0x000004  // segments are 32-bit by default
#define PR_RNAMESOK   0x000008  // allow to user register names for
                                // location names
//#define PR_DB2CSEG    0x0010  // .byte directive in code segments
//                              // should define even number of bytes
//                              // (used by AVR processor)
#define PR_ADJSEGS    0x000020  // IDA may adjust segments moving
                                // their starting/ending addresses.
#define PR_DEFNUM     0x0000C0  // default number representation:
#define PRN_HEX       0x000000  //      hex
#define PRN_OCT       0x000040  //      octal
#define PRN_DEC       0x000080  //      decimal
#define PRN_BIN       0x0000C0  //      binary
#define PR_WORD_INS   0x000100  // instruction codes are grouped
                                // 2bytes in binrary line prefix
#define PR_NOCHANGE   0x000200  // The user can't change segments
                                // and code/data attributes
                                // (display only)
#define PR_ASSEMBLE   0x000400  // Module has a built-in assembler
                                // and understands IDP_ASSEMBLE
#define PR_ALIGN      0x000800  // All data items should be aligned
                                // properly
#define PR_TYPEINFO   0x001000  // the processor module supports
                                // type information callbacks
                                // ALL OF THEM SHOULD BE IMPLEMENTED!
                                // (the ones >= decorate_name)
#define PR_USE64      0x002000  // supports 64-bit addressing?
#define PR_SGROTHER   0x004000  // the segment registers don't contain
                                // the segment selectors, something else
#define PR_STACK_UP   0x008000  // the stack grows up
#define PR_BINMEM     0x010000  // the processor module provides correct
                                // segmentation for binary files
                                // (i.e. it creates additional segments)
                                // The kernel will not ask the user
                                // to specify the RAM/ROM sizes
#define PR_SEGTRANS   0x020000  // the processor module supports
                                // the segment translation feature
                                // (it means it calculates the code
                                // addresses using the codeSeg() function)
#define PR_CHK_XREF   0x040000  // don't allow near xrefs between segments
                                // with different bases
#define PR_NO_SEGMOVE 0x080000  // the processor module doesn't support move_segm()
                                // (i.e. the user can't move segments)
#define PR_FULL_HIFXP 0x100000  // REF_VHIGH operand value contains full operand
                                // not only the high bits. Meaningful if ph.high_fixup_bits
#define PR_USE_ARG_TYPES 0x200000 // use ph.use_arg_types callback
#define PR_SCALE_STKVARS 0x400000 // use ph.get_stkvar_scale callback
#define PR_DELAYED    0x800000 // has delayed jumps and calls
#define PR_ALIGN_INSN 0x1000000 // allow ida to create alignment instructions
                                // arbirtrarily. Since these instructions
                                // might lead to other wrong instructions
                                // and spoil the listing, IDA does not create
                                // them by default anymore
#define PR_PURGING    0x2000000 // there are calling conventions which may
                                // purge bytes from the stack
#define PR_CNDINSNS   0x4000000 // has conditional instructions
#define PR_USE_TBYTE  0x8000000 // BTMT_SPECFLT means _TBYTE type
#define PR_DEFSEG64  0x10000000 // segments are 64-bit by default
  bool has_segregs(void) const  { return (flag & PR_SEGS)     != 0; }
  bool use32(void) const        { return (flag & (PR_USE64|PR_USE32)) != 0; }
  bool use64(void) const        { return (flag & PR_USE64)    != 0; }
  bool ti(void) const           { return (flag & PR_TYPEINFO) != 0; }
  bool stkup(void) const        { return (flag & PR_STACK_UP) != 0; }
  bool use_tbyte(void) const    { return (flag & PR_USE_TBYTE) != 0; }
  int get_segm_bitness(void) const { return (flag & PR_DEFSEG64) != 0 ? 2 : (flag & PR_DEFSEG32) != 0; }

  int cnbits;                           // Number of bits in a byte
                                        // for code segments (usually 8)
                                        // IDA supports values up to 32 bits
  int dnbits;                           // Number of bits in a byte
                                        // for non-code segments (usually 8)
                                        // IDA supports values up to 32 bits
//
// Number of 8bit bytes required to hold one byte of the target processor
//
  int cbsize(void) { return (cnbits+7)/8; }     // for code segments
  int dbsize(void) { return (dnbits+7)/8; }     // for other segments

                                        // IDP module may support several compatible
                                        // processors. The following arrays define
                                        // processor names:
  const char **psnames;                 // short processor names (NULL terminated)
                                        // Each name should be shorter than 9 characters
  const char **plnames;                 // long processor names (NULL terminated)
                                        // No restriction on name lengths.
  asm_t **assemblers;                   // pointer to array of target
                                        // assembler definitions. You may
                                        // change this array when current
                                        // processor is changed.
                                        // (NULL terminated)

// Custom instruction codes defined by processor extension plugins
// must be greater than or equal to this:

#define CUSTOM_CMD_ITYPE 0x8000


// use_regarg_type (see below) uses this bit in the return value
// to indicate that the register value has been spoiled

#define REG_SPOIL 0x80000000L


//
// Subtypes in callback custom_fixup
//
  enum cust_fix
  {
      cf_base,                 // Get fixup base
                               // args: ea_t *answer
      cf_size,                 // Get fixup size
                               // args: int *answer
                               // return 2 if *answer has been filled
      cf_desc,                 // Describe fixup
                               // args: char *buf, size_t bufsize
                               // return 2 if buf has been filled
      cf_apply,                // Apply a fixup
                               // args: ea_t item_start, int opnum
                               // return 2 if fixup has been applied to the database
      cf_move,                 // Relocate the fixup
                               // may be called from loader_t.move_segm()
                               // args: adiff_t delta
                               // return: nothing
  };

//
// Callback function. IDP module can take appropriate
// actions when some events occurs in the kernel.
//
  enum idp_notify
  {
        init,                   // The IDP module is just loaded
                                // arg - const char *idp_modname
                                //       processor module name
                                // Processor modules should return zero to indicate failure
        term,                   // The IDP module is being unloaded
        newprc,                 // Before changing proccesor type
                                // arg - int processor number in the
                                //       array of processor names
                                // return 1-ok,0-prohibit
        newasm,                 // Before setting a new assembler
                                // arg = int asmnum
        newfile,                // A new file is loaded (already)
                                // arg - char * input file name
        oldfile,                // An old file is loaded (already)
                                // arg - char * input file name
        newbinary,              // Before loading a binary file
                                // args:
                                //  char *filename - binary file name
                                //  uint32 fileoff  - offset in the file
                                //  ea_t basepara  - base loading paragraph
                                //  ea_t binoff    - loader offset
                                //  uint32 nbytes   - number of bytes to load
        endbinary,              // After loading a binary file
                                //  bool ok        - file loaded successfully?
        newseg,                 // A new segment is about to be created
                                // arg = segment_t *
                                // return 1-ok, 0-segment should not be created
        assemble,               // Assemble an instruction
                                // (display a warning if an error is found)
                                // args:
                                //  ea_t ea -  linear address of instruction
                                //  ea_t cs -  cs of instruction
                                //  ea_t ip -  ip of instruction
                                //  bool use32 - is 32bit segment?
                                //  const char *line - line to assemble
                                //  uchar *bin - pointer to output opcode buffer
                                // returns size of the instruction in bytes
        obsolete_makemicro,     // Generate microcode for the instruction
                                // in 'cmd' structure.
                                // arg - mblock_t *
                                // returns MICRO_... error codes
        outlabel,               // The kernel is going to generate an instruction
                                // label line or a function header
                                // args:
                                //   ea_t ea -
                                //   const char *colored_name -
                                // If returns value <=0, then the kernel should
                                // not generate the label
        rename,                 // The kernel is going to rename a byte
                                // args:
                                //   ea_t ea
                                //   const char *new_name
                                // If returns value <=0, then the kernel should
                                // not rename it. See also the 'renamed' event
        may_show_sreg,          // The kernel wants to display the segment registers
                                // in the messages window.
                                // arg - ea_t current_ea
                                // if this function returns 0
                                // then the kernel will not show
                                // the segment registers.
                                // (assuming that the module have done it)
        closebase,              // The database will be closed now
        load_idasgn,            // FLIRT signature have been loaded
                                // for normal processing (not for
                                // recognition of startup sequences)
                                // arg - const char *short_sig_name
                                // returns: nothing
        coagulate,              // Try to define some unexplored bytes
                                // This notification will be called if the
                                // kernel tried all possibilities and could
                                // not find anything more useful than to
                                // convert to array of bytes.
                                // The module can help the kernel and convert
                                // the bytes into something more useful.
                                // arg:
                                //      ea_t start_ea
                                // returns: number of converted bytes + 1
        auto_empty,             // Info: all analysis queues are empty
                                // args: none
                                // returns: none
                                // This callback is called once when the
                                // initial analysis is finished. If the queue is
                                // not empty upon the return from this callback,
                                // it will be called later again.
                                // See also auto_empty_finally.
        auto_queue_empty,       // One analysis queue is empty
                                // args: atype_t type
                                // returns: 1-yes, keep the queue empty
                                //        <=0-no, the queue is not empty anymore
                                // This callback can be called many times, so
                                // only the autoMark() functions can be used from it
                                // (other functions may work but it is not tested)
        func_bounds,            // find_func_bounds() finished its work
                                // The module may fine tune the function bounds
                                // args: int *possible_return_code
                                //       func_t *pfn
                                //       ea_t max_func_end_ea (from the kernel's point of view)
                                // returns: none
        may_be_func,            // can a function start here?
                                // the instruction is in 'cmd'
                                // arg: int state -- autoanalysis phase
                                //   state == 0: creating functions
                                //         == 1: creating chunks
                                // returns: probability 0..100
                                // the idp module is allowed to modify 'cmd'
        is_sane_insn,           // is the instruction sane for the current file type?
                                // arg:  int no_crefs
                                // 1: the instruction has no code refs to it.
                                //    ida just tries to convert unexplored bytes
                                //    to an instruction (but there is no other
                                //    reason to convert them into an instruction)
                                // 0: the instruction is created because
                                //    of some coderef, user request or another
                                //    weighty reason.
                                // The instruction is in 'cmd'
                                // returns: 1-ok, <=0-no, the instruction isn't
                                // likely to appear in the program
        is_jump_func,           // is the function a trivial "jump" function?
                                // args:  func_t *pfn
                                //        ea_t *jump_target
                                //        ea_t *func_pointer
                                // returns: 0-no, 1-don't know, 2-yes, see jump_target
                                // and func_pointer
        gen_regvar_def,         // generate register variable definition line
                                // args:  regvar_t *v
                                // returns: 0-ok
        setsgr,                 // The kernel has changed a segment register value
                                // args:  ea_t startEA
                                //        ea_t endEA
                                //        int regnum
                                //        sel_t value
                                //        sel_t old_value
                                //        uchar tag (SR_... values)
                                // returns: 1-ok, 0-error
        set_compiler,           // The kernel has changed the compiler information
                                // (inf.cc structure)
        is_basic_block_end,     // Is the current instruction end of a basic block?
                                // This function should be defined for processors
                                // with delayed jump slots. The current instruction
                                // is stored in 'cmd'
                                // args:  bool call_insn_stops_block
                                // returns: 1-unknown, 0-no, 2-yes
        reglink,                // IBM PC only, ignore it
        get_vxd_name,           // IBM PC only, ignore it
                                // Get Vxd function name
                                // args: int vxdnum
                                //       int funcnum
                                //       char *outbuf
                                // returns: nothing

                                // PROCESSOR EXTENSION NOTIFICATIONS
                                // They are used to add support of new instructions
                                // to the existing processor modules.
                                // They should be processed only in notification callbacks
                                // set by hook_to_notification_point(HK_IDP,...)
        custom_ana,             // args: none, the address to analyze is in cmd.ea
                                //   cmd.ip and cmd.cs are initialized too
                                //   cmd.itype must be set >= 0x8000
                                //   cmd.size must be set to the instruction length
                                //   (good plugin would fill the whole 'cmd' including the operand fields)
                                //   in the case of error the cmd structure should be kept intact
                                // returns: 1+cmd.size
        custom_out,             // args: none (cmd structure contains information about the instruction)
                                //   optional notification
                                //   (depends on the processor module)
                                //   generates the instruction text using
                                //   the printf_line() function
                                // returns: 2
        custom_emu,             // args: none (cmd structure contains information about the instruction)
                                //   optional notification. if absent,
                                //   the instruction is supposed to be an regular one
                                //   the kernel will proceed to the analysis of the next instruction
                                // returns: 2
        custom_outop,           // args: op_t *op
                                //   optional notification to generate operand text. if absent,
                                //   the standard operand output function will be called.
                                //   the output buffer is inited with init_output_buffer()
                                //   and this notification may use out_...() functions from ua.hpp
                                //   to form the operand text
                                // returns: 2
        custom_mnem,            // args: char *outbuffer, size_t bufsize (cmd structure contains information about the instruction)
                                //   optional notification. if absent,
                                //   the IDC function GetMnem() won't work
                                // returns: 2
                                // At least one of custom_out or custom_mnem
                                // should be implemented. custom_ana should always be
                                // implemented. These custom_... callbacks will be
                                // called for all instructions. It is the responsability
                                // of the plugin to ignore the undesired callbacks
                                // END OF PROCESSOR EXTENSION NOTIFICATIONS

        undefine,               // An item in the database (insn or data) is being deleted
                                // args: ea_t ea
                                // returns: >0-ok, <=0-the kernel should stop
                                // if the return value is positive:
                                //   bit0 - ignored
                                //   bit1 - do not delete srareas at the item end
        make_code,              // An instruction is being created
                                // args: ea_t ea, asize_t size
                                // returns: 1-ok, <=0-the kernel should stop
        make_data,              // A data item is being created
                                // args: ea_t ea, flags_t flags, tid_t tid, asize_t len
                                // returns: 1-ok, <=0-the kernel should stop

        moving_segm,            // May the kernel move the segment?
                                // args: segment_t - segment to move
                                //       ea_t to   - new segment start address
                                //       int flags - combination of MSF_... bits
                                // returns: 1-yes, <=0-the kernel should stop
        move_segm,              // A segment is moved
                                // Fix processor dependent address sensitive information
                                // args: ea_t from  - old segment address
                                //       segment_t* - moved segment
                                // returns: nothing

        is_call_insn,           // Is the instruction a "call"?
                                // ea_t ea  - instruction address
                                // returns: 1-unknown, 0-no, 2-yes

        is_ret_insn,            // Is the instruction a "return"?
                                // ea_t ea  - instruction address
                                // bool strict - 1: report only ret instructions
                                //               0: include instructions like "leave"
                                //                  which begins the function epilog
                                // returns: 1-unknown, 0-no, 2-yes

        get_stkvar_scale_factor,// Should stack variable references be multiplied by
                                // a coefficient before being used in the stack frame?
                                // Currently used by TMS320C55 because the references into
                                // the stack should be multiplied by 2
                                // Returns: scaling factor
                                // Note: PR_SCALE_STKVARS should be set to use this callback

        create_flat_group,      // Create special segment representing the flat group
                                // (to use for PC mainly)
                                // args - ea_t image_base, int bitness, sel_t dataseg_sel

        kernel_config_loaded,   // This callback is called when ida.cfg is parsed
                                // args - none, returns - nothing

        might_change_sp,        // Does the instruction at 'ea' modify the stack pointer?
                                // args: ea_t ea
                                // returns: 1-yes, 0-false
                                // (not used yet)

        is_alloca_probe,        // Does the function at 'ea' behave as __alloca_probe?
                                // args: ea_t ea
                                // returns: 2-yes, 1-false

        out_3byte,              // Generate text representation of 3byte data
                                // init_out_buffer() is called before this function
                                // and all Out... function can be used.
                                // uFlag contains the flags.
                                // This callback might be implemented by the processor
                                // module to generate custom representation of 3byte data.
                                // args:
                                // ea_t dataea - address of the data item
                                // uint32 value - value to output
                                // bool analyze_only - only create xrefs if necessary
                                //              do not generate text representation
                                // returns: 2-yes, 1-false

        get_reg_name,           // Generate text representation of a register
                                // int reg        - internal register number as defined in the processor module
                                // size_t width   - register width in bytes
                                // char *buf      - output buffer
                                // size_t bufsize - size of output buffer
                                // int reghi      - if not -1 then this function will return the register pair
                                // returns: -1 if error, strlen(buf)+2 otherwise
                                // Most processor modules do not need to implement this callback
                                // It is useful only if ph.regNames[reg] does not provide
                                // the correct register names
        savebase,               // The database is being saved. Processor module should
                                // save its local data
        gen_asm_or_lst,         // Callback: generating asm or lst file
                                // The kernel calls this callback twice, at the beginning
                                // and at the end of listing generation. Processor
                                // module can intercept this event and adjust its output
                                // bool starting - beginning listing generation
                                // FILE *fp      - output file
                                // bool is_asm   - true:assembler, false:listing
                                // int flags     - flags passed to gen_file()
                                // gen_outline_t **outline - ptr to ptr to outline callback
                                // the outline callback, if defined by gen_asm_or_lst,
                                // will be used by the kernel to output the generated lines
                                // returns: nothing
        out_src_file_lnnum,     // Callback: generate analog of
                                //   #line "file.c" 123
                                // directive.
                                // const char *file - source file (may be NULL)
                                // size_t lnnum     - line number
                                // returns: 2-directive has been generated
        get_autocmt,            // Callback: get dynamic auto comment
                                // Will be called if the autocomments are enabled
                                // and the comment retrieved from ida.int starts with
                                // '$!'. 'cmd' contains valid info.
                                // char *buf  - output buffer
                                // size_t bufsize - output buffer size
                                // returns: 2-new comment has been generated
                                //          1-callback has not been handled
                                //            the buffer must not be changed in this case
        is_insn_table_jump,     // Callback: determine if instruction is a table jump or call
                                // If CF_JUMP bit can not describe all kinds of table
                                // jumps, please define this callback.
                                // It will be called for insns with CF_JUMP bit set.
                                // input: cmd structure contains the current instruction
                                // returns: 1-yes, 0-no
        auto_empty_finally,     // Info: all analysis queues are empty definitively
                                // args: none
                                // returns: none
                                // This callback is called only once.
                                // See also auto_empty.
        loader_finished,        // Event: external file loader finished its work
                                // linput_t *li
                                // uint16 neflags
                                // const char *filetypename
                                // Use this event to augment the existing loader functionality
        loader_elf_machine,     // Event: ELF loader machine type checkpoint
                                // linput_t *li
                                // int machine_type
                                // const char **p_procname
                                // proc_def **p_pd (see ldr\elf.h)
                                // set_elf_reloc_t *set_reloc
                                // A plugin check the machine_type. If it is the desired one,
                                // the the plugin fills p_procname with the processor name.
                                // p_pd is used to handle relocations, otherwise can be left untouched
                                // set_reloc can be later used by the plugin to specify relocations
                                // returns: e_machine value (if it is different from the
                                // original e_machine value, procname and p_pd will be ignored
                                // and the new value will be used)
                                // This event occurs for each loaded ELF file
        is_indirect_jump,       // Callback: determine if instruction is an indrect jump
                                // If CF_JUMP bit can not describe all jump types
                                // jumps, please define this callback.
                                // input: cmd structure contains the current instruction
                                // returns: 1-use CF_JUMP, 2-no, 3-yes
        verify_noreturn,        // The kernel wants to set 'noreturn' flags for a function
                                // func_t *pfn
                                // Returns: 1-ok, any other value-do not set 'noreturn' flag
        verify_sp,              // All function instructions have been analyzed
                                // Now the processor module can analyze the stack pointer
                                // for the whole function
                                // input: func_t *pfn
                                // Returns: 1-ok, 0-bad stack pointer
        renamed,                // The kernel has renamed a byte
                                // args:
                                //   ea_t ea
                                //   const char *new_name
                                //   bool local_name
                                // Returns: nothing. See also the 'rename' event
        add_func,               // The kernel has added a function
                                // args: func_t *pfn
                                // Returns: nothing
        del_func,               // The kernel is about to delete a function
                                // args: func_t *pfn
                                // Returns: 1-ok,<=0-do not delete
        set_func_start,         // Function chunk start address will be changed
                                // args: func_t *pfn
                                //       ea_t new_start
                                // Returns: 1-ok,<=0-do not change
        set_func_end,           // Function chunk end address will be changed
                                // args: func_t *pfn
                                //       ea_t new_end
                                // Returns: 1-ok,<=0-do not change
        treat_hindering_item,   // An item hinders creation of another item
                                // args: ea_t hindering_item_ea
                                //       flags_t new_item_flags (0 for code)
                                //       ea_t new_item_ea
                                //       asize_t new_item_length
                                // Returns: 1-no reaction, <=0-the kernel may delete the hindering item
        str2reg,                // Convert a register name to a register number
                                // args: const char *regname
                                // Returns: register number + 2
                                // The register number is the register index in the regNames array
                                // Most processor modules do not need to implement this callback
                                // It is useful only if ph.regNames[reg] does not provide
                                // the correct register names
        create_switch_xrefs,    // Create xrefs for a custom jump table
                                // in: ea_t jumpea;        - address of the jump insn
                                //     switch_info_ex_t *; - switch information
                                // returns: must return 2
        calc_switch_cases,      // Calculate case values and targets for a custom jump table
                                // in:  ea_t insn_ea - address of the 'indirect jump' instruction
                                //      switch_info_ex_t *si      - switch information
                                //      casevec_t *casevec - vector of case values...
                                //      evec_t *targets - ...and corresponding target addresses
                                // casevec and targets may be NULL
                                // returns: 2-ok, 1-failed
        determined_main,        // The main() function has been determined
                                // in:  ea_t main - address of the main() function
                                // returns: none
        preprocess_chart,       // gui has retrieved a function flow chart
                                // in: qflow_chart_t *fc
                                // returns: none
                                // Plugins may modify the flow chart in this callback
        get_bg_color,           // Get item background color
                                // in: ea_t ea, bgcolor_t *color
                                // Returns: 1-not implemented, 2-color set
                                // Plugins can hook this callback to color disassembly lines
                                // dynamically
        validate_flirt_func,    // flirt has recognized a library function
                                // this callback can be used by a plugin or proc module
                                // to intercept it and validate such a function
                                // args: ea_t start_ea
                                //       const char *funcname
                                // returns: -1-do not create a function,
                                //           1-function is validated
                                // the idp module is allowed to modify 'cmd'
        get_operand_string,     // Request text string for operand (cli, java, ...)
                                // args: int opnum
                                //       char *buf
                                //       size_t buflen
                                // (cmd structure must contain info for the desired insn)
                                // opnum is the operand number; -1 means any string operand
                                // returns: 1 - no string (or empty string)
                                //         >1 - original string length with terminating zero

                                // the following 5 events are very low level
                                // take care of possible recursion
        add_cref,               // a code reference is being created
                                // args: ea_t from, ea_t to, cref_t type
                                // returns: <0 - cancel cref creation
        add_dref,               // a data reference is being created
                                // args: ea_t from, ea_t to, dref_t type
                                // returns: <0 - cancel dref creation
        del_cref,               // a code reference is being deleted
                                // args: ea_t from, ea_t to, bool expand
                                // returns: <0 - cancel cref deletion
        del_dref,               // a data reference is being deleted
                                // args: ea_t from, ea_t to
                                // returns: <0 - cancel dref deletion
        coagulate_dref,         // data reference is being analyzed
                                // args: ea_t from, ea_t to, bool may_define, ea_t *code_ea
                                // plugin may correct code_ea (e.g. for thumb mode refs, we clear the last bit)
                                // returns: <0 - cancel dref analysis
        custom_fixup,           // mutipurpose notification for FIXUP_CUSTOM
                                // args: cust_fix oper, ea_t ea, const fixup_data_t*, ... (see cust_fix)
                                // returns: 1 - no accepted (fixup ignored by ida)
                                //         >1 - accepted (see cust_fix)
        off_preproc,            // called from get_offset_expr, when refinfo_t
                                // contain flag REFINFO_PREPROC. Normally this
                                // notification used in a combination with custom_fixup
                                // args: ea_t ea, int numop, ea_t* opval, const refinfo_t* ri,
                                //       char* buf, size_t bufsize, ea_t* target,
                                // ea_t* fullvalue, ea_t from, int getn_flags
                                // returns: 2 - buf filled as simple expression
                                //          3 - buf filled as complex expression
                                //          4 - apply standard processing (with - possible - changed values)
                                //     others - can't convert to offset expression

        set_proc_options,       // called if the user specified an option string in the command line:
                                //  -p<processor name>:<options>
                                // can be used for e.g. setting a processor subtype
                                // also called if option string is passed to set_processor_type()
                                // and IDC's SetProcessorType()
                                // args: const char * options
                                // returns: <0 - bad option string

        adjust_libfunc_ea,      // called when a signature module has been matched against
                                // bytes in the database. This is used to compute the
                                // offset at which a particular module's libfunc should
                                // be applied.
                                // args: const idasgn_t *sig, const libfunc_t *libfun, ea_t *ea
                                // returns: 2 - the ea_t pointed to by the third argument was modified.
                                //     others - not modified. Use default algorithm.
                                //
                                // Note: "*ea" initially contains the ea_t of the start
                                //       of the pattern match.

        last_cb_before_debugger,
        // START OF DEBUGGER CALLBACKS
#ifdef NO_OBSOLETE_FUNCS        //
        obsolete_get_operand_info = 100, // Get operand information
#else
        get_operand_info = 100, // Get operand information
#endif
                                // This callback is used to calculate the operand
                                // value for double clicking on it, hints, etc
                                // ea_t ea  - instruction address
                                // int n    - operand number
                                // int thread_id - current thread id
                                // const regval_t &(*idaapi getreg)(const char *name,
                                //                                  const regval_t *regvalues))
                                //                           - function to get register values
                                // const regval_t *regvalues - register values array
                                // idd_opinfo_t *opinf       - the output buffer
                                // returns: 0-ok, otherwise failed

        get_reg_info,           // Get register information by its name
                                // const char *regname
                                // const char **main_regname (NULL-failed)
                                // uint64 *mask - mask to apply to 'main_regname' value (0-no mask)
                                // returns: 1-unimplemented, 0-implemented
                                // example: "ah" returns main_regname="eax" and mask=0xFF00
                                // this callback might be unimplemented if the register
                                // names are all present in ph.regNames and they all have
                                // the same size
#ifdef NO_OBSOLETE_FUNCS        //
        next_exec_insn,         // Get next address to be executed
#else                           //
        get_jump_target,        // Get jump target (old name)
#endif                          //
                                // ea_t ea                   - instruction address
                                // int tid                   - current therad id
                                // const regval_t &(*idaapi getreg)(const char *name,
                                //                                  const regval_t *regvalues))
                                //                           - function to get register values
                                // const regval_t *regvalues - register values array
                                // ea_t *target              - pointer to the answer
                                // This function must return the next address to be executed.
                                // If the instruction following the current one is executed, then it must return BADADDR
                                // Usually the instructions to consider are: jumps, branches, calls, returns
                                // This function is essential if the 'single step' is not supported in hardware
                                // returns: 1-unimplemented, 0-implemented

        calc_step_over,         // Calculate the address of the instruction which will be
                                // executed after "step over". The kernel will put a breakpoint there.
                                // If the step over is equal to step into or we can not calculate
                                // the address, return BADADDR.
                                // ea_t ip - instruction address
                                // ea_t *target - pointer to the answer
                                // returns: 1-unimplemented, 0-implemented

        get_macro_insn_head,    // Calculate the start of a macro instruction
                                // This notification is called if IP points to the middle of an instruction
                                // ea_t ip - instruction address
                                // ea_t *head - answer, BADADDR means normal instruction
                                // returns: 1-unimplemented, 0-implemented

        get_dbr_opnum,          // Get the number of the operand to be displayed in the
                                // debugger reference view (text mode)
                                // ea_t ea - instruction address
                                // int *opnum - operand number (out, -1 means no such operand)
                                // returns: 1-unimplemented, 0-implemented

        insn_sets_tbit,         // Check if the instruction will set the trace bit
                                // given the current memory and register contents
                                // ea_t ea - instruction address
                                // const regval_t &(*idaapi getreg)(const char *name,
                                //                                  const regval_t *regvalues))
                                //                           - function to get register values
                                // const regval_t *regvalues - register values array
                                // returns: 1-no, 2-yes, 3-causes bpt exception (int3)
#ifdef NO_OBSOLETE_FUNCS
        get_operand_info,       // Get operand information. See the description above
#else
        reserved_entry,
#endif
        calc_next_eas,          // Calculate list of addresses the instruction in cmd
                                // may pass control to.
                                // bool over - calculate for step over (ignore call targets)
                                // ea_t *res - array for the results.
                                //             This array has NEXTEAS_ANSWER_SIZE elements.
                                // int *nsubcalls - number of addresses of called functions
                                //                  in the above array. they must be put
                                //                  at the beginning of the array.
                                //                  if over=true, this answer will be zero.
                                // returns: number of calculated addresses+1
                                // If there are too many addresses or they are
                                // incalculable (indirect jumps, for example), return -1.
                                // This callback is required for source level debugging.

        // END OF DEBUGGER CALLBACKS

        // START OF TYPEINFO CALLBACKS
                                // The codes below will be called only if
                                // PR_TYPEINFO is set
                                // ALL OF THEM UP TO calc_arglocs2 SHOULD BE IMPLEMENTED IN THIS CASE!!!
                                // (setup_til and calc_purged_bytes are optional)

        decorate_name=500,      // Decorate/undecorate a C symbol name
                                // const til_t *ti    - pointer to til
                                // const char *name   - name of symbol
                                // const type_t *type - type of symbol. If NULL then it will try to guess.
                                // char *outbuf       - output buffer
                                // size_t bufsize     - size of the output buffer
                                // bool mangle        - true-mangle, false-unmangle
                                // cm_t cc            - real calling convention for VOIDARG functions
                                // returns: true if success

        setup_til,              // Setup default type libraries (called after loading
                                // a new file into the database)
                                // The processor module may load tils, setup memory
                                // model and perform other actions required to set up
                                // the type system
                                // args:    none
                                // returns: nothing
                                // Optional callback

        based_ptr,              // get prefix and size of 'segment based' ptr
                                // type (something like char _ss *ptr)
                                // see description in typeinf.hpp
                                // args:  unsigned ptrt
                                //        const char **ptrname (output arg)
                                // returns: size of type

        max_ptr_size,           // get maximal size of a pointer in bytes
                                // args:  none
                                // returns: max possible size of a pointer plus 1

        get_default_enum_size,  // get default enum size
                                // args:  cm_t cm
                                // returns: sizeof(enum)

        OBSOLETE(calc_arglocs), // See calc_arglocs2

        use_stkarg_type,        // use information about a stack argument
                                // args:    ea_t ea            - address of the push instruction which
                                //                               pushes the function argument into the stack
                                //          const type_t *type - the function argument type
                                //          const char *name   - the function argument name. may be NULL
                                // returns: true - ok, false - failed, the kernel will create
                                //          a comment with the argument name or type for the instruction

        OBSOLETE(use_regarg_type),
        OBSOLETE(use_arg_types),
        OBSOLETE(get_fastcall_regs),
        OBSOLETE(get_thiscall_regs),
        OBSOLETE(calc_cdecl_purged_bytes),
        OBSOLETE(get_stkarg_offset),

        calc_purged_bytes,      // calculate number of purged bytes by the given function type
                                // args: type_t *type - must be function type
                                // returns: number of bytes purged from the stack + 2
                                // Optional callback

        calc_arglocs2,          // calculate function argument locations
                                // args:    const type_t *type - points to the return type of the function type string
                                //          cm_t cc        - calling convention
                                //          uint32 *arglocs - the result array
                                // the arglocs array is big enough to store
                                // argument location information (it is at least nargs+1 elements)
                                // This callback supersedes calc_argloc.
                                // returns: 1-not implemented, 2-ok, -1-error
                                // this callback is never called for CM_CC_SPECIAL functions

        calc_retloc,            // calculate return value location
                                // args:   const type_t *rettype
                                //         cm_t cc
                                //         unit32 *retloc - the result
                                // returns: 1-not implemented, 2-ok, -1-error

        calc_varglocs,          // calculate locations of the arguments that correspond to '...'
                                // args:const func_type_info_t *fti - function type
                                //      int nargs  - number of actual arguments
                                //      const type_t *const *argtypes - type of each actual argument.
                                //                                      may be NULL if types are unknown
                                //      argloc_t *arglocs- in: size of each actual argument
                                //                        out: argloc of each actual argument
                                //                             argloc array contains one extra element
                                //                             to store the total size of all stack arguments
                                //      regobjs_t *regargs - register arguments
                                //      relobj_t *stkargs  - stack arguments
                                // Note: fixed arguments are not present in argtypes and arglocs
                                // returns: 1-not implemented, 2-ok, -1-error

        OBSOLETE(get_varcall_regs),

        use_regarg_type2,       // use information about register argument
                                // args:
                                //      int *retidx          - pointer to the returned value
                                //      ea_t ea              - address of the instruction
                                //      const type_t * const * - array of argument types
                                //      const char * const * - array of argument names
                                //      const uint32 *       - array of register numbers
                                //      int n                - number of register arguments
                                // at the end, *retidx contains:
                                //   idx of the used argument - if the argument is defined in the current instruction
                                //                              a comment will be applied by the kernel
                                //   idx|REG_SPOIL            - argument is spoiled by the instruction
                                //   -1                       - if the instruction doesn't change any registers
                                //   -2                       - if the instruction spoils all registers
                                // returns: 2

        use_arg_types2,         // use information about callee arguments
                                // args:ea_t ea              - address of the call instruction
                                //      const type_t * const * - array of all argument types
                                //      const char * const * - array of all argument names
                                //      const uint32 *       - array of argument locations
                                //      int n                - number of all arguments
                                //      const type_t **      - array of register argument types
                                //      const char **        - array of register argument names
                                //      uint32 *             - array of register numbers
                                //      int *rn              - number of register arguments
                                // returns: 2 (and updates *rn)
                                // this callback will be used only if PR_USE_ARG_TYPES is set

        get_fastcall_regs2,     // get array of registers used in the fastcall calling convention
                                // the array is -1 terminated
                                // args: const int ** - place to put the pointer into the array
                                // returns: number_of_fastcall_regs+2

        get_thiscall_regs2,     // get array of registers used in the thiscall calling convention
                                // the array is -1 terminated
                                // args: const int ** - place to put the pointer into the array
                                // returns: number_of_thiscall_regs+2

        get_varcall_regs2,      // get array of registers used in the ellipsis (...) calling convention
                                // the array is -1 terminated
                                // args: const int ** - place to put the pointer into the array
                                // returns: number_of_varcall_regs+2, *args is filled.

        calc_cdecl_purged_bytes2,// calculate number of purged bytes after call
                                // args: ea_t - address of the call instruction
                                // returns: number of purged bytes+2 (usually add sp, N)

        get_stkarg_offset2,     // get offset from SP to the first stack argument
                                // args: none
                                // returns: the offset
                                // for example: pc: 0, hppa: -0x34, ppc: 0x38

        til_for_file,           // internal notification, do not use

                                // END OF TYPEINFO RELATED NOTIFICATIONS

        // END OF TYPEINFO CALLBACKS

        loader=1000,            // this code and higher ones are reserved
                                // for the loaders.
                                // the arguments and the return values are
                                // defined by the loaders
  };

  int   (idaapi* notify)(idp_notify msgid, ...); // Various notifications for the idp

// Get the stack variable scaling factor
// Useful for processors who refer to the stack with implicit scaling factor.
// TMS320C55 for example: SP(#1) really refers to (SP+2)

   int get_stkvar_scale(void)
     { return (flag & PR_SCALE_STKVARS) ? notify(get_stkvar_scale_factor) : 1; }

//
// The following functions generate portions of the disassembled text.
//
  void  (idaapi* header)(void);                // function to produce start of disassembled text
  void  (idaapi* footer)(void);                // function to produce end of disassembled text

  void  (idaapi* segstart)(ea_t ea);          // function to produce start of segment
  void  (idaapi* segend)  (ea_t ea);          // function to produce end of segment

  void  (idaapi* assumes) (ea_t ea);          // function to produce assume directives
                                        // when segment register value changes
                                        // if your processor has no segment
                                        // registers, you may define it as NULL

// Analyze one instruction and fill 'cmd' structure.
// cmd.ea contains address of instruction to analyze.
// Return length of the instruction in bytes, 0 if instruction can't be decoded.
// This function shouldn't change the database, flags or anything else.
// All these actions should be performed only by u_emu() function.

  int   (idaapi* u_ana)   (void);

//
// Emulate instruction, create cross-references, plan to analyze
// subsequent instructions, modify flags etc. Upon entrance to this function
// all information about the instruction is in 'cmd' structure.
// If zero is returned, the kernel will delete the instruction.

  int   (idaapi* u_emu)   (void);

// Generate text representation of an instruction in 'cmd' structure.
// This function shouldn't change the database, flags or anything else.
// All these actions should be performed only by u_emu() function.

  void  (idaapi* u_out)   (void);

// Generate text representation of an instructon operand.
// This function shouldn't change the database, flags or anything else.
// All these actions should be performed only by u_emu() function.
// The output text is placed in the output buffer initialized with init_output_buffer()
// This function uses out_...() functions from ua.hpp to generate the operand text
// Returns: 1-ok, 0-operand is hidden.

  bool  (idaapi* u_outop) (op_t &op);


// Generate text represenation of data items
// This function MAY change the database and create cross-references, etc.

  void  (idaapi* d_out)   (ea_t ea);          // disassemble data

// Compare instruction operands.
// Returns 1-equal,0-not equal operands.
// This pointer may be NULL.

  bool  (idaapi* cmp_opnd)(const op_t &op1, const op_t &op2);

// Can the operand have a type as offset, segment, decimal, etc.
// (for example, a register AX can't have a type, meaning that the user can't
// change its representation. see bytes.hpp for information about types and flags)
// This pointer may be NULL.

  bool  (idaapi* can_have_type)(op_t &op);

//
//      Processor register information:
//

  int   regsNum;                        // number of registers
  const char **regNames;                // their names

// The following pointers should be NULL:

  AbstractRegister *(idaapi* getreg)(int regnum); // Get register value.
                                        // If specified, will be
                                        // used in the determining predefined
                                        // comment based on the register value

  int   rFiles;                         // number of register files
  const char **rFnames;                 // register names for files
  rginfo *rFdescs;                      // description of registers
  WorkReg *CPUregs;                     // pointer to CPU registers

// Segment register information (use virtual CS and DS registers if your
// processor doesn't have segment registers):

  int   regFirstSreg;                   // number of first segment register
  int   regLastSreg;                    // number of last segment register
  int   segreg_size;                    // size of a segment register in bytes

// You should define 2 virtual segment registers for CS and DS.
// Let's call them rVcs and rVds.

  int   regCodeSreg;                    // number of CS register
  int   regDataSreg;                    // number of DS register

//
//      Empirics
//

  const bytes_t *codestart;             // Array of typical code start sequences
                                        // This array is used when a new file
                                        // is loaded to find the beginnings of code
                                        // sequences.
                                        // This array is terminated with
                                        // a zero length item.
  const bytes_t *retcodes;              // Array of 'return' instruction opcodes
                                        // This array is used to determine
                                        // form of autogenerated locret_...
                                        // labels.
                                        // The last item of it should be { 0, NULL }
                                        // This array may be NULL
                                        // Better way of handling return instructions
                                        // is to define the is_ret_insn callback in
                                        // the notify() function

//
//      Instruction set
//

  int   instruc_start;                  // icode of the first instruction
  int   instruc_end;                    // icode of the last instruction + 1
  bool is_canon_insn(uint16 itype) const { return itype >= instruc_start && itype < instruc_end; }

  instruc_t *instruc;                   // Array of instructions

// is indirect far jump or call instruction?
// meaningful only if the processor has 'near' and 'far' reference types

  int   (idaapi* is_far_jump)(int icode);


//      Translation function for offsets
//      Currently used in the offset display functions
//      to calculate the referenced address
//
  ea_t (idaapi* translate)(ea_t base, adiff_t offset);

//
//      Size of long double (tbyte) for this processor
//      (meaningful only if ash.a_tbyte != NULL)
//
  size_t tbyte_size;

//
//      Floating point -> IEEE conversion function
// error codes returned by this function (load/store):
#define REAL_ERROR_FORMAT  -1 // not supported format for current .idp
#define REAL_ERROR_RANGE   -2 // number too big (small) for store (mem NOT modifyed)
#define REAL_ERROR_BADDATA -3 // illegal real data for load (IEEE data not filled)
//
  int (idaapi* realcvt)(void *m, uint16 *e, uint16 swt);

//
// Number of digits in floating numbers after the decimal point.
// If an element of this array equals 0, then the corresponding
// floating point data is not used for the processor.
// This array is used to align numbers in the output.
//      real_width[0] - number of digits for short floats (only PDP-11 has them)
//      real_width[1] - number of digits for "float"
//      real_width[2] - number of digits for "double"
//      real_width[3] - number of digits for "long double"
// Example: IBM PC module has { 0,7,15,19 }
//
  char real_width[4];

//
//  Find 'switch' idiom
//      fills 'si' structure with information and returns 1
//      returns 0 if switch is not found.
//      input: 'cmd' structure is correct.
//      this function may use and modify 'cmd' structure
//      it will be called for instructions marked with CF_JUMP
//
  bool (idaapi* is_switch)(switch_info_ex_t *si);

//
//  Generate map file. If this pointer is NULL, the kernel itself
//  will create the map file.
//  This function returns number of lines in output file.
//  0 - empty file, -1 - write error
//
  int32 (idaapi* gen_map_file)(FILE *fp);

//
//  Extract address from a string. Returns BADADDR if can't extract.
//  Returns BADADDR-1 if kernel should use standard algorithm.
//
  ea_t (idaapi* extract_address)(ea_t ea,const char *string,int x);

//
//  Check whether the operand is relative to stack pointer or frame pointer.
//  This function is used to determine how to output a stack variable
//  This function may be absent. If it is absent, then all operands
//  are sp based by default.
//  Define this function only if some stack references use frame pointer
//  instead of stack pointer.
//  returns flags:
#define OP_FP_BASED  0x00000000 // operand is FP based
#define OP_SP_BASED  0x00000001 // operand is SP based
#define OP_SP_ADD    0x00000000 // operand value is added to the pointer
#define OP_SP_SUB    0x00000002 // operand value is substracted from the pointer
//
   int (idaapi* is_sp_based)(const op_t &x);

//
//  Create a function frame for a newly created function.
//  Set up frame size, its attributes etc.
//  This function may be absent.
//
   bool (idaapi* create_func_frame)(func_t *pfn);


// Get size of function return address in bytes
//      pfn - pointer to function structure, can't be NULL
// If this function is absent, the kernel will assume
//      4 bytes for 32-bit function
//      2 bytes otherwise

   int (idaapi* get_frame_retsize)(func_t *pfn);


//  Generate stack variable definition line
//  If this function is NULL, then the kernel will create this line itself.
//  Default line is
//              varname = type ptr value
//  where 'type' is one of byte,word,dword,qword,tbyte
//
   void (idaapi* gen_stkvar_def)(char *buf,
                                 size_t bufsize,
                                 const member_t *mptr,
                                 sval_t v);


// Generate text representation of an item in a special segment
// i.e. absolute symbols, externs, communal definitions etc.
// returns: 1-overflow, 0-ok

   bool (idaapi* u_outspec)(ea_t ea,uchar segtype);


// Icode of return instruction. It is ok to give any of possible return
// instructions

   int icode_return;


// Set IDP-specific option (see below)
  set_options_t *set_idp_options;

//      Is the instruction created only for alignment purposes?
//      returns: number of bytes in the instruction

  int (idaapi* is_align_insn)(ea_t ea);

//      Micro virtual machine description
//      If NULL, IDP doesn't support microcodes.

  mvm_t *mvm;

//      If the FIXUP_VHIGH and FIXUP_VLOW fixup types are supported
//      then the number of bits in the HIGH part. For example,
//      SPARC will have here 22 because it has HIGH22 and LOW10 relocations.
//      See also: the description of PR_FULL_HIFXP bit

  int high_fixup_bits;

};

// The following two structures contain information about the current
// processor and assembler.

idaman processor_t ida_export_data ph;   // Current processor
idaman asm_t ida_export_data ash;        // Current assembler

idaman int ida_export str2regf(const char *p);    // -1 - error. Returns word reg number
idaman int ida_export str2reg(const char *p);     // -1 - error. Returns any reg number

// Get text represenation of a register
//      reg     - internal register number as defined in the processor module
//      width   - register width in bytes
//      buf     - output buffer
//      bufsize - size of output buffer
//      reghi   - if specified, then this function will return the register pair
// For most processors this function will just return ph.regNames[reg]
// If the processor module has implemented processor_t::get_reg_name, it will be
// used instead
// Returns: length of register name in bytes or -1 if failure

idaman ssize_t ida_export get_reg_name(int reg, size_t width, char *buf, size_t bufsize, int reghi=-1);


// get register information - useful for registers like al, ah, dil, etc.
// returns NULL - no such register
inline const char *get_reg_info(const char *regname, uint64 *mask)
{
  const char *r2;
  if ( ph.notify != NULL )
  {
    if ( ph.notify(ph.get_reg_info, regname, &r2, mask) == 0 )
      return r2;
    if ( str2reg(regname) != -1 )
    {
      if ( mask != NULL )
        *mask = 0;
      return regname;
    }
  }
  return NULL;
}

// get register number and size from register name
struct reg_info_t
{
  int reg;              // register number
  int size;             // register size
  bool operator==(const reg_info_t &r) const
  {
    return reg == r.reg && size == r.size;
  }
  bool operator!=(const reg_info_t &r) const
  {
    return !(*this == r);
  }
};
DECLARE_TYPE_AS_MOVABLE(reg_info_t);
typedef qvector<reg_info_t> reginfovec_t;

idaman bool ida_export parse_reg_name(const char *regname, reg_info_t *ri);


inline bool insn_t::is_canon_insn(void) const // (see def in ua.hpp)
{
  return ph.is_canon_insn(itype);
}

inline const char *insn_t::get_canon_mnem(void) const
{
  return is_canon_insn() ? ph.instruc[itype-ph.instruc_start].name : NULL;
}

inline uint32 insn_t::get_canon_feature(void) const
{
  return is_canon_insn() ? ph.instruc[itype-ph.instruc_start].feature : 0;
}

inline size_t sizeof_ldbl(void)
{
  return inf.size_ldbl ? inf.size_ldbl : ph.tbyte_size;
}


idaman void ida_export intel_data(ea_t ea);   // kernel function to display data items
                                        // and undefined bytes
                                        // This function should be used to
                                        // display data.
idaman bool ida_export gen_spcdef(ea_t ea,uchar segtype);
                                        // generate declaration for item
                                        // in a special segment
                                        // return: 1-overflow, 0-ok
idaman bool ida_export gen_extern(ea_t ea,const char *name);
                                        // generate declaration of extern symbol
                                        // return: 1-overflow, 0-ok
idaman bool ida_export gen_abssym(ea_t ea,const char *name);
                                        // generate declaration of absolute symbol
                                        // return: 1-overflow, 0-ok
idaman bool ida_export gen_comvar(ea_t ea,const char *name);
                                        // generate declaration of communal variable
                                        // return: 1-overflow, 0-ok

// Set target processor type
//      procname - name of processor type
//      level    - the power of request:
//        SETPROC_COMPAT - search for the processor type in the current module
//        SETPROC_ALL    - search for the processor type in all modules
//                         only if there were not calls with SETPROC_USER
//        SETPROC_USER   - search for the processor type in all modules
//                         and prohibit level SETPROC_USER
//        SETPROC_FATAL  - can be combined with previous bits.
//                         means that if the processor type can't be
//                         set, IDA should display an error message and exit.
// Returns: NULL - failed, otherwise path of file with processor module

#define SETPROC_COMPAT  0
#define SETPROC_ALL     1
#define SETPROC_USER    2

#define SETPROC_FATAL   0x80

idaman char *ida_export set_processor_type(const char *procname,int level);


// Get name of the current processor module
//      buf -  the output buffer, should be at least QMAXFILE length
// The name is derived from the file name.
// For example, for IBM PC the module is named "pc.w32" (windows version)
// Then the module name is "PC" (uppercase)
// If no processor module is loaded, this function will return NULL

idaman char *ida_export get_idp_name(char *buf, size_t bufsize);


// Set target assembler
//      asmnum - number of assembler in the current processor module
// Returns: success

idaman bool ida_export set_target_assembler(int asmnum);


// Unload the processor module.
// This function is for the kernel only.

void free_processor_module(void);


// Read IDA.CFG file and configure IDA for the current processor
// This is an internal kernel function.
// It should not be used in modules.

void read_config_file(int npass, bool testmode);


// IDB event group. Some events are still in the processor group, so you will
// need to hook to both groups. These events do not returns anything.
// The callback function should return 0 but the kernel won't check it.
// Use the hook_to_notification_point() function to install your callback.
namespace idb_event
{
  enum event_code_t
  {
    byte_patched,           // A byte has been patched
                            // in: ea_t ea, uint32 old_value
    cmt_changed,            // An item comment has been changed
                            // in: ea_t ea, bool repeatable_cmt
    ti_changed,             // An item typestring (c/c++ prototype) has been changed
                            // in: ea_t ea, const type_t *type, const p_list *fnames
    op_ti_changed,          // An operand typestring (c/c++ prototype) has been changed
                            // in: ea_t ea, int n, const type_t *type, const p_list *fnames
    op_type_changed,        // An operand type (offset, hex, etc...) has been set or deleted
                            // in: ea_t ea, int n
    enum_created,           // An enum type has been created
                            // in: enum_t id
    enum_deleted,           // An enum type has been deleted
                            // in: enum_t id
    enum_bf_changed,        // An enum type 'bitfield' attribute has been changed
                            // in: enum_t id
    enum_renamed,           // An enum or member has been renamed
                            // in: tid_t id
    enum_cmt_changed,       // An enum or member type comment has been changed
                            // in: tid_t id, bool repeatable
#ifndef NO_OBSOLETE_FUNCS
    enum_const_created,
    enum_const_deleted,
#else
    enum_member_created,    // An enum member has been created
                            // in: enum_t id, const_t cid
    enum_member_deleted,    // An enum member has been deleted
                            // in: enum_t id, const_t cid
#endif
    struc_created,          // A new structure type has been created
                            // in: tid_t struc_id
    struc_deleted,          // A structure type has been deleted
                            // in: tid_t struc_id
    struc_renamed,          // A structure type has been renamed
                            // in: struc_t *sptr
    struc_expanded,         // A structure type has been expanded/shrank
                            // in: struc_t *sptr
    struc_cmt_changed,      // A structure type comment has been changed
                            // in: tid_t struc_id
    struc_member_created,   // A structure member has been created
                            // in: struc_t *sptr, member_t *mptr
    struc_member_deleted,   // A structure member has been deleted
                            // in: struc_t *sptr, tid_t member_id, ea_t offset
    struc_member_renamed,   // A structure member has been renamed
                            // in: struc_t *sptr, member_t *mptr
    struc_member_changed,   // A structure member has been changed
                            // in: struc_t *sptr, member_t *mptr
    thunk_func_created,     // A thunk bit has been set for a function
                            // in: func_t *pfn
    func_tail_appended,     // A function tail chunk has been appended
                            // in: func_t *pfn, func_t *tail
    func_tail_removed,      // A function tail chunk has been removed
                            // in: func_t *pfn, ea_t tail_ea
    tail_owner_changed,     // A tail chunk owner has been changed
                            // in: func_t *tail, ea_t owner_func, ea_t old_owner
    func_noret_changed,     // FUNC_NORET bit has been changed
                            // in: func_t *pfn
    segm_added,             // A new segment has been created
                            // in: segment_t *s
    segm_deleted,           // A segment has been deleted
                            // in: ea_t startEA, ea_t endEA
    segm_start_changed,     // Segment start address has been changed
                            // in: segment_t *s
    segm_end_changed,       // Segment end address has been changed
                            // in: segment_t *s
    segm_moved,             // Segment has been moved
                            // in: ea_t from, ea_t to, asize_t size
    area_cmt_changed,       // Area comment has been changed
                            // in: areacb_t *cb, const area_t *a, const char *cmt, bool repeatable
                            // cb may be: &funcs, &segs, etc.

                            // Events that happen before database modifications
                            // IDA may not to call the corresponding ...changed event
                            // if there are any errors.

    changing_cmt,           // An item comment is to be changed
                            // in: ea_t ea, bool repeatable_cmt, const char *newcmt
    changing_ti,            // An item typestring (c/c++ prototype) is to be changed
                            // in: ea_t ea, const type_t *new_type, const p_list *new_fnames
    changing_op_ti,         // An operand typestring (c/c++ prototype) is to be changed
                            // in: ea_t ea, int n, const type_t *new_type, const p_list *new_fnames
    changing_op_type,       // An operand type (offset, hex, etc...) is to be changed
                            // in: ea_t ea, int n
    deleting_enum,          // An enum type is to be deleted
                            // in: enum_t id
    changing_enum_bf,       // An enum type 'bitfield' attribute is to be changed
                            // in: enum_t id, bool new_bf
    renaming_enum,          // An enum or enum member is to be renamed
                            // in: tid_t id, bool is_enum, const char *newname
    changing_enum_cmt,      // An enum or member type comment is to be changed
                            // in: tid_t id, bool repeatable, const char *newcmt
#ifndef NO_OBSOLETE_FUNCS
    deleting_enum_const,
#else
    deleting_enum_member,   // An enum member is to be deleted
                            // in: enum_t id, const_t cid
#endif
    deleting_struc,         // A structure type is to be deleted
                            // in: struc_t *sptr
    renaming_struc,         // A structure type is to be renamed
                            // in: tid_t id, const char *oldname, const char *newname
    expanding_struc,        // A structure type is to be expanded/shrunk
                            // in: struc_t *sptr, ea_t offset, adiff_t delta
    changing_struc_cmt,     // A structure type comment is to be changed
                            // in: tid_t struc_id, bool repeatable, const char *newcmt
    deleting_struc_member,  // A structure member is to be deleted
                            // in: struc_t *sptr, member_t *mptr
    renaming_struc_member,  // A structure member is to be renamed
                            // in: struc_t *sptr, member_t *mptr, const char *newname
    changing_struc_member,  // A structure member is to be changed
                            // in: struc_t *sptr, member_t *mptr, flags_t flag, const opinfo_t *ti, asize_t nbytes
    removing_func_tail,     // A function tail chunk is to be removed
                            // in: func_t *pfn, constr area_t *tail
    deleting_segm,          // A segment is to be deleted
                            // in: ea_t startEA
    changing_segm_start,    // Segment start address is to be changed
                            // in: segment_t *s, ea_t new_start, int segmod_flags
    changing_segm_end,      // Segment end address is to be changed
                            // in: segment_t *s, ea_t new_end, int segmod_flags
    changing_area_cmt,      // Area comment is to be changed
                            // in: areacb_t *cb, const area_t *a, const char *cmt, bool repeatable
    changing_segm_name,     // Segment name is beging changed
                            // in: segment_t *s, const char *oldname
    changing_segm_class,    // Segment class is being changed
                            // in: segment_t *s
    segm_name_changed,      // Segment name has been changed
                            // in: segment_t *s, const char *name
    segm_class_changed,     // Segment class has been changed
                            // in: segment_t *s, const char *sclass
    destroyed_items,        // Instructions/data have been destroyed in [ea1,ea2)
                            // in: ea_t ea1, ea_t ea2, bool will_disable_range
    changed_stkpnts,        // Stack change points have been modified
                            // in: func_t *pfn
  };
};

  // the kernel will use this function to generate idb_events
void gen_idb_event(idb_event::event_code_t code, ...);

#pragma pack(pop)
#endif // _IDP_HPP
