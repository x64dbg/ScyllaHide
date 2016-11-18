/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2008 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _UA_HPP
#define _UA_HPP
#pragma pack(push, 1)   // IDA uses 1 byte alignments!

//      This file contains functions that deal with the disassembling
//      of program instructions. There are 2 kinds of functions:
//              - functions that are called from the kernel
//                to disassemble an instruction. These functions
//                call IDP module for it.
//              - functions that are called from IDP module to
//                disassemble an instruction. We will call them
//                'helper functions'
//      Disassembly of an instruction is made in three steps:
//              A. analysis             ana.cpp
//              B. emulation            emu.cpp
//              C. convertion to text   out.cpp
//      The kernel calls IDP module to perform these steps.
//      At first, the kernel always calls analysis. The analyzer
//      must decode the instruction and fill 'cmd' structure.
//      It has no rights to change anything in the database.
//      The second step, emulation, is called for each instruction.
//      This step must make nesessary changes to the database,
//      plan analysis of subsequent instructions, it may track register
//      values, memory contents, etc. However, the kernel may call the
//      emulation step for any address in the program, there is no
//      ordering of addresses. Usually, the emulation is called for
//      sequentally for subsequent addresses but this is not guaranteed.
//      The main goal of emulation step is to track down execution flow
//      and to plan conversion of nesessary bytes to instructions.
//      The last step, conversion to text, is called each time when
//      an instruction is displayed on the screen. The kernel will always
//      call the analysis step first (the analysis should be very fast)
//      and then will call conversion to text.
//      The emulation and conversion steps should use information stored
//      in 'cmd' structure. They should not access to bytes of instruction
//      and decode it again - this should be done in the analysis step.

#include <kernwin.hpp>  // for btoa()
#include <lines.hpp>    // for colors
#include <xref.hpp>     // add_cref()

//--------------------------------------------------------------------------
//      T Y P E   O F   O P E R A N D
//--------------------------------------------------------------------------

// Type of an operand
// An operand of an instruction has a type. The kernel knows about
// some operand types and accordingly interprets some fields of op_t
// structure. The fields used by the kernel is shown below.
// There are some IDP specific types (o_idpspec?). You are free to
// give any meaning to these types. I suggest you to create a #define
// to use mnemonic names. However, don't forget that the kernel will
// know nothing about operands of those types.
// As about "data field", you may use any additional fields to store
// processor specific operand information
#ifndef SWIG
typedef uchar optype_t;
const optype_t     // Description                          Data field
  o_void     =  0, // No Operand                           ----------
  o_reg      =  1, // General Register (al,ax,es,ds...)    reg
  o_mem      =  2, // Direct Memory Reference  (DATA)      addr
  o_phrase   =  3, // Memory Ref [Base Reg + Index Reg]    phrase
  o_displ    =  4, // Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
  o_imm      =  5, // Immediate Value                      value
  o_far      =  6, // Immediate Far Address  (CODE)        addr
  o_near     =  7, // Immediate Near Address (CODE)        addr
  o_idpspec0 =  8, // IDP specific type
  o_idpspec1 =  9, // IDP specific type
  o_idpspec2 = 10, // IDP specific type
  o_idpspec3 = 11, // IDP specific type
  o_idpspec4 = 12, // IDP specific type
  o_idpspec5 = 13, // IDP specific type
  o_last     = 14; // first unused type

// How to assign the operand types
// -------------------------------
//
//o_reg    denotes a simple register, the register number should
//         be stored in x.reg. All processor registers, including special
//         registers, can be represented by this operand type
//o_mem    a direct memory data reference whose target address is known at the compliation time.
//         The target virtual address is stored in x.addr and the full address
//         is calculated as toEA(cmd.cs, x.addr). For the processors with
//         complex memory organization the final address can be calculated
//         using other segment registers. For flat memories, x.addr is the final
//         address and cmd.cs is usually equal to zero. In any case, the address
//         within the segment should be stored in x.addr.
//o_phrase a memory reference using register contents. indexed, register based,
//         and other addressing modes can be represented with the operand type.
//         This addressing mode can not contain immediate values (use o_displ for them)
//         The phrase number should be stored in x.phrase. To denote the preincrement
//         and similar features please use additional operand fields like specflags.
//         Usually x.phrase contains the register number and additional information
//         is stored in x.specflags. Please note that this operand type can not
//         contain immediate values (except the scaling coefficients)
//o_displ  a memory reference using register contents with displacement.
//         The displacement should be stored in the x.addr field. The rest of information
//         is stored the same way as in o_phrase.
//o_imm    an immediate value. Any operand consisting of only a number is represented
//         by this operand type. The value should be stored in x.value. You may sign
//         extend short (1-2 byte) values. In any case don't forget to specify x.dtyp
//         (x.dtyp should be set for all operand types)
//o_near   a direct memory code reference whose target address is known at the compliation time.
//         The target virtual address is stored in x.addr and the final address
//         is always toEA(cmd.cs, x.addr). Usually this operand type is used for
//         the branches and calls whose target address is known. If the current
//         processor has 2 different types of references for intersegment and intrasegment
//         references, then o_near should be used only for intrasegment references.
//o_far    If the current processor has a special addressing mode for intersegment
//         references, then this operand type should be used instead of o_near.
//         If you want, you may use PR_CHK_XREF in ph.flag to disable intersegment
//         calls if o_near operand type is used. Currently only IBM PC uses this flag.
//
//      If the above operand types do not cover all possible addressing modes,
//      then use o_idpspec operand types.

//--------------------------------------------------------------------------
//      O P E R A N D   O F   I N S T R U C T I O N
//--------------------------------------------------------------------------

// Operand of an instruction. This structure is filled by the analyzer.
// Upon entrance to the analyzer, some fields of this structure are initialized:
//      type    - o_void
//      offb    - 0
//      offo    - 0
//      flags   - OF_SHOW

class op_t
{
public:
// Number of operand. Initialized once at the start of work.
// You have no right to change its value.

  uchar         n;              // number of operand (0,1,2)


// Type of operand. See above for explanations

  optype_t      type;           // type of operand


// Offset of operand value from the instruction start.
// Of course this field is meaningful only for certain types of operands.
// Leave it equal to zero if the operand has no offset.
// This offset should point to the 'interesting' part of operand.
// For example, it may point to the address of a function in
//      call func
// or it may point to bytes holding '5' in
//      mov  ax, [bx+5]
// Usually bytes pointed to this offset are relocated (have fixup information)

  char          offb;           // offset of operand relative to instruction start
                                // 0 - unknown


// The same as above. Some operands have 2 numeric values used to
// form operand. 'offo' is used for the second part of operand if it exists.
// Currently this field is used only for outer offsets of Motorla processors.
// Leave it equal to zero if the operand has no offset

  char          offo;           // offset of operand relative to instruction start
                                // 0 - unknown


// Some characteristics of operand

  uchar         flags;
#define OF_NO_BASE_DISP 0x80    // o_displ: base displacement doesn't exist
                                // meaningful only for o_displ type
                                // if set, base displacement (x.addr)
                                // doesn't exist.
#define OF_OUTER_DISP   0x40    // o_displ: outer displacement exists
                                // meaningful only for o_displ type
                                // if set, outer displacement (x.value) exists.
#define PACK_FORM_DEF   0x20    // !o_reg + dt_packreal: packed factor defined
#define OF_NUMBER       0x10    // can be output as number only
                                // if set, the operand can be converted to a
                                // number only
#define OF_SHOW         0x08    // should the operand be displayed?
                                // if clear, the operand is hidden and should
                                // not be displayed


// Convenience functions:

  void set_showed()     { flags |=  OF_SHOW; }
  void clr_showed()     { flags &= ~OF_SHOW; }
  bool showed() const   { return (flags & OF_SHOW) != 0; }


// Type of operand value. Usually first 9 types are used.
// This is the type of the operand itself, not the size of the addressing mode.
// for example, byte ptr [epb+32_bit_offset]  will have dt_byte type.

  char          dtyp;
// from here..
#define dt_byte         0       // 8 bit
#define dt_word         1       // 16 bit
#define dt_dword        2       // 32 bit
#define dt_float        3       // 4 byte
#define dt_double       4       // 8 byte
#define dt_tbyte        5       // variable size (ph.tbyte_size)
#define dt_packreal     6       // packed real format for mc68040
// ...to here the order should not be changed, see mc68000
#define dt_qword        7       // 64 bit
#define dt_byte16       8       // 128 bit
#define dt_code         9       // ptr to code (not used?)
#define dt_void         10      // none
#define dt_fword        11      // 48 bit
#define dt_bitfild      12      // bit field (mc680x0)
#define dt_string       13      // pointer to asciiz string
#define dt_unicode      14      // pointer to unicode string
#define dt_3byte        15      // 3-byte data
#define dt_ldbl         16      // long double (which may be different from tbyte)


// The following unions keep other information about the operand

  union
  {
    uint16 reg;                 // number of register (o_reg)
    uint16 phrase;              // number of register phrase (o_phrase,o_displ)
                                // you yourself define numbers of phrases
                                // as you like
  };

  bool is_reg(int r) const { return type == o_reg && reg == r; }

//  Next 12 bytes are used by mc68k for some float types


// VALUE

  union {
    uval_t value;               // 1) operand value (o_imm)
                                // 2) outer displacement (o_displ+OF_OUTER_DISP)
                                // integer values should be in IDA's (little-endian) order
                                // when using ieee_realcvt, floating point values should be in the processor's native byte order
                                // dt_double values take up 8 bytes (value and addr fields for 32-bit modules)
                                // NB: in case a dt_dword/dt_qword immediate is forced to float by user,
                                // the kernel converts it to processor's native order before calling FP conversion routines

    struct {                    // this structure is defined for
        uint16 low;             // your convenience only
        uint16 high;
    } value_shorts;
  };

  bool is_imm(uval_t v) const { return type == o_imm && value == v; }


// VIRTUAL ADDRESS (OFFSET WITHIN THE SEGMENT)

  union {
    ea_t addr;                  // virtual address pointed or used by the operand
                                // (o_mem,o_displ,o_far,o_near)

    struct {                    // this structure is defined for
        uint16 low;             // your convenience only
        uint16 high;
    } addr_shorts;
  };


// IDP SPECIFIC INFORMATION

  union {
    ea_t specval;               // This field may be used as you want.
    struct {                    // this structure is defined for your convenience only
        uint16 low;             // IBM PC: segment register number (o_mem,o_far,o_near)
        uint16 high;            // IBM PC: segment selector value  (o_mem,o_far,o_near)
    } specval_shorts;
  };

// The following fields are used only in idp modules
// You may use them as you want to store additional information about
// the operand

  char          specflag1;
  char          specflag2;
  char          specflag3;
  char          specflag4;

};


//--------------------------------------------------------------------------
//      I N S T R U C T I O N
//--------------------------------------------------------------------------

// Structure to hold information about an instruction. This structure is
// filled by the analysis step of IDP and used by the emulation and
// conversion to text steps. The kernel uses this structure too.
// All structure fields except cs, ip, ea, Operand.n, Operand.flags
// are initialized to zero by the kernel. The rest should be filled
// by ana().

class insn_t
{
public:
// Current segment base paragraph. Initialized by the kernel.

  ea_t cs;                      // segment base (in paragraphs)


// Virtual address of the instruction (address within the segment)
// Initialized by the kernel.

  ea_t ip;                      // offset in the segment


// Linear address of the instruction.
// Initialized by the kernel.

  ea_t ea;                      // instruction start addresses


// Internal code of instruction. IDP should define its own instruction
// codes. These codes are usually defined in ins.hpp. The array of instruction
// names and features (ins.cpp) is accessed using this code.

  uint16 itype;                 // instruction code (see ins.hpp)
                                // only for canonical insns (not user defined!):
  inline bool is_canon_insn(void) const; // (see def in idp.hpp)
  inline uint32 get_canon_feature(void) const; // (see def in idp.hpp)
  inline const char *get_canon_mnem(void) const; // (see def in idp.hpp)

// Size of instruction in bytes.
// The analyzer should put here the actual size of the instruction.

  uint16 size;                  // instruction size in bytes


// Additinal information about the instruction.
// You may use these field as you want.

  union
  {
    uint16 auxpref;             // processor dependent field
    struct
    {
      uchar low;
      uchar high;
    } auxpref_chars;
  };
  char segpref;                 // processor dependent field
  char insnpref;                // processor dependent field

// Information about instruction operands.

#define UA_MAXOP        6
  op_t Operands[UA_MAXOP];

  #define Op1 Operands[0]
  #define Op2 Operands[1]
  #define Op3 Operands[2]
  #define Op4 Operands[3]
  #define Op5 Operands[4]
  #define Op6 Operands[5]

  char flags;                   // instruction flags
#define INSN_MACRO  0x01        // macro instruction
#define INSN_MODMAC 0x02        // macros: may modify the database
                                // to make room for the macro insn
  bool is_macro(void) const { return (flags & INSN_MACRO) != 0; }

};


//--------------------------------------------------------------------------
//      V A L U E   O F   O P E R A N D
//--------------------------------------------------------------------------

// This structure is used to pass values of bytes to helper functions.

union value_u
{
  uint8  v_char;
  uint16 v_short;
  uint32 v_long;
  uint64 v_int64;
  uval_t v_uval;
  struct dq_t { uint32 low; uint32 high; } _dq;
  struct dt_t { uint32 low; uint32 high; uint16 upper; } dt;
  struct d128_t { uint64 low; uint64 high; } d128;
  uint8 byte16[16];
  uint32 dword3[3];
};

#endif // SWIG

// Get immediate values used in the operand if it fits into uval_t.
//      ea - linear address
//      n  - number of operand:(0..UA_MAXOP-1) (-1 - all operands)
//      v  - array of immediate values (at least 2*UA_MAXOP elements)
// returns: number of immediate values (0..2*UA_MAXOP)

idaman size_t ida_export get_operand_immvals(ea_t ea, int n, uval_t *v);


//--------------------------------------------------------------------------
//      T H E   M A I N   S T R U C T U R E
//--------------------------------------------------------------------------

// Structure holding information about an instruction
// Analyzer should fill this structure.

idaman insn_t ida_export_data cmd;      // current instruction


// Undocumented variable. It is not used by the kernel.
// Its value may be specified in IDA.CFG:
//      LOOKBACK = <number>
// IDP may use it as you like it.
// TMS module uses it as commented below.

idaman int ida_export_data lookback;    // number of instructions to look back


//--------------------------------------------------------------------------
//      I D P   H E L P E R   F U N C T I O N S  -  C O M M O N
//--------------------------------------------------------------------------

// Flags value for the byte at the start of the current instruction.
// (see bytes.hpp for explanation of flags)
// The kernel retrieves flags value and stores it in this variable for
// your convenience. Anytime you change the database by calling functions
// that change flags value you should refresh it using get_flags_novalue()
// uFlag does not contain MS_VAL and FF_IVL fields of flags, so please
// don't call hasValue on it.

idaman flags_t ida_export_data uFlag;    // features flag


// The following functions return segment base linear addresses of
// the data or code segment for the current instruction.
// They use values of segment registers, operand types, etc.

idaman ea_t ida_export dataSeg_opreg(int opnum, int rgnum);
                                          // get data segment by operand
                                          // number and the specified
                                          // segment register number
                                          // meaningful only if the processor
                                          // has segment registers
idaman ea_t ida_export dataSeg_op(int opnum);    // get data segment by operand
                                          // number.
idaman ea_t ida_export dataSeg(void);            // get data segment regardless of
                                          // operand number
idaman ea_t ida_export codeSeg(ea_t addr, int opnum); // get code segment. this function
                                          // takes into account the segment
                                          // translations.
                                          // addr - the referenced address
                                          //        used by translations
                                          // opnum- operand number


//--------------------------------------------------------------------------
// 3-byte (tribyte) data item order
enum tribyte_order_t
{
  tbo_123,      // regular most significant byte first (big endian) - default
  tbo_132,
  tbo_213,
  tbo_231,
  tbo_312,
  tbo_321,      // regular least significant byte first (little endian)
};

//--------------------------------------------------------------------------
//      I D P   H E L P E R   F U N C T I O N S  -  A N A L Y S I S
//--------------------------------------------------------------------------

// The following 4 functions return next byte,2bytes, 4bytes, and 8bytes of the
// instruction accordingly.
// They use and modify size of instruction field (cmd.size).
// Normally they are used in the analyzer to get bytes of the instruction.
// ATTENTION: These functions work only for normal (8bit) byte processors!

idaman uint8  ida_export ua_next_byte(void);
idaman uint16 ida_export ua_next_word(void);
idaman uint32 ida_export ua_next_long(void);
idaman uint64 ida_export ua_next_qword(void);


//--------------------------------------------------------------------------
//      I D P   H E L P E R   F U N C T I O N S  -  O U T P U T
//--------------------------------------------------------------------------

// All output functions use 'cmd' structure to get information.

// Before using any out/Out functions, you should initialize the
// output buffer:

idaman void ida_export init_output_buffer(char *buf, size_t bufsize);


// After using all out/Out functions to form the output string
// you should terminate the buffer by calling this function:
// (it returns pointer to the end of the output string)

idaman char *ida_export term_output_buffer(void);


// Append a formatted string to the output string
// Returns the number of characters appended

idaman AS_PRINTF(1, 2) int ida_export out_snprintf(const char *format, ...);


// Set the pointer to the output buffer
// Returns the old value of the pointer
// If ptr == NULL, the pointer value is not changed (essentially this
// function becomes get_output_ptr if ptr==NULL)

idaman char *ida_export set_output_ptr(char *ptr);
inline char *idaapi get_output_ptr(void) { return set_output_ptr(NULL); }


// Insert a string into the output string
//      ptr - place to insert to. should come from get_output_ptr()
//      string - string to insert

idaman void ida_export out_insert(char *ptr, const char *string);


// Output instruction mnemonics using information in 'cmd'
// This function outputs a colored text.
//      width   - width of field with mnemonics
//                if width < 0 then 'postfix' will be output before
//                             the mnemonics, i.e. as a prefix
//      postfix - optional postfix added to the instruction mnemonics
// This function will output at least one space after the instruction
// mnemonics even if the specified 'width' is not enough.

idaman int ida_export OutMnem(int width=8, const char *postfix=NULL);
                                        // output instruction mnemonics
                                        // width - width of mnemonics field
                                        // postfix may be NULL
                                        // returns 0-displayed as bytes
                                        // returns 1-displayed as instruction


// Output instruction as a sequence of bytes
// followed by a comment character and instruction mnemonics
// This function is used to display undocumented instructions or
// instructions that are improperly handled by the target assembler.
// OutMnem() calls this function if the current instruction is present
// in the array of bad instructions (ash.badworks)
// This function outputs a colored text.

idaman void ida_export OutBadInstruction(void);           // Display instruction as bytes


// Use this function to output an operand of an instruction
//      n - number of operand
// This function check for the existence of manually defined operand
// and will output manually defined operand if it exists.
// Otherwise it will call ph.outop() to output operand.
// This function outputs a colored text.
// returns: 1-operand is displayed
//          o-operand is hidden

idaman int ida_export out_one_operand(int n);  // should be used in IDP modules.
                                        // outs forced operand or calls outop()
                                        // returns 1 if something was output


// Output immediate value
// This function outputs a number from x.addr or x.value in the form
// determined by 'uFlag'.
// This function outputs a colored text.
// returns: flags of the output value
//      -1: value is output with COLOR_ERROR
//      0:  value is output as a number or character or segment
// Try to use this function to output all constants of instruction operands

idaman flags_t ida_export OutValue(const op_t &x, int outflags=0);

// 'outflags' parameter is combination of the following bits:
// (don't use OOF_SIGNMASK and OOF_WIDTHMASK, they are for the kernel)

#define OOF_SIGNMASK    0x0003      // sign symbol (+/-) output:
#define   OOFS_IFSIGN   0x0000      //   output sign if needed
#define   OOFS_NOSIGN   0x0001      //   don't output sign, forbid the user to change the sign
#define   OOFS_NEEDSIGN 0x0002      //   always out sign         (+-)
#define OOF_SIGNED      0x0004      // output as signed if < 0
#define OOF_NUMBER      0x0008      // always as a number
#define OOF_WIDTHMASK   0x0070      // width of value in bits:
#define   OOFW_IMM      0x0000      //   take from x.dtyp
#define   OOFW_8        0x0010      //   8 bit width
#define   OOFW_16       0x0020      //   16 bit width
#define   OOFW_24       0x0030      //   24 bit width
#define   OOFW_32       0x0040      //   32 bit width
#define   OOFW_64       0x0050      //   64 bit width
#define OOF_ADDR        0x0080      // output x.addr, otherwise x.value
#define OOF_OUTER       0x0100      // output outer operand
#define OOF_ZSTROFF     0x0200      // meaningful only if isStroff(uFlag)
                                    // append a struct field name if
                                    // the field offset is zero?
                                    // if AFL_ZSTROFF is set, then this flag
                                    // is ignored.
#define OOF_NOBNOT      0x0400      // prohibit use of binary not
#define OOF_SPACES      0x0800      // do not suppress leading spaces
                                    // currently works only for floating point numbers


// Extract immediate value from the operand according to the specified flags
// x    - operand
// outf - combination of OOF_.. flags
// extend_sign - should the sign be extended?
// dtyp_ptr - pointer to the dtyp which will be filled by this function
// nbytes_ptr - pointer to the 'nbytes' which will be filled by this function
//              number of bytes required to store the value
// This is an internal function. Use get_operand_immvals() instead

uval_t get_immval(const op_t &x,
                  int outf=0,
                  bool extend_sign=false,
                  char *dtyp_ptr=NULL,
                  size_t *nbytes_ptr=NULL);


// Output a character with COLOR_SYMBOL color.

idaman void ida_export out_symbol(char c);


// Output a string with the specified color.

idaman void ida_export out_line(const char *str, color_t color);


// Output a string with COLOR_KEYWORD color.

inline void out_keyword(const char *str)
{
  out_line(str, COLOR_KEYWORD);
}


// Output a character with COLOR_REG color.

inline void out_register(const char *str)
{
  out_line(str, COLOR_REG);
}


// Output "turn color on" escape sequence

idaman void ida_export out_tagon(color_t tag);


// Output "turn color off" escape sequence

idaman void ida_export out_tagoff(color_t tag);


// Output "address" escape sequence

idaman void ida_export out_addr_tag(ea_t ea);


// Output a colored line with register names in it
// The register names will be substituted by user-defined names (regvar_t)
// Please note that out_tagoff tries to make substitutions too (when called with COLOR_REG)

idaman void ida_export out_colored_register_line(const char *str);


// Output plain text without color codes.
// see also out_line()

idaman void ida_export OutLine(const char *s);


// Output one character.
// The character is output without color codes.
// see also out_symbol()

idaman void ida_export OutChar(char c);


// Output a number with the specified base (binary, octal, decimal, hex)
// The number is output without color codes.
// see also out_long()

idaman void ida_export OutLong(uval_t Word, char radix);


// Output operand value as a commented character constant
// This function is used to comment void operands with their representation
// in the form of character contants.
// This function outputs a colored text.

idaman void ida_export OutImmChar(const op_t &x);


// Try to display value as a character constant.
// This is low level function, it is called from OutValue()
// This function outputs uncolored text.
//      v    - pointer to value to convert
//      buf  - output buffer
//      size - size of input value in bytes
// returns: 1-ok, the buffer contains character constant
//                its form depends on ash.flags
//          0-failed, probably the constant is invalid for the target
//                assembler

idaman bool ida_export showAsChar(const void *ptr, char *buf, int size);
                                                // try to show as character constant
                                                // return 1 - ok, 0 - can't


// Output a floating point value
// Low level function. Use OutValue() if you can.
// This function outputs uncolored text.
//      v    - floating point value in processor native format
//      size - size of the value in bytes
//      buf  - output buffer. may be NULL
//      bufsize - size of the output buffer
// return true-ok, false-can't represent as floating point number

idaman bool ida_export out_real(const void *v, int size, char *buf, size_t bufsize);


// Output a number with appropriate color.
// Low level function. Use OutValue() if you can.
//      v     - value to output
//      radix - base (2,8,10,16)
// if 'voidop' is set then
//   out_long() uses COLOR_VOIDOP instead of COLOR_NUMBER
// 'voidop' is initialized
//      in out_one_operand()
//      and in ..\ida\gl.cpp (before calling ph.d_out())
// voidop==0: operand is ok
// voidop==1: operand is void and should be output with COLOR_VOIDOP
// voidop==2: operand can't be output as requested and should be output with COLOR_ERROR

idaman int ida_export_data voidop;
idaman void ida_export out_long(sval_t v, char radix);

// Output a name expression
//    x      - instruction operand referencing the name expression
//    ea     - address to convert to name expression
//    off    - the value of name expression. this parameter is used only to
//             check that the name expression will have the wanted value.
//             You may pass BADADDR for this parameter but I discourage it
//             because it prohibits checks.
// Returns: true if the name expression has been produced

idaman bool ida_export out_name_expr(const op_t &x,
                                     ea_t ea,
                                     adiff_t off=BADADDR);


//--------------------------------------------------------------------------
//      I D P   H E L P E R   F U N C T I O N S  -  E M U L A T O R
//--------------------------------------------------------------------------

// Convert to data using information about operand value type (op.dtyp)
// This function creates data only if the address was unexplored
//      opoff - offset of the operand from the start of instruction
//              if the offset is unknown, then 0
//      ea    - linear address to be converted to data
//      dtype - operand value type (from op.dtyp)
// Emulator could use this function to convert unexplored bytes to data
// when an instruction references them.
// Returns: 1-ok, 0-failed to create data item

idaman bool ida_export ua_dodata2(int opoff, ea_t ea, int dtype);


// Create or modify a stack variable in the function frame
//      x    - operand (used to determine the addressing type)
//      v    - a displacement in the operand
//      flags- combination of STKVAR_... constants
// The emulator could use this function to create stack variables
// in the function frame before converting the operand to a stack variable.
// Please check with may_create_stkvars() before calling this function.
// returns: 1 - ok, a stack variable exists now
//          0 - no, couldn't create stack variable

idaman bool ida_export ua_stkvar2(const op_t &x, adiff_t v, int flags);

#define STKVAR_VALID_SIZE       0x0001 // x.dtyp contains correct variable type
                                       // (for insns like 'lea' this bit must be off)
                                       // in general, dr_O references do not allow
                                       // to determine the variable size

// Add a code cross-reference from the current instruction (cmd.ea)
//      opoff - offset of the operand from the start of instruction
//              if the offset is unknown, then 0
//      to    - target linear address
//      type  - type of xref

idaman void ida_export ua_add_cref(int opoff, ea_t to, cref_t type);


// Add a data cross-reference from the current instruction (cmd.ea)
//      opoff - offset of the operand from the start of instruction
//              if the offset is unknown, then 0
//      to    - target linear address
//      type  - type of xref
// See the next function - usually it can be used in most cases.

idaman void ida_export ua_add_dref(int opoff, ea_t to, dref_t type);


// Add xrefs for an operand of the current instruction (cmd.ea)
// This function creates all cross references for 'offset' and
// 'structure offset' operands.
//      x     - reference to operand
//      type  - type of xref
//      outf  - OutValue() flags. These flags should match
//              the flags used to output the operand
// Returns: if isOff(): the reference target address (the same as calc_reference_target)
//          else: BADADDR, because for stroffs the target address is unknown
// Use the second form in the presence of negative offsets

idaman ea_t ida_export ua_add_off_drefs(const op_t &x, dref_t type);
idaman ea_t ida_export ua_add_off_drefs2(const op_t &x, dref_t type, int outf);

// Get size and flags for op_t.dtyp field.

idaman flags_t ida_export get_dtyp_flag(char dtype);
idaman size_t ida_export get_dtyp_size(char dtype);
idaman char ida_export get_dtyp_by_size(asize_t size);


//--------------------------------------------------------------------------
//      K E R N E L   I N T E R F A C E   T O   I D P   F U N C T I O N S
//--------------------------------------------------------------------------
// Create an instruction at the specified address
//      ea - linear address
// This function checks if an instruction is present at the specified address
// and will try to create one if there is none. It will fail if there is
// a data item or other items hindering the creation of the new instruction.
// This function will also fill the 'cmd' structure.
// Returns the length of the instruction or 0

idaman int ida_export create_insn(ea_t ea);


// Analyze the specified address and fill 'cmd'
//      ea - linear address
// This function does not modify the database
// It just tries to intepret the specified address as an instruction and fills
// the 'cmd' structure with the results.
// Returns the length of the (possible) instruction or 0

idaman int ida_export decode_insn(ea_t ea);


// Generate text repesentation for operand #n
//      ea - linear address
//      buf - output buffer
//      bufsize - size of output buffer
//      n - operand number (0,1,2...)
//      flags - combination of GETN_... constants
//              Currently only GETN_NODUMMY is allowed
// This function will generate the text represention of the specified operand.
// If the instruction is not present in the database, it will be created.
// This function will also fill the 'cmd' structure.
// Returns: success

idaman bool ida_export ua_outop2(ea_t ea, char *buf, size_t bufsize, int n, int flags=0);


// Generate text represention of the instruction mnemonics
//      ea - linear address
//      buf - output buffer
//      bufsize - size of output buffer
// This function will generate the text represention of the instruction mnemonics,
// like 'mov', 'add', etc.
// If the instruction is not present in the database, it will be created.
// This function will also fill the 'cmd' structure.
// Returns: pointer to buf or NULL if failure

idaman const char *ida_export ua_mnem(ea_t ea, char *buf, size_t bufsize);

//--------------------------------------------------------------------------
//      Helper functions for the processor emulator/analyzer
//--------------------------------------------------------------------------

// Decode previous instruction if it exists
// Fill 'cmd'
// Return the previous instruction address (BADADDR-no such insn)

idaman ea_t ida_export decode_prev_insn(ea_t ea);


// Decode preceding instruction in the execution flow
// Prefer far xrefs from addresses < the current to ordinary flows
// Return the preceding instruction address (BADADDR-no such insn) and fill 'cmd'
// *p_farref will contain 'true' if followed an xref, false otherwise

idaman ea_t ida_export decode_preceding_insn(ea_t ea, bool *p_farref);


//      Construct a macro instruction
//      This function may be called from ana()
//      to generate a macro instruction
//
//      The real work is done by the 'build_macro()' callback
//      This callback should be provided by the module writer.
//
//      Here we just create the instruction in the database when the macro
//      generation is turned on/off.
//
// enable - enable macro generation
// build_macro - try to grow the instruction in 'cmd' to a macro
//               returns: true=the macro instruction is generated in 's'
//                        false=no macro
// returns: true=macro is built
//          false=no macro

idaman bool ida_export construct_macro(bool enable,
                        bool (idaapi *build_macro)(insn_t &s, bool may_go_forward));


// Guess the jump table address (ibm pc specific)

idaman ea_t ida_export guess_table_address(void);


// Guess the jump table size

idaman asize_t ida_export guess_table_size(ea_t jump_table);


// Does the instruction in 'cmd' spoil any register from 'regs'?
// Returns: index in the 'regs' array or -1
// This function checks the CF_CHGx flags from the instructions array
// Only o_reg operand types are consulted

idaman int ida_export get_spoiled_reg(const uint32 *regs, size_t n);


int ua_out(ea_t ea, bool create_insn);  // Generate text representation of the insn
                                        // Returns length of instruction in bytes
                                        // 0 - bad instruction
                                        // create_insn: modify database if necessary

bool ua_use_fixup(void);                // apply fixups to the instruction
                                        // 'cmd' should be valid

void init_ua(void);
void term_ua(void);
size_t get_equal_items(ea_t ea, size_t itemsize, value_u *v, bool *isdef);


#ifndef NO_OBSOLETE_FUNCS
idaman DEPRECATED void ida_export ua_dodata(ea_t ea, int dtype);                       // use ua_dodata2
idaman DEPRECATED bool ida_export ua_outop(ea_t ea, char *buf, size_t bufsize, int n); // use ua_outop2
idaman DEPRECATED bool ida_export ua_stkvar(const op_t &x, adiff_t v);                 // use ua_stkvar2
idaman DEPRECATED int ida_export ua_ana0(ea_t ea);                                     // use decode_insn
idaman DEPRECATED int ida_export ua_code(ea_t ea);                                     // use create_insn
#endif

#pragma pack(pop)
#endif // _UA_HPP
