/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2008 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _LINES_HPP
#define _LINES_HPP
#pragma pack(push, 1)           // IDA uses 1 byte alignments!

//
//      This file contains high level functions that deal with the generation
//      of the disassembled text lines.
//
//      Also it contains definitions for the syntax highlighting.
//
//      Finally there are functions that deal with anterior/posterior
//      user-defined lines.
//

#include <ida.hpp>

struct area_t;

//------------------------------------------------------------------------
//      C O L O R   D E F I N I T I O N S
//------------------------------------------------------------------------

//
//      Information required for the syntax highlighting is embedded into
//      the generated line in the form of escape sequences.
//      IDP module should insert appropriate escape characters into the
//      output lines as nesessary. This approach allows to create an IDP
//      module without the syntax highlighting too - just don't use
//      escape sequences.
//
//      A typical color sequence looks like this:
//
//      COLOR_ON COLOR_xxx text COLOR_OFF COLOR_xxx
//
//      The first 2 items turn color 'xxx' on, then the text follows,
//      and the color is turned off by two last items.
//
//      For the convenience we've defined a set of macro definitions
//      and functions to deal with colors.
//

// ---------------- Color escape sequence defitions -------------------------

#define COLOR_ON        '\1'    // Escape character (ON)
                                // Followed by a color code (color_t)
#define COLOR_OFF       '\2'    // Escape character (OFF)
                                // Followed by a color code (color_t)
#define COLOR_ESC       '\3'    // Escape character (Quote next character)
                                // This is needed to output '\1' and '\2'
                                // characters
#define COLOR_INV       '\4'    // Escape character (Inverse foreground and background colors)
                                // This escapse character has no corresponding COLOR_OFF
                                // It's action continues up the next COLOR_INV or end of line

#define SCOLOR_ON       "\1"    // Escape character (ON)
#define SCOLOR_OFF      "\2"    // Escape character (OFF)
#define SCOLOR_ESC      "\3"    // Escape character (Quote next character)
#define SCOLOR_INV      "\4"    // Escape character (Inverse colors)

inline bool requires_color_esc(char c) { return c >= COLOR_ON && c <= COLOR_INV; }

typedef uchar color_t;
const color_t
  COLOR_DEFAULT  = 0x01,         // Default
  COLOR_REGCMT   = 0x02,         // Regular comment
  COLOR_RPTCMT   = 0x03,         // Repeatable comment (comment defined somewhere else)
  COLOR_AUTOCMT  = 0x04,         // Automatic comment
  COLOR_INSN     = 0x05,         // Instruction
  COLOR_DATNAME  = 0x06,         // Dummy Data Name
  COLOR_DNAME    = 0x07,         // Regular Data Name
  COLOR_DEMNAME  = 0x08,         // Demangled Name
  COLOR_SYMBOL   = 0x09,         // Punctuation
  COLOR_CHAR     = 0x0A,         // Char constant in instruction
  COLOR_STRING   = 0x0B,         // String constant in instruction
  COLOR_NUMBER   = 0x0C,         // Numeric constant in instruction
  COLOR_VOIDOP   = 0x0D,         // Void operand
  COLOR_CREF     = 0x0E,         // Code reference
  COLOR_DREF     = 0x0F,         // Data reference
  COLOR_CREFTAIL = 0x10,         // Code reference to tail byte
  COLOR_DREFTAIL = 0x11,         // Data reference to tail byte
  COLOR_ERROR    = 0x12,         // Error or problem
  COLOR_PREFIX   = 0x13,         // Line prefix
  COLOR_BINPREF  = 0x14,         // Binary line prefix bytes
  COLOR_EXTRA    = 0x15,         // Extra line
  COLOR_ALTOP    = 0x16,         // Alternative operand
  COLOR_HIDNAME  = 0x17,         // Hidden name
  COLOR_LIBNAME  = 0x18,         // Library function name
  COLOR_LOCNAME  = 0x19,         // Local variable name
  COLOR_CODNAME  = 0x1A,         // Dummy code name
  COLOR_ASMDIR   = 0x1B,         // Assembler directive
  COLOR_MACRO    = 0x1C,         // Macro
  COLOR_DSTR     = 0x1D,         // String constant in data directive
  COLOR_DCHAR    = 0x1E,         // Char constant in data directive
  COLOR_DNUM     = 0x1F,         // Numeric constant in data directive
  COLOR_KEYWORD  = 0x20,         // Keywords
  COLOR_REG      = 0x21,         // Register name
  COLOR_IMPNAME  = 0x22,         // Imported name
  COLOR_SEGNAME  = 0x23,         // Segment name
  COLOR_UNKNAME  = 0x24,         // Dummy unknown name
  COLOR_CNAME    = 0x25,         // Regular code name
  COLOR_UNAME    = 0x26,         // Regular unknown name
  COLOR_COLLAPSED= 0x27,         // Collapsed line
  COLOR_FG_MAX   = 0x28,         // Max color number

  // Fictive colors

  COLOR_ADDR     = COLOR_FG_MAX, // hidden address marks
                                 // The address is represented as 8digit
                                 // hex number: 01234567
                                 // It doesn't have COLOR_OFF pair
                                 // NB: for 64-bit IDA, the address is 16digit

#define COLOR_ADDR_SIZE (sizeof(ea_t)*2)

  COLOR_OPND1    = COLOR_ADDR+1, // Instruction operand 1
  COLOR_OPND2    = COLOR_ADDR+2, // Instruction operand 2
  COLOR_OPND3    = COLOR_ADDR+3, // Instruction operand 3
  COLOR_OPND4    = COLOR_ADDR+4, // Instruction operand 4
  COLOR_OPND5    = COLOR_ADDR+5, // Instruction operand 5
  COLOR_OPND6    = COLOR_ADDR+6, // Instruction operand 6


  COLOR_UTF8     = COLOR_ADDR+10;// Following text is UTF-8 encoded

// The following definitions are used in COLSTR() macro:

#define SCOLOR_DEFAULT   "\x01"  // Default
#define SCOLOR_REGCMT    "\x02"  // Regular comment
#define SCOLOR_RPTCMT    "\x03"  // Repeatable comment (defined not here)
#define SCOLOR_AUTOCMT   "\x04"  // Automatic comment
#define SCOLOR_INSN      "\x05"  // Instruction
#define SCOLOR_DATNAME   "\x06"  // Dummy Data Name
#define SCOLOR_DNAME     "\x07"  // Regular Data Name
#define SCOLOR_DEMNAME   "\x08"  // Demangled Name
#define SCOLOR_SYMBOL    "\x09"  // Punctuation
#define SCOLOR_CHAR      "\x0A"  // Char constant in instruction
#define SCOLOR_STRING    "\x0B"  // String constant in instruction
#define SCOLOR_NUMBER    "\x0C"  // Numeric constant in instruction
#define SCOLOR_VOIDOP    "\x0D"  // Void operand
#define SCOLOR_CREF      "\x0E"  // Code reference
#define SCOLOR_DREF      "\x0F"  // Data reference
#define SCOLOR_CREFTAIL  "\x10"  // Code reference to tail byte
#define SCOLOR_DREFTAIL  "\x11"  // Data reference to tail byte
#define SCOLOR_ERROR     "\x12"  // Error or problem
#define SCOLOR_PREFIX    "\x13"  // Line prefix
#define SCOLOR_BINPREF   "\x14"  // Binary line prefix bytes
#define SCOLOR_EXTRA     "\x15"  // Extra line
#define SCOLOR_ALTOP     "\x16"  // Alternative operand
#define SCOLOR_HIDNAME   "\x17"  // Hidden name
#define SCOLOR_LIBNAME   "\x18"  // Library function name
#define SCOLOR_LOCNAME   "\x19"  // Local variable name
#define SCOLOR_CODNAME   "\x1A"  // Dummy code name
#define SCOLOR_ASMDIR    "\x1B"  // Assembler directive
#define SCOLOR_MACRO     "\x1C"  // Macro
#define SCOLOR_DSTR      "\x1D"  // String constant in data directive
#define SCOLOR_DCHAR     "\x1E"  // Char constant in data directive
#define SCOLOR_DNUM      "\x1F"  // Numeric constant in data directive
#define SCOLOR_KEYWORD   "\x20"  // Keywords
#define SCOLOR_REG       "\x21"  // Register name
#define SCOLOR_IMPNAME   "\x22"  // Imported name
#define SCOLOR_SEGNAME   "\x23"  // Segment name
#define SCOLOR_UNKNAME   "\x24"  // Dummy unknown name
#define SCOLOR_CNAME     "\x25"  // Regular code name
#define SCOLOR_UNAME     "\x26"  // Regular unknown name
#define SCOLOR_COLLAPSED "\x27"  // Collapsed line
#define SCOLOR_ADDR      "\x28"  // Hidden address mark


// This macro is used in string constants to turn them into colored
// strings:

#define COLSTR(str,tag) SCOLOR_ON tag str SCOLOR_OFF tag


//------------------------------------------------------------------------

// Convenience functions.
// NOTE: higher level convenience functions are defined in ua.hpp
//       Please use the following functions only if functions from ua.hpp
//       are not useful in your case.


// Append 'turn on color' sequence to a string.
//      ptr - pointer to the output buffer
//      end - pointer to the end of the buffer
//      tag - color tag (one of COLOR_...)
// returns: ptr to end of string

idaman char *ida_export tag_on(char *ptr, char *end, color_t tag);


// Append 'turn off color' sequence to a string.
//      ptr - pointer to the output buffer
//      end - pointer to the end of the buffer
//      tag - color tag (one of COLOR_...)
// returns: ptr to end of string

idaman char *ida_export tag_off(char *ptr, char *end, color_t tag);


// Append a colored character to a string.
//      ptr - pointer to the output buffer
//      end - pointer to the end of the buffer
//      tag - color tag (one of COLOR_...)
//      chr - character to append
// returns: ptr to end of string

idaman char *ida_export tag_addchr(char *ptr, char *end, color_t tag, char chr);


// Append a colored substring to a string.
//      ptr - pointer to the output buffer
//      end - pointer to the end of the buffer
//      tag - color tag (one of COLOR_...)
//      chr - substring to append
// returns: ptr to end of string

idaman char *ida_export tag_addstr(char *ptr, char *end, color_t tag, const char *string);


// Append an address mark to a string
//      ptr - pointer to the output buffer
//      end - pointer to the end of the buffer
//      ea  - address to include
// returns: ptr to end of string

idaman char *ida_export tag_addr(char *ptr, char *end, ea_t ea);


// Move pointer to a 'line' to 'cnt' positions right.
// Take into account escape sequences.
//      line - pointer to string
//      cnt  - number of positions to move right
// returns: moved pointer

idaman const char *ida_export tag_advance(const char *line, int cnt);


// Move the pointer past all color codes
// arg: line, can't be NULL
// returns: moved pointer, can't be NULL

idaman const char *ida_export tag_skipcodes(const char *line);


// Skip one color code
// returns: moved pointer
// This function should be used if you are interested in color codes
// and want to analyze all of them.
// Otherwise tag_skipcodes() function is better since it will skip all colors at once.
// This function will skip the current color code if there is one.
// If the current symbol is not a color code, it will return the input

idaman const char *ida_export tag_skipcode(const char *line);


// Calculate length of a colored string, -1 if error

idaman ssize_t ida_export tag_strlen(const char *line);


// Remove color escape sequences from a string
//      inptr   - input colored string.
//      buf     - output buffer
//                if == NULL, then return -1
//      bufsize - size of output buffer
//                if == 0, then don't check size of output buffer
// input and output buffer may be the same
// returns: length of resulting string, -1 if error

idaman ssize_t ida_export tag_remove(const char *instr, char *buf, size_t bufsize);


// ---------------- Line prefix colors --------------------------------------

//      Line prefix colors are not used in modules

#define COLOR_DEFAULT    0x01   // Default
#define COLOR_SELECTED   0x02   // Selected
#define COLOR_LIBFUNC    0x03   // Library function
#define COLOR_REGFUNC    0x04   // Regular function
#define COLOR_CODE       0x05   // Single instruction
#define COLOR_DATA       0x06   // Data bytes
#define COLOR_UNKNOWN    0x07   // Unexplored byte
#define COLOR_EXTERN     0x08   // External name definition segment
#define COLOR_CURITEM    0x09   // Current item
#define COLOR_CURLINE    0x0A   // Current line
#define COLOR_HIDLINE    0x0B   // Hidden line
#define COLOR_BG_MAX     0x0C   // Max color number

#define PALETTE_SIZE       (COLOR_FG_MAX+COLOR_BG_MAX)

idaman color_t   ida_export calc_prefix_color(ea_t ea);  // COLOR... constants
idaman bgcolor_t ida_export calc_bg_color(ea_t ea);      // RGB color

// Structure to keep some background colors configurable in ida.cfg
struct bgcolors_t
{
  bgcolor_t prolog_color;
  bgcolor_t epilog_color;
  bgcolor_t switch_color;
};
extern bgcolors_t bgcolors;

//------------------------------------------------------------------------
//      S O U R C E   F I L E S
//------------------------------------------------------------------------

// IDA can keep information about source files used to create the program.
// Each source file is represented by a range of addresses.
// A source file may contains several address ranges.

// init/save/term work with source files.
// These functions are called from the kernel at the start.

       void init_sourcefiles(void);
inline void save_sourcefiles(void) {}
       void term_sourcefiles(void);
       void move_sourcefiles(ea_t from, ea_t to, asize_t size);


// Mark a range of address as belonging to a source file
// An address range may belong only to one source file.
// A source file may be represented by several address ranges.
//      ea1     - linear address of start of the address range
//      ea2     - linear address of end of the address range (excluded)
//      filename- name of source file.
// returns: 1-ok, 0-failed.

idaman bool ida_export add_sourcefile(ea_t ea1,ea_t ea2,const char *filename);


// Get name of source file occupying the given address
//      ea     - linear address
//      bounds - pointer to the output buffer with the address range
//               for the current file. May be NULL.
// returns: NULL - source file information is not found
//          otherwise returns pointer to file name

idaman const char *ida_export get_sourcefile(ea_t ea, area_t *bounds=NULL);


// Delete information about the source file
//      ea - linear address
// returns: 1-ok, 0-failed

idaman bool ida_export del_sourcefile(ea_t ea);


//------------------------------------------------------------------------
//      G E N E R A T I O N  O F  D I S A S S E M B L E D  T E X T
//------------------------------------------------------------------------

// The following variables control generation of additional information.
// Initially they are set to 0, you should set them to 1 when you want
// additional information generated upon calling MakeLine()

idaman char ida_export_data gl_comm;   // generate comment at the next call to MakeLine()
idaman char ida_export_data gl_name;   // generate name    at the next call to MakeLine()
idaman char ida_export_data gl_xref;   // generate xrefs   at the next call to MakeLine()


// The following variables contain lengths of line prefix and binary line prefix
// accordingly. You can use them IDP modules to calculate nesessary indentions
// and the resulting string length if you need to.

idaman int ida_export_data gl_psize;  // Line prefix width (set by setup_makeline)
idaman int ida_export_data gl_bpsize; // Binary line prefix width (set by setup_makeline)


// User-defined line-prefixes are displayed just after the autogenerated
// line prefixes. In order to use them, the plugin should call the
// following function to specify its width and contents.
//      width - the width of the user-defined prefix
//      get_user_defined_prefix - a callback to get the contents of the
//                                prefix. Its arguments:
//                      ea     - linear address
//                      indent - indent of the line contents
//                               -1 means the default instruction
//                               indent and is used for instruction
//                               itself. see explanations for printf_line()
//                      line   - the line to be generated.
//                               the line usually contains color tags
//                               this argument can be examined to decide
//                               whether to generated the prefix
//                      buf    - the output buffer
//                      bufsize- the size of the output buffer
// In order to remove the callback before unloading the plugin,
// specify the width or the callback == NULL.

idaman void ida_export set_user_defined_prefix(size_t width,
                        void (idaapi*get_user_defined_prefix)(ea_t ea,
                                                        int lnnum,
                                                        int indent,
                                                        const char *line,
                                                        char *buf,
                                                        size_t bufsize));


// Generate ONE line of disassembled text. You may call this function from
// out.cpp as many times as you need to generate all lines for an item
// (instruction or data).
//      contents - colored line to generate
//      indent   - see explaination for printf_line()
// returns: 1-you've made too many calls to MakeLine(), you should stop
//            calling MakeLine() and return to the caller.
//            The current limit is 500 lines per item.
//          0-ok

idaman bool ida_export MakeLine(const char *contents,int indent=-1);


// Generate ONE line of disassembled text. You may call this function from
// out.cpp as many times as you need to generate all lines for an item
// (instruction or data).
//      format   - printf style colored line to generate
//      indent   - indention of the line
//                 if indent == -1, the kernel with indent the line
//                 at inf.indent. if indent < 0, -indent will be used for indention
//                 The first line printed with indent < 0 is considered as the
//                 most important line at the current address. Usually it is
//                 the line with the instruction itself. This line will be
//                 displayed in the cross-reference lists and other places.
//                 If you need to output an additional before the main line
//                 then pass inf.indent instead of -1. The kernel will know
//                 that your line is not the most important one.
// returns: 1-you've made too many calls to printf_line(), you should stop
//            calling printf_line() and return to the caller.
//            The current limit is 500 lines per item.
//          0-ok

idaman AS_PRINTF(2, 0) bool ida_export printf_line_v(
        int indent,
        const char *format,
        va_list va);

AS_PRINTF(2, 3) inline bool printf_line(int indent, const char *format, ...)
{
  va_list va;
  va_start(va,format);
  bool code = printf_line_v(indent,format,va);
  va_end(va);
  return code;
}


// Generate empty line. This function does nothing if generation of empty
// lines is disabled.
// returns: 1-the limit of lines per item is reached
//            The current limit is determined by MAX_ITEM_LINES in IDA.CFG
//          0-ok

idaman bool ida_export MakeNull(void);


// Generate thin border line. This function does nothing if generation
// of border lines is disabled.
// returns: 1-the limit of lines per item is reached
//            The current limit is determined by MAX_ITEM_LINES in IDA.CFG
//          0-ok

idaman bool ida_export MakeBorder(void);


// Generate solid border line.
// returns: 1-the limit of lines per item is reached
//            The current limit is determined by MAX_ITEM_LINES in IDA.CFG
//          0-ok

idaman bool ida_export MakeSolidBorder (void);

// Generate one non-indented comment line, colored with COLOR_AUTOCMT
//      format - printf() style format line. The resulting comment line
//               should not include comment character (;)
// returns: 1-the limit of lines per item is reached
//          0-ok

idaman AS_PRINTF(2, 0) bool ida_export gen_colored_cmt_line_v(
        color_t color,
        const char *format,
        va_list va);

AS_PRINTF(1, 0) inline bool gen_cmt_line_v(const char *format, va_list va)
{
  return gen_colored_cmt_line_v(COLOR_AUTOCMT, format, va);
}

AS_PRINTF(1, 2) inline bool gen_cmt_line(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  bool code = gen_cmt_line_v(format, va);
  va_end(va);
  return code;
}

// Generate one non-indented comment line, colored with COLOR_COLLAPSED
//      format - printf() style format line. The resulting comment line
//               should not include comment character (;)
// returns: 1-you've made too many calls to MakeLine(), you should stop
//            calling MakeLine() and return to the caller.
//          0-ok

AS_PRINTF(1, 2) inline bool gen_collapsed_line(const char *format, ...)
{
  va_list va;
  va_start(va,format);
  bool answer = gen_colored_cmt_line_v(COLOR_COLLAPSED, format, va);
  va_end(va);
  return answer;
}

// Generate big non-indented comment lines.
//      cmt - comment text. may contain '\n' characters to denote new lines.
//            should not contain comment character (;)
//      color - color of comment text (one of COLOR_...)
// returns: 1-you've made too many calls to MakeLine(), you should stop
//            calling MakeLine() and return to the caller.
//            The current limit is 500 lines per item.
//          0-ok

idaman bool ida_export generate_big_comment(const char *cmt, color_t color);


// Generate many non-indented lines.
//      string - text. may contain '\n' characters to denote new lines.
//      color  - color of the text (one of COLOR_...)
// returns: 1-you've made too many calls to MakeLine(), you should stop
//            calling MakeLine() and return to the caller.
//            The current limit is 500 lines per item.
//          0-ok

idaman bool ida_export generate_many_lines(const char *string, color_t color);


//------------------------------------------------------------------------
//      A N T E R I O R / P O S T E R I O R  L I N E S
//------------------------------------------------------------------------

// Add anterior/posterior line(s)
// This is low level function. Use describe() or add_long_cmt() instead.
//      ea     - linear address
//      prefix - prefix to use at the start of each line
//      isprev - do we add anterior lines? (0-no, posterior)
//      format - printf() style format string. may contain '\n' to denote
//               new lines.
//      va     - parameteres for format

idaman AS_PRINTF(4, 0) void ida_export describex(
        ea_t ea,
        const char *prefix,
        bool isprev,
        const char *format,
        va_list va);


// Add anterior/posterior line(s)
//      ea     - linear address
//      isprev - do we add anterior lines? (0-no, posterior)
//      format - printf() style format string. may contain '\n' to denote
//               new lines.

AS_PRINTF(3, 4) inline void describe(ea_t ea, bool isprev, const char *format, ...)
{
  va_list va;
  va_start(va,format);
  describex(ea,NULL,isprev,format,va);
  va_end(va);
}


// Add anterior/posterior comment line(s)
//      ea     - linear address
//      isprev - do we add anterior lines? (0-no, posterior)
//      format - printf() style format string. may contain '\n' to denote
//               new lines. The resulting string should not contain comment
//               characters (;), the kernel will add them automatically

idaman AS_PRINTF(3, 0) void ida_export add_long_cmt_v(
        ea_t ea,
        bool isprev,
        const char *format,
        va_list va);

AS_PRINTF(3, 4) inline void add_long_cmt(ea_t ea, bool isprev, const char *format, ...)
{
  va_list va;
  va_start(va,format);
  add_long_cmt_v(ea, isprev, format, va);
  va_end(va);
}



// Add anterior/posterior comment line(s) at the start of program
//      format - printf() style format string. may contain '\n' to denote
//               new lines. The resulting string should not contain comment
//               characters (;), the kernel will add them automatically

AS_PRINTF(1, 2) inline void add_pgm_cmt(const char *format, ...)
{
  va_list va;
  va_start(va,format);
  add_long_cmt_v(inf.minEA, true, format, va);
  va_end(va);
}


//------------------------------------------------------------------------
//      The following functions are used in kernel only:

int gen_xref_lines(             // returns < 0 - overflow
        ea_t genEA,            // otherwise number of xrefs displayed
        ea_t (idaapi*first)(ea_t),
        ea_t (idaapi*next) (ea_t,ea_t),
        const char *tag,
        color_t color,
        int maxrefnum,
        size_t tail_depth,
        int checkflags);

typedef ssize_t idaapi ml_getcmt_t(color_t *cmttype, char *buf, size_t bufsize);
typedef ssize_t idaapi ml_getnam_t(color_t *namtype, char *buf, size_t bufsize);
typedef bool    idaapi ml_genxrf_t(void); // returns: overflow
typedef bool    idaapi ml_saver_t(const char *line); // returns: overflow

idaman void ida_export setup_makeline(
        ea_t ea,                                // address to generate lines for
        const char *prefix,
        ml_getcmt_t *getcmt,
        ml_getnam_t *getnam,
        ml_genxrf_t *genxrf,
        ml_saver_t *saver,
        int flags);
#define MAKELINE_NONE           0x00
#define MAKELINE_BINPREF        0x01
#define MAKELINE_VOID           0x02
#define MAKELINE_STACK          0x04

idaman bool ida_export save_line_in_array(const char *line);      // a standard line saver()
idaman void ida_export init_lines_array(char *lnar[],int maxsize);// initialization function for it

idaman int ida_export finish_makeline(bool restart_comments=false);  // returns number of generated lines

idaman int ida_export generate_disassembly(
                                // Generate disassembly (many lines)
                                // and put them into a buffer
                                // Returns number of generated lines
        ea_t ea,                // address to generate disassembly for
        char *lines[],          // buffer to hold pointer to generated lines
        int bufsize,            // size of buffer
        int *lnnum,             // number of "the most interesting" line
                                // may be NULL
        bool as_stack);         // Display undefined items as 2/4/8 bytes

idaman bool ida_export generate_disasm_line(
                                // Generate one line of disassembly
                                // This function discards all "non-interesting" lines
                                // It is designed to generate one-line desriptions
                                // of addresses for lists, etc.
        ea_t ea,                // address to generate disassembly for
        char *buf,              // pointer to the output buffer
        size_t bufsize,         // size of the output buffer
        int flags=0);
#define GENDSM_FORCE_CODE 1     // generate a disassembly line as if
                                // there is an instruction at 'ea'
#define GENDSM_MULTI_LINE 2     // if the instruction consists of several lines,
                                // produce all of them (useful for parallel instructions)


// Generate label, function header, stack variable definitions, etc.
// returns: overflow

int gen_labeled_line(ea_t ea);


// Generate local label if it exists
//      make_null - generate an empty line before generating a local label
// returns: overflow

int gen_lname_line(ea_t ea, bool make_null);


// A makeline producer is a function which completes the generation
// of a line. Its usual duties are to attach indented comments, xrefs,
// void marks and similar things to the line and call the saver function.
// Actually the producer gets what you send to MakeLine as argumens.
// There are several line producers in the kernel. They are invisible outside.

typedef bool idaapi makeline_producer_t(const char *line, int indent);


// set a new producer and get the old one
// if a producer is set to NULL, then the output lines won't be generated

makeline_producer_t *set_makeline_producer(makeline_producer_t *mp);


// Get pointer to the sequence of characters denoting 'close comment'
// empty string means no comment (the current assembler has no open-comment close-comment pairs)
// This function uses ash.cmnt2

idaman const char *ida_export closing_comment(void);


// Generate the closing comment if any
//      ptr - pointer to the output buffer
//      end - the end of the output buffer
// returns: pointer past the comment

inline char *close_comment(char *ptr, char *end)
{
  APPEND(ptr, end, closing_comment());
  return ptr;
}


//------------------------------------------------------------------------

// Every anterior/posterior line has its number.
// Anterior  lines have numbers from E_PREV
// Posterior lines have numbers from E_NEXT

const int E_PREV = 1000;
const int E_NEXT = 2000;

void    copy_extra_lines(ea_t from, ea_t to, int what);

bool                  ExtraLines (ea_t ea, int start);   // 1-overflow
void                  ExtraKill  (ea_t ea);              // kill all extra lines
idaman int ida_export ExtraFree  (ea_t ea, int start);

int Dumper(ea_t EA, char* Answer[],int maxsize, void *ud);

// these functions are for the kernel only:

inline void init_lines(void) {}
inline void save_lines(void) {}
       void term_lines(void);

extern char gl_namedone; // name has been generated for the current item

extern bool data_as_stack;      // display undefined data as 2/4/8 bytes
                                // depends on IDAPLACE_STACK
                                // used by intel_data()

int calc_stack_alignment(ea_t ea); // calculate stack alignment, returns 2, 4, or 8
idaman ea_t ida_export align_down_to_stack(ea_t newea);
idaman ea_t ida_export align_up_to_stack(ea_t ea1, ea_t ea2=BADADDR);

// remove all spaces at the end of a colored string if any
char *remove_spaces(char *buf, char *end, char *ptr);

#pragma pack(pop)
#endif
