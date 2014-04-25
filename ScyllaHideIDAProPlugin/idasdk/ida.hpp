/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2008 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _IDA_HPP
#define _IDA_HPP

#include <pro.h>

#pragma pack(push, 1)   // IDA uses 1 byte alignments!

//
//      This file contains the 'inf' structure definition and some
//      functions common to the whole IDA project.
//      The 'inf' structure is saved in the database and contains information
//      specific to the current program being disassembled.
//      Initially it is filled with values from ida.cfg.
//
//      Althrough it is not a good idea to change values in 'inf'
//      structure (because you will overwrite values taken from ida.cfg),
//      you are allowed to do it if you feel it nesessary.
//

//--------------------------------------------------------------------------
// Known input file formats (kept in inf.filetype):

enum filetype_t
{
  f_EXE_old,            // MS DOS EXE File
  f_COM_old,            // MS DOS COM File
  f_BIN,                // Binary File
  f_DRV,                // MS DOS Driver
  f_WIN,                // New Executable (NE)
  f_HEX,                // Intel Hex Object File
  f_MEX,                // MOS Technology Hex Object File
  f_LX,                 // Linear Executable (LX)
  f_LE,                 // Linear Executable (LE)
  f_NLM,                // Netware Loadable Module (NLM)
  f_COFF,               // Common Object File Format (COFF)
  f_PE,                 // Portable Executable (PE)
  f_OMF,                // Object Module Format
  f_SREC,               // R-records
  f_ZIP,                // ZIP file (this file is never loaded to IDA database)
  f_OMFLIB,             // Library of OMF Modules
  f_AR,                 // ar library
  f_LOADER,             // file is loaded using LOADER DLL
  f_ELF,                // Executable and Linkable Format (ELF)
  f_W32RUN,             // Watcom DOS32 Extender (W32RUN)
  f_AOUT,               // Linux a.out (AOUT)
  f_PRC,                // PalmPilot program file
  f_EXE,                // MS DOS EXE File
  f_COM,                // MS DOS COM File
  f_AIXAR,              // AIX ar library
  f_MACHO,              // Max OS X
};

//--------------------------------------------------------------------------
// information abou the target compiler

typedef uchar comp_t;     // compiler
typedef uchar cm_t;       // calling convention and memory model

struct compiler_info_t
{
  comp_t id;            // compiler id (see typeinf.hpp, COMP_...)
  cm_t cm;              // memory model and calling convention (typeinf.hpp, CM_...)
  uchar size_i;         // sizeof(int)
  uchar size_b;         // sizeof(bool)
  uchar size_e;         // sizeof(enum)
  uchar defalign;       // default alignment for structures
  uchar size_s;         // short
  uchar size_l;         // long
  uchar size_ll;        // longlong
                        // NB: size_ldbl is stored separately!
};

//--------------------------------------------------------------------------
// Storage types for flag bits
enum storage_type_t
{
  STT_CUR = -1, // use current storage type (may be used only as a function argument)
  STT_VA  = 0,  // regular storage: virtual arrays, an explicit flag for each byte
  STT_MM  = 1,  // memory map: sparse storage. useful for huge objects
  STT_DBG = 2,  // memory map: temporary debugger storage. used internally
};


//--------------------------------------------------------------------------
// The database parameters
// This structure is kept in the ida database
// It contains the essential parameters for the current program

#ifdef __EA64__
#define EA64_ALIGN(n) uint32 n;
#else
#define EA64_ALIGN(n)
#endif

struct idainfo
{
  char          tag[3];                 // 'IDA'
  ushort        version;                // Version of database
  char          procName[8];            // Name of current processor
                                        // The terminating zero may be absent
                                        // if the processor name is too long!
  void set_proc_name(const char *name)
  {
    size_t len = strlen(name) + 1;
    memcpy(procName, name, qmin(len, sizeof(procName)));
  }
  char *get_proc_name(char *buf) const
  {
    buf[0] = procName[0];
    buf[1] = procName[1];
    buf[2] = procName[2];
    buf[3] = procName[3];
    buf[4] = procName[4];
    buf[5] = procName[5];
    buf[6] = procName[6];
    buf[7] = procName[7];
    buf[8] = '\0';
    return buf;
  }

  uchar         lflags;                 // Misc. flags
#define LFLG_PC_FPP     0x01            // decode floating point processor
                                        // instructions?
#define LFLG_PC_FLAT    0x02            // Flat model?
#define LFLG_64BIT      0x04            // 64-bit program?
  bool is_32bit(void) const { return (lflags & LFLG_PC_FLAT) != 0; }
  bool is_64bit(void) const { return (lflags & LFLG_64BIT) != 0; }
#define LFLG_DBG_NOPATH 0x08            // do not store input full path
                                        // in debugger process options
#define LFLG_SNAPSHOT   0x10            // memory snapshot was taken?
  bool is_snapshot(void) const { return (lflags & LFLG_SNAPSHOT) != 0; }
#define LFLG_IS_DLL     0x20            // Is dynamic library?
  bool is_dll(void) const { return (lflags & LFLG_IS_DLL) != 0; }

  uchar         demnames;               // display demangled names as:
#define DEMNAM_MASK  3                  // mask for name form
#define  DEMNAM_CMNT 0                  //   comments
#define  DEMNAM_NAME 1                  //   regular names
#define  DEMNAM_NONE 2                  //   don't display
#define DEMNAM_GCC3  4                  // assume gcc3 names (valid for gnu compiler)
  uchar get_demname_form(void) const { return (uchar)(demnames & DEMNAM_MASK); }

  ushort        filetype;               // The input file type (see above)

  bool like_binary(void) const          // is unstructured input file?
  { return filetype == f_BIN
        || filetype == f_HEX
        || filetype == f_MEX
        || filetype == f_SREC; }

  uval_t        fcoresiz;               // size of input file core image
                                        // used to create executable file
  uval_t        corestart;              // start of pages to load
                                        // (offset in the file)

  ushort        ostype;                 // OS type the program is for
                                        // bit definitions in libfuncs.hpp
  ushort        apptype;                // Application type
                                        // bit definitions in libfuncs.hpp
  ea_t          startSP;                // SP register value at the start of
                                        // program execution

  ushort        af;                     // Analysis flags:
#define AF_FIXUP        0x0001          // Create offsets and segments using fixup info
#define AF_MARKCODE     0x0002          // Mark typical code sequences as code
#define AF_UNK          0x0004          // Delete instructions with no xrefs
#define AF_CODE         0x0008          // Trace execution flow
#define AF_PROC         0x0010          // Create functions if call is present
#define AF_USED         0x0020          // Analyze and create all xrefs
#define AF_FLIRT        0x0040          // Use flirt signatures
#define AF_PROCPTR      0x0080          // Create function if data xref data->code32 exists
#define AF_JFUNC        0x0100          // Rename jump functions as j_...
#define AF_NULLSUB      0x0200          // Rename empty functions as nullsub_...
#define AF_LVAR         0x0400          // Create stack variables
#define AF_TRACE        0x0800          // Trace stack pointer
#define AF_ASCII        0x1000          // Create ascii string if data xref exists
#define AF_IMMOFF       0x2000          // Convert 32bit instruction operand to offset
#define AF_DREFOFF      0x4000          // Create offset if data xref to seg32 exists
#define AF_FINAL        0x8000          // Final pass of analysis

  ea_t          startIP;                // IP register value at the start of
                                        // program execution

  ea_t          beginEA;                // Linear address of program entry point
  ea_t          minEA;                  // current limits of program
  ea_t          maxEA;                  // maxEA is excluded
  ea_t          ominEA;                 // original minEA (is set after loading the input file)
  ea_t          omaxEA;                 // original maxEA (is set after loading the input file)

  ea_t          lowoff;                 // Low  limit for offsets
                                        // (used in calculation of 'void' operands)
  ea_t          highoff;                // High limit for offsets
                                        // (used in calculation of 'void' operands)
  uval_t        maxref;                 // Max tail for references
  uchar         ASCIIbreak;             // ASCII line break symbol.
  uchar         wide_high_byte_first;   // Bit order of wide bytes: high byte first?
                                        // (wide bytes: ph.nbits > 8)

  uchar         indent;                 // Indention for instructions
  uchar         comment;                // Indention for comments

  uchar         xrefnum;                // Number of references to generate
                                        // 0 - xrefs won't be generated at all
  uchar         s_entab;                // Use '\t' chars in the output file?
  uchar         specsegs;               // New format of special segments?
  uchar         s_void;                 // Display void marks?
  uchar         s_reserved2;            // obsolete
  uchar         s_showauto;             // Display autoanalysis indicator?
  uchar         s_auto;                 // Autoanalysis is enabled?
  uchar         s_limiter;              // Generate delimiters:
#define LMT_THIN        0x01            //  thin borders
#define LMT_THICK       0x02            //  thick borders
#define LMT_EMPTY       0x04            //  empty lines at the end of basic blocks
  uchar         s_null;                 // Generate empty lines?
  uchar         s_genflags;             // General flags:
#define INFFL_LZERO     0x01            //  generate leading zeroes in numbers
#define INFFL_ALLASM    0x02            //  may use constructs not supported by
                                        //  the target assembler
  bool use_allasm(void) const { return (s_genflags & INFFL_ALLASM) != 0; }
#define INFFL_LOADIDC   0x04            //  loading an idc file that contains database info
  bool loading_idc(void) const { return (s_genflags & INFFL_LOADIDC) != 0; }
  uchar         s_showpref;             // Show line prefixes?
  uchar         s_prefseg;              // line prefixes with segment name?

  uchar         asmtype;                // target assembler number
  uval_t        baseaddr;               // base address of the program (paragraphs)

  uchar         s_xrefflag;
#define SW_SEGXRF       0x01            // show segments in xrefs?
#define SW_XRFMRK       0x02            // show xref type marks?
#define SW_XRFFNC       0x04            // show function offsets?
#define SW_XRFVAL       0x08            // show xref values? (otherwise-"...")

  short         binSize;                // # of instruction bytes to show
                                        // in line prefix
  uchar         s_cmtflg;               // comments:
#define SW_RPTCMT       0x01            //   show repeatable comments?
#define SW_ALLCMT       0x02            //   comment all lines?
#define SW_NOCMT        0x04            //   no comments at all
#define SW_LINNUM       0x08            //   show source line numbers
#define SW_TESTMODE     0x10            //   testida.idc is running
#define SW_SHHID_ITEM   0x20            //   show hidden instructions
#define SW_SHHID_FUNC   0x40            //   show hidden functions
#define SW_SHHID_SEGM   0x80            //   show hidden segments

  char          nametype;               // dummy names represenation type
#define NM_REL_OFF      0
#define NM_PTR_OFF      1
#define NM_NAM_OFF      2
#define NM_REL_EA       3
#define NM_PTR_EA       4
#define NM_NAM_EA       5
#define NM_EA           6
#define NM_EA4          7
#define NM_EA8          8
#define NM_SHORT        9
#define NM_SERIAL       10
  uchar         s_showbads;             // show bad instructions?
                                        // an instruction is bad if it appears
                                        // in the ash.badworks array

  uchar         s_prefflag;
#define PREF_SEGADR     0x01            // show segment addresses?
#define PREF_FNCOFF     0x02            // show function offsets?
#define PREF_STACK      0x04            // show stack pointer?
#define PREF_VARMARK    0x08            // show asterisk for variable addresses?

  uchar         s_packbase;             // pack database?
  uchar         asciiflags;             // ASCII string flags
#define ASCF_GEN        0x01            //   generate ASCII names?
#define ASCF_AUTO       0x02            //   ASCII names have 'autogenerated' bit?
#define ASCF_SERIAL     0x04            //   generate serial names?
#define ASCF_UNICODE    0x08            //   unicode strings are present?
#define ASCF_COMMENT    0x10            //   generate auto comment for ascii references?
#define ASCF_SAVECASE   0x20            //   preserve case of ascii strings for identifiers
  uchar         listnames;              // What names should be included in the list?
#define LN_NORMAL       0x01            //   normal names
#define LN_PUBLIC       0x02            //   public names
#define LN_AUTO         0x04            //   autogenerated names
#define LN_WEAK         0x08            //   weak names
  char          ASCIIpref[16];          // ASCII names prefix
  uval_t        ASCIIsernum;            // serial number
  char          ASCIIzeroes;            // leading zeroes
  uchar         graph_view;             // currently using graph options (dto.graph)
  uchar         s_reserved5;            // old memory model & calling convention
  uchar         tribyte_order;          // tribyte_order_t: order of bytes in 3-byte items
  uchar         mf;                     // Byte order: is MSB first?
  uchar         s_org;                  // Generate 'org' directives?
  uchar         s_assume;               // Generate 'assume' directives?
  uchar         s_checkarg;             // Check manual operands?
  sel_t         start_ss;               // selector of the initial stack segment
  sel_t         start_cs;               // selector of the segment with the main entry point
  ea_t          main;                   // address of main()
  uint32         short_demnames;        // short form of demangled names
  EA64_ALIGN(align_short_demnames)
  uint32         long_demnames;         // long form of demangled names
                                        // see demangle.h for definitions
  EA64_ALIGN(align_long_demnames)
  uval_t        datatypes;              // data types allowed in data carousel
                                        // used in MakeData command.
  int32          strtype;               // current ascii string type
                                        // see nalt.hpp for string types
  EA64_ALIGN(align_strtype)
  ushort        af2;                    // Analysis flags 2:
#define AF2_JUMPTBL     0x0001          // Locate and create jump tables
#define AF2_DODATA      0x0002          // Coagulate data segs at the final pass
#define AF2_HFLIRT      0x0004          // Automatically hide library functions
#define AF2_STKARG      0x0008          // Propagate stack argument information
#define AF2_REGARG      0x0010          // Propagate register argument information
#define AF2_CHKUNI      0x0020          // Check for unicode strings
#define AF2_SIGCMT      0x0040          // Append a signature name comment for recognized anonymous library functions
#define AF2_SIGMLT      0x0080          // Allow recognition of several copies of the same function
#define AF2_FTAIL       0x0100          // Create function tails
#define AF2_DATOFF      0x0200          // Automatically convert data to offsets
#define AF2_ANORET      0x0400          // Perform 'no-return' analysis
#define AF2_VERSP       0x0800          // Perform full SP-analysis (ph.verify_sp)
#define AF2_DOCODE      0x1000          // Coagulate code segs at the final pass
#define AF2_TRFUNC      0x2000          // Truncate functions upon code deletion
#define AF2_PURDAT      0x4000          // Control flow to data segment is ignored

  ushort        namelen;                // max name length (without zero byte)
  ushort        margin;                 // max length of data lines
  ushort        lenxref;                // max length of line with xrefs
  char          lprefix[16];            // prefix of local names
                                        // if a new name has this prefix,
                                        // it will be automatically converted to a local name
  uchar         lprefixlen;             // length of the lprefix
  compiler_info_t cc;                   // Target compiler
  uint32        database_change_count;  // incremented after each byte and regular
                                        // segment modifications
  uchar         size_ldbl;              // sizeof(long double) if different from ph.tbyte_size
  uint32        appcall_options;        // appcall options, see idd.hpp

  uchar         reserved[55];           // 55 zero bytes for the future
                                        // total size: 256 bytes (for 32bit)

  void init(void);
  bool retrieve(void);                  // low level function to get this
                                        // structure from the database
  bool read(const char *basename);      // high level function to get
                                        // this structure from the database
                                        // and convert to the current format
  void write(void);                     // write back to the database
};

idaman idainfo ida_export_data inf;        // program specific information

// Dual options are different for the text and graph views
// The UI will refresh them when the user switches from one view type to the other
// A copy of the current options is kept in the 'inf' structure
// The text and graph options are stored separately in 'RootNode'.
struct dual_text_options_t
{
  int mysize;       // size of this structure
  uchar graph_view; // Graph options?
  uchar xrefnum;    // Number of references to generate
  uchar s_showpref; // Show line prefixes?
  uchar comment;    // Indentation for comments
  uchar indent;     // Indentation for instructions
  uchar s_limiter;  // Generate delimiters
  ushort margin;    // Right margin
  ushort binSize;   // # of instruction bytes to show
  dual_text_options_t(bool for_graph) { init(for_graph); }
  dual_text_options_t(const idainfo &_inf) { copy_from_inf(_inf); }
  void init(bool for_graph);
  void copy_to_inf(idainfo &inf) const;
  void copy_from_inf(const idainfo &inf);
  bool restore(bool for_graph);
  void save(bool for_graph) const;
};

struct text_options_t
{
  dual_text_options_t text;
  dual_text_options_t graph;
  text_options_t(void) : text(false), graph(true) {}
  void copy_to_inf(bool gv, idainfo &_inf) { (gv ? graph : text).copy_to_inf(_inf); }
  void copy_from_inf(const idainfo &_inf) { (_inf.graph_view ? graph : text).copy_from_inf(_inf); }
};

idaman text_options_t ida_export_data dto; // text and graph view options

inline bool idaapi showRepeatables(void) { return (inf.s_cmtflg & SW_RPTCMT) != 0; }
inline bool idaapi showAllComments(void) { return (inf.s_cmtflg & SW_ALLCMT) != 0; }
inline bool idaapi showComments(void)    { return (inf.s_cmtflg & SW_NOCMT)  == 0; }
inline bool idaapi should_trace_sp(void) { return (inf.af & AF_TRACE) != 0; }
inline bool idaapi should_create_stkvars(void) { return (inf.af & AF_LVAR) != 0; }

//------------------------------------------------------------------------//
// user defined data for linearray_t: int *flag
// *flag value is a combination of:
#define IDAPLACE_HEXDUMP 0x000F  // produce hex dump
#define IDAPLACE_STACK   0x0010  // produce 2/4/8 bytes per undefined item
                                 // (used to display the stack contents)
                                 // the number of displayed bytes depends on the stack bitness
// not used yet because it confuses users:
//#define IDAPLACE_SHOWPRF 0x0020  // display line prefixes
#define IDAPLACE_SEGADDR 0x0040  // display line prefixes with the segment part

inline int calc_default_idaplace_flags(void)
{
  int flags = 0;
//  if ( inf.s_showpref ) flags |= IDAPLACE_SHOWPRF;
  if ( inf.s_prefflag & PREF_SEGADR )
    flags |= IDAPLACE_SEGADDR;
  return flags;
}

//------------------------------------------------------------------------//
// Maximum address allowed to use in the program being disassebled.
// This is obsolete, don't use it!

#ifdef __EA64__
#ifdef __GNUC__
#define MAXADDR         0xFF00000000000000ll    // Max allowed address in IDA (excluded)
#else
#define MAXADDR         0xFF00000000000000ui64  // Max allowed address in IDA (excluded)
#endif
#else
#define MAXADDR         0xFF000000L             // Max allowed address in IDA (excluded)
#endif


//------------------------------------------------------------------------//
// convert (seg,off) value to a linear address

inline ea_t idaapi toEA(sel_t reg_cs,ea_t reg_ip)
{
  return (reg_cs<<4) + reg_ip;
}


//------------------------------------------------------------------------//
// IDA databases are in the OEM encoding (user comments, etc)

#define IDB_OEM

// Helper functions to convert input/output data (OEM<->ANSI conversions)
// These functions return the destination string

idaman char *ida_export idb2scr(char *name);
idaman char *ida_export scr2idb(char *name);

// Helper function to convert strings from the input file to database encoding
// under windows
inline char *idaapi ansi2idb(char *name)
{
#if defined(IDB_OEM) && defined(__NT__) && !defined(UNDER_CE)
  char2oem(name);
#endif
  return name;
}

#define IDB_EXT32 "idb"
#define IDB_EXT64 "i64"
#ifdef __EA64__
#define IDB_EXT IDB_EXT64
#else
#define IDB_EXT IDB_EXT32
#endif

// Helper functions to copy dual options
idaman void ida_export dto_copy_to_inf(const dual_text_options_t *, idainfo *inf);
idaman void ida_export dto_copy_from_inf(dual_text_options_t *, const idainfo *inf);
idaman void ida_export dto_init(dual_text_options_t *dt, bool for_graph);

inline void dual_text_options_t::copy_to_inf(idainfo &_inf) const { dto_copy_to_inf(this, &_inf); }
inline void dual_text_options_t::copy_from_inf(const idainfo &_inf) { dto_copy_from_inf(this, &_inf); }
inline void dual_text_options_t::init(bool for_graph) { dto_init(this, for_graph); }

#pragma pack(pop)
#endif // _IDA_HPP
