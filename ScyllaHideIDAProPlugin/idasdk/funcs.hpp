/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2008 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef FUNCS_HPP
#define FUNCS_HPP
#include <area.hpp>
#include <bytes.hpp>
#pragma pack(push, 1)           // IDA uses 1 byte alignments!

//
//      This file contains routines for working with functions within the
//      disassembled program.
//
//      This file also contains routines for working with library signatures
//      (e.g. FLIRT).
//
//      Each function consists of function chunks. At least one function chunk
//      must be present in the function definition - the function entry chunk.
//      Other chunks are called function tails. There may be several of them
//      for a function.
//
//      A function tail is a continuous range of addresses.
//      It can be used in the definition of one or more functions.
//      One function using the tail is singled out and called the tail owner.
//      This function is considered as 'possessing' the tail.
//      get_func() on a tail address will return the function possessing the tail.
//      You can enumerate the functions using the tail by using func_parent_iterator_t.
//
//      Each function chunk in the disassembly is represented as an "area" (a range
//      of addresses, see area.hpp for details) with characteristics.
//
//      A function entry must start with an instruction (code) byte.
//
struct stkpnt_t;                // #include <frame.hpp>
struct regvar_t;                // #include <frame.hpp>
struct llabel_t;                // #include <frame.hpp>

struct regarg_t                 // register argument description
{                               // regargs are destroyed when the full function
  int reg;                      // type is determined
  type_t *type;
  char *name;
};


//------------------------------------------------------------------------
// A function is a set of continuous ranges of addresses with characteristics:

class func_t : public area_t
{
public:
  ushort flags;
#define FUNC_NORET      0x00000001     // Function doesn't return
#define FUNC_FAR        0x00000002     // Far function
#define FUNC_LIB        0x00000004     // Library function

//oaidl.h also defines FUNC_STATIC
#ifdef NO_OBSOLETE_FUNCS
# define FUNC_STATICDEF  0x00000008     // Static function
#else
# define FUNC_STATIC     0x00000008     // Static function
#endif

#define FUNC_FRAME      0x00000010     // Function uses frame pointer (BP)
#define FUNC_USERFAR    0x00000020     // User has specified far-ness
                                       // of the function
#define FUNC_HIDDEN     0x00000040     // A hidden function chunk
#define FUNC_THUNK      0x00000080     // Thunk (jump) function
#define FUNC_BOTTOMBP   0x00000100     // BP points to the bottom of
                                       // the stack frame
#define FUNC_NORET_PENDING 0x00200     // Function 'non-return' analysis
                                       // must be performed. This flag is
                                       // verified upon func_does_return()
#define FUNC_SP_READY   0x00000400     // SP-analysis has been performed
                                       // If this flag is on, the stack
                                       // change points should not be not
                                       // modified anymore. Currently this
                                       // analysis is performed only for PC
#define FUNC_PURGED_OK  0x00004000     // 'argsize' field has been validated.
                                       // If this bit is clear and 'argsize'
                                       // is 0, then we do not known the real
                                       // number of bytes removed from
                                       // the stack. This bit is handled
                                       // by the processor module.
#define FUNC_TAIL       0x00008000     // This is a function tail.
                                       // Other bits must be clear
                                       // (except FUNC_HIDDEN)

  bool is_far(void) const { return (flags & FUNC_FAR) != 0; }
  bool does_return(void) const { return (flags & FUNC_NORET) == 0; }
  bool analyzed_sp(void) const { return (flags & FUNC_SP_READY) != 0; }
#ifndef SWIG
  union
  {
    struct              // attributes of a function entry chunk
    {
#endif // SWIG
      //
      // Stack frame of the function. It is represented as a structure:
      //
      //    +----------------------------------------+
      //    | function arguments                     |
      //    +----------------------------------------+
      //    | return address (isn't stored in func_t)|
      //    +----------------------------------------+
      //    | saved registers (SI,DI,etc)            |
      //    +----------------------------------------+ <- typical BP
      //    |                                        |  |
      //    |                                        |  | fpd
      //    |                                        |  |
      //    |                                        | <- real BP
      //    | local variables                        |
      //    |                                        |
      //    |                                        |
      //    +----------------------------------------+ <- SP
      //
      uval_t frame;        // netnode id of frame structure. use get_frame()
      asize_t frsize;      // size of local variables part of frame in bytes
                           // this value is used as offset for BP
                           // (only if FUNC_FRAME is set)
      ushort frregs;       // size of saved registers in frame
      asize_t argsize;     // number of bytes purged from the stack
                           // upon returning
      asize_t fpd;         // frame pointer delta (usually 0, i.e. realBP==typicalBP)
                           // use update_fpd() to modify it

      bgcolor_t color;     // user defined function color

        // the following fields should not be accessed directly:

      ushort pntqty;       // number of SP change points
      stkpnt_t *points;    // array of SP change points
                           // use ...stkpnt...() functions to access this array

      int regvarqty;       // number of register variables (-1-not read in yet)
                           // use find_regvar() to read register variables
      regvar_t *regvars;   // array of register variables
                           // this array is sorted by: startEA
                           // use ...regvar...() functions to access this array

      int llabelqty;       // number of local labels
      llabel_t *llabels;   // local labels
                           // this array is sorted by ea
                           // use ...llabel...() functions to access this array

      int regargqty;       // number of register arguments
      regarg_t *regargs;   // unsorted array of register arguments
                           // use ...regarg...() functions to access this array

      int tailqty;         // number of function tails
      area_t *tails;       // array of tails, sorted by ea
                           // use func_tail_iterator_t to access function tails
#ifndef SWIG
    };
    struct                 // attributes of a function tail chunk
    {
#endif // SWIG
      ea_t owner;          // the address of the main function possessing this tail
      int refqty;          // number of referers
      ea_t *referers;      // array of referers (function start addresses)
                           // use func_parent_iterator_t to access the referers
#ifndef SWIG
    };
  };
#endif // SWIG
};
DECLARE_TYPE_AS_MOVABLE(func_t);

inline bool is_func_entry(const func_t *pfn) { return pfn != NULL && (pfn->flags & FUNC_TAIL) == 0; }
inline bool is_func_tail(const func_t *pfn) { return pfn != NULL && (pfn->flags & FUNC_TAIL) != 0; }

idaman areacb_t ida_export_data funcs;      // area control block for functions


// Helper class to lock a function pointer so it stays valid
class lock_func
{
  const func_t *pfn;
public:
  lock_func(const func_t *_pfn) : pfn(_pfn)
  {
    areacb_t_lock_area(&funcs, pfn);
  }
  ~lock_func(void)
  {
    areacb_t_unlock_area(&funcs, pfn);
  }
};

// Is a function pointer locked?
inline bool is_func_locked(const func_t *pfn)
{
  return areacb_t_get_area_locks(&funcs, pfn) > 0;
}

//--------------------------------------------------------------------
//      F U N C T I O N S
//--------------------------------------------------------------------
// Get pointer to function structure by address
//      ea - any address in a function
// Returns ptr to a function or NULL
// This function returns a function entry chunk

idaman func_t *ida_export get_func(ea_t ea);


// Does the given function contain the given address?
// returns: the number of function tail chunk
//          0 means the 'pfn' itself contains it
//          -1 means 'does not contain'

idaman int ida_export get_func_chunknum(func_t *pfn, ea_t ea);
inline bool func_contains(func_t *pfn, ea_t ea)
{
  return get_func_chunknum(pfn, ea) >= 0;
}


// Get pointer to function structure by number
//      n - number of function, is in range 0..get_func_qty()-1
// Returns ptr to a function or NULL
// This function returns a function entry chunk

idaman func_t *ida_export getn_func(size_t n);


// Get total number of functions in the program

idaman size_t ida_export get_func_qty(void);


// Get ordinal number of a function
//      ea - any address in the function
// Returns number of function (0..get_func_qty()-1)
// -1 means 'no function at the specified address'

idaman int ida_export get_func_num(ea_t ea);


// Get pointer to the previous function
//      ea - any address in the program
// Returns ptr to function or NULL if previous function doesn't exist

idaman func_t *ida_export get_prev_func(ea_t ea);


// Get pointer to the next function
//      ea - any address in the program
// Returns ptr to function or NULL if next function doesn't exist

idaman func_t *ida_export get_next_func(ea_t ea);


// Get function limits
// The function limits is the minimal area containing all addresses
// belonging to the function
// returns: true-ok, false-wrong arguments

idaman bool ida_export get_func_limits(func_t *pfn, area_t *limits);


// Get function comment
//      fn        - ptr to function structure
//      repetable - get repetable comment?
// returns: comment or NULL. The caller must qfree() the result.
// In fact this function works with function chunks too

inline char *get_func_cmt(func_t *fn ,bool repeatable)
                { return funcs.get_area_cmt(fn, repeatable); }


// Set function comment
//      fn        - ptr to function structure
//      repetable - set repetable comment?
// In fact this function works with function chunks too

inline bool set_func_cmt(func_t *fn, const char *cmt, bool repeatable)
                { return funcs.set_area_cmt(fn, cmt, repeatable); }


// Delete function comment
//      fn        - ptr to function structure
//      repetable - delete repetable comment?
// In fact this function works with function chunks

inline void del_func_cmt(func_t *fn, bool repeatable)
                { funcs.del_area_cmt(fn, repeatable); }


// Update information about a function in the database (func_t)
//      fn - ptr to function structure with updated information
// You must not change the function start and end addresses using this function.
// Use ui_func_setstart() and ui_func_setend() for it.
// returns: 1-ok,0-failure

inline bool update_func(func_t *fn) { return funcs.update(fn) != 0; }


// Add a new function
//   fn - ptr to filled function structure
// If the fn->endEA is BADADDR, then
// IDA will try to determine the function bounds
// by calling find_func_bounds(..., FIND_FUNC_DEFINE);
//
// If ea1 is in the middle of an existing function,
// the kernel will try to shrink it to make room for the new function.
// returns: 1-ok, 0-failure

idaman bool ida_export  add_func_ex(func_t *fn);


// Add a new function
//      ea1 - start address
//      ea2 - end address
//
// If the function end address is BADADDR, then
// IDA will try to determine the function bounds
// by calling find_func_bounds(..., FIND_FUNC_DEFINE);
//
// If ea1 is in the middle of an existing function,
// the kernel will try to shrink it to make room for the new function.
// returns: 1-ok, 0-failure

idaman bool ida_export add_func(ea_t ea1, ea_t ea2);


// Delete a function
//      ea - any address in the function entry chunk
// returns: 1-ok,0-failure

idaman bool ida_export del_func(ea_t ea);


// Move function chunk start address
//      ea       - any address in the function
//      newstart - new end address of the function
// returns: MOVE_FUNC_...

idaman int ida_export func_setstart(ea_t ea, ea_t newstart);
#define MOVE_FUNC_OK            0  // ok
#define MOVE_FUNC_NOCODE        1  // no instruction at 'newstart'
#define MOVE_FUNC_BADSTART      2  // bad new start address
#define MOVE_FUNC_NOFUNC        3  // no function at 'ea'
#define MOVE_FUNC_REFUSED       4  // a plugin refused the action


// Move function chunk end address
//      ea     - any address in the function
//      newend - new end address of the function
// returns: 1-ok,0-failure

idaman bool ida_export func_setend(ea_t ea, ea_t newend);


// Reanalyze a function
//      pfn - pointer to a function
//      ea1 - start of the area to analyze
//      ea2 - end of area to analyze
//      analyze_parents - meaningful only if pfn points to a function tail
//              if true, all tail parents will be reanalyzed
//              if false, only the given tail will be reanalized
// This function analyzes all chunks of the given function
// Optional parameters (ea1,ea2) may be used to narrow the analyzed area

idaman void ida_export reanalyze_function(func_t *pfn,
                                          ea_t ea1=0,
                                          ea_t ea2=BADADDR,
                                          bool analyze_parents=false);


// Initialize the function structure

idaman void ida_export clear_func_struct(func_t *fn);


// Determine the boundaries of a new function
//      ea    - starting address of a new function
//      nfn   - structure to fill with information
//      flags - composition of the following bits:
#define FIND_FUNC_NORMAL   0x0000 // stop processing if undefined byte is encountered
#define FIND_FUNC_DEFINE   0x0001 // create instruction if undefined byte is encountered
#define FIND_FUNC_IGNOREFN 0x0002 // ignore existing function boundaries
                                  // by default the function returns function boundaries
                                  // if ea belongs to a function
// This function tries to find the start and end addresses of a new function.
// returns a code, see below
// This function calls the module with ph.func_bounds to allows it to
// fine tune the function boundaries.
// It returns one of FIND_FUNC_... constants

idaman int ida_export find_func_bounds(ea_t ea, func_t *nfn, int flags);

#define FIND_FUNC_UNDEF 0       // the function has instructions that
                                // pass execution flow to unexplored bytes
                                // nfn->endEA will have the address of the unexplored byte
#define FIND_FUNC_OK    1       // ok, 'nfn' is ready for add_func()
#define FIND_FUNC_EXIST 2       // a function exists already,
                                // its bounds are returned in 'nfn'


// Get function name
//      ea     - any address in the function
//      buf    - buffer for the answer
//      bufsize- size of the output buffer
// returns: function name or NULL

idaman char *ida_export get_func_name(ea_t ea, char *buf, size_t bufsize);


// Get function bitness (which is equal to the function segment bitness)
//      0 - 16, 1- 32, 2 - 64
// pfn==NULL => returns 0

idaman int ida_export get_func_bitness(const func_t *pfn);

// Get number of bits in the function addressing
inline int idaapi get_func_bits(func_t *pfn) { return 1 << (get_func_bitness(pfn)+4); }

// Get number of bytes in the function addressing
inline int idaapi get_func_bytes(func_t *pfn) { return get_func_bits(pfn)/8; }


// Is the function visible (not hidden)?

inline bool is_visible_func(func_t *pfn) { return (pfn->flags & FUNC_HIDDEN) == 0; }

inline bool is_finally_visible_func(func_t *pfn) // is function visible?
 { return (inf.s_cmtflg & SW_SHHID_FUNC) != 0 || is_visible_func(pfn); }

// Set visibility of function

idaman void ida_export set_visible_func(func_t *pfn, bool visible);


// Give a meaningful name to function if it consists of only 'jump' instruction
//      fn      - pointer to function (may be NULL)
//      oldname - old name of function.
//                if old name was in "j_..." form, then we may discard it
//                and set a new name.
//                if oldname is not known, you may pass NULL.
// returns: 1-ok,0-failure

idaman int ida_export set_func_name_if_jumpfunc(func_t *fn, const char *oldname);


// Calculate target of a thunk function
//      fn      - pointer to function (may not be NULL)
//      fptr    - out: will hold address of a function pointer (if indirect jump)
// returns: the target function or BADADDR

idaman ea_t ida_export calc_thunk_func_target(func_t *fn, ea_t *fptr);


// Convert address to "funcname+offset" text form.
//      ea  - linear address
//      buf - output buffer
//      bufsize - size of the output buffer
// returns: NULL if no function is found at 'ea'
//          "funcname+offset" otherwise

idaman char *ida_export a2funcoff(ea_t ea, char *buf, size_t bufsize);


// Generate standard function header lines using MakeLine()
//      pfn - pointer to function structure

idaman void ida_export std_gen_func_header(func_t *pfn);


// Does the function return?
// To calculate the answer, FUNC_NORET flag and has_noret() are consulted
// The latter is required for imported functions in the .idata section.
// Since in .idata we have only function pointers but not functions, we have
// to introduce a special flag for them.

idaman bool ida_export func_does_return(ea_t callee);


// Signal a non-returning instruction
// This function can be used by the processor module to tell the kernel
// about non-returning instructions (like call exit). The kernel will
// perform the global function analysis and find out if the function
// returns at all. This analysis will be done at the first call to func_does_return()
// Returns: true if the instruction 'noret' flag has been changed

idaman bool ida_export set_noret_insn(ea_t insn_ea, bool noret);


//--------------------------------------------------------------------
//      F U N C T I O N  C H U N K S
//--------------------------------------------------------------------
// Get pointer to function chunk structure by address
//      ea - any address in a function chunk
// Returns ptr to a function chunk or NULL
// This function may return a function entry as well as a function tail

inline func_t *get_fchunk(ea_t ea) { return (func_t *)funcs.get_area(ea); }


// Get pointer to function chunk structure by number
//      n - number of function chunk, is in range 0..get_fchunk_qty()-1
// Returns ptr to a function chunk or NULL
// This function may return a function entry as well as a function tail

inline func_t *getn_fchunk(int n) { return (func_t *)funcs.getn_area(n); }


// Get total number of function chunks in the program

inline size_t get_fchunk_qty(void) { return funcs.get_area_qty(); }


// Get ordinal number of a function chunk in the global list of function chunks
//      ea - any address in the function chunk
// Returns number of function chunk (0..get_fchunk_qty()-1)
// -1 means 'no function chunk at the specified address'

inline int get_fchunk_num(ea_t ea) { return funcs.get_area_num(ea); }


// Get pointer to the previous function chunk in the global list
//      ea - any address in the program
// Returns ptr to function chunk or NULL if previous function chunk doesn't exist

inline func_t *get_prev_fchunk(ea_t ea) { return getn_fchunk(funcs.get_prev_area(ea)); }


// Get pointer to the next function chunk in the global list
//      ea - any address in the program
// Returns ptr to function chunk or NULL if next function chunk doesn't exist

inline func_t *get_next_fchunk(ea_t ea) { return getn_fchunk(funcs.get_next_area(ea)); }


//--------------------------------------------------------------------
// Functions to manipulate function chunks

// Append a new tail chunk to the function definition
// If the tail already exists, then it will simply be added to the function tail list
// Otherwise a new tail will be created and its owner will be set to be our function
// If a new tail can not be created, then this function will fail
//      ea1 - start of the tail. If a tail already exists at the specified address
//            it must start at 'ea1'
//      ea2 - end of the tail. If a tail already exists at the specified address
//            it must end at 'ea2'

idaman bool ida_export append_func_tail(func_t *pfn, ea_t ea1, ea_t ea2);


// Remove a function tail
// If the tail belongs only to one function, it will be completely removed
// Otherwise if the function was the tail owner, the first function using
// this tail becomes the owner of the tail.

idaman bool ida_export remove_func_tail(func_t *pfn, ea_t tail_ea);


// Set a function as the possessing function of a function tail.
// The function should already refer to the tail (after append_func_tail)

idaman bool ida_export set_tail_owner(func_t *fnt, ea_t func_start);


// Auxiliary function(s) to be used in func_..._iterator_t

class func_parent_iterator_t;
class func_tail_iterator_t;
class func_item_iterator_t;

#define DECLARE_FUNC_ITERATORS(prefix) \
prefix bool ida_export func_tail_iterator_set(func_tail_iterator_t *fti, func_t *pfn, ea_t ea);\
prefix bool ida_export func_tail_iterator_set2(func_tail_iterator_t *fti, func_t *pfn, ea_t ea);\
prefix bool ida_export func_tail_iterator_set_ea(func_tail_iterator_t *fti, ea_t ea);\
prefix bool ida_export func_parent_iterator_set(func_parent_iterator_t *fpi, func_t *pfn);\
prefix bool ida_export func_parent_iterator_set2(func_parent_iterator_t *fpi, func_t *pfn);\
prefix bool ida_export func_item_iterator_next(func_item_iterator_t *fii, testf_t *testf, void *ud);\
prefix bool ida_export func_item_iterator_prev(func_item_iterator_t *fii, testf_t *testf, void *ud);\
prefix bool ida_export func_item_iterator_decode_prev_insn(func_item_iterator_t *fii);\
prefix bool ida_export func_item_iterator_decode_preceding_insn(func_item_iterator_t *fii, eavec_t *visited, bool *p_farref);
DECLARE_FUNC_ITERATORS(idaman)


// helper function to accept any address
inline bool idaapi f_any(flags_t, void *) { return true; }

// Class to enumerate all function tails sorted by addresses.
// Enumeration is started with main(), first(), or last()
// If first() is used, the function entry chunk will be excluded from the enumeration.
// Otherwise it will be included in the enumeration (for main() and last())
// The loop may continue until the next() or prev() function returns false.
// These functions return false when the enumeration is over.
// The tail chunks are always sorted by their addresses.
// Sample code:
//      func_tail_iterator_t fti(pfn);
//      for ( bool ok=fti.first(); ok; ok=fti.next() )
//        const area_t &a = fti.chunk();
//        ....
// If the 'ea' parameter is used in the constructor, then the iterator is positioned
// at the chunk containing the specified 'ea'. Otherwise it is positioned at the
// function entry chunk.
// If 'pfn' is specified as NULL then the set() function will fail,
// but it is still possible to use the class. In this case the iteration will be
// limited by the segment boundaries.
// The function main chunk is locked during the iteration.
// It is also possible to enumerate one single arbitrary area using set_range()
// This function is mainly designed to be used from func_item_iterator_t

class func_tail_iterator_t
{
  DECLARE_FUNC_ITERATORS(friend)
  func_t *pfn;
  int idx;
  area_t seglim;        // valid and used only if pfn == NULL
public:
  func_tail_iterator_t(void) : pfn(NULL) {}
  func_tail_iterator_t(func_t *_pfn, ea_t ea=BADADDR) : pfn(NULL) { set(_pfn, ea); }
  ~func_tail_iterator_t(void)
  {
    // if was iterating over function chunks, unlock the main chunk
    if ( pfn != NULL )
      areacb_t_unlock_area(&funcs, pfn);
  }
  bool set(func_t *_pfn, ea_t ea=BADADDR) { return func_tail_iterator_set2(this, _pfn, ea); }
  bool set_ea(ea_t ea) { return func_tail_iterator_set_ea(this, ea); }
  // set an arbitrary range
  bool set_range(ea_t ea1, ea_t ea2)
  {
    this->~func_tail_iterator_t();
    pfn = NULL;
    idx = -1;
    seglim = area_t(ea1, ea2);
    return !seglim.empty();
  }
  const area_t &chunk(void) const { if ( pfn == NULL ) return seglim; return idx >= 0 ? pfn->tails[idx] : *(area_t*)pfn; }
  bool first(void) { if ( pfn != NULL ) { idx = 0; return pfn->tailqty > 0; } return false; } // get only tail chunks
  bool last(void) { if ( pfn != NULL ) { idx = pfn->tailqty - 1; return true; } return false; }  // get all chunks (the entry chunk last)
  bool next(void) { if ( pfn != NULL && idx+1 < pfn->tailqty ) { idx++; return true; } return false; }
  bool prev(void) { if ( idx >= 0 ) { idx--; return true; } return false; }
  bool main(void) { idx = -1; return pfn != NULL; }  // get all chunks (the entry chunk first)
};


// Function to iterate function chunks (all of them including the entry chunk)
//      pfn - pointer to the function
//      func - function to call for each chunk
//      ud - user data for 'func'
//      include_parents - meaningful only if pfn points to a function tail
//              if true, all tail parents will be iterated
//              if false, only the given tail will be iterated

idaman void ida_export iterate_func_chunks(
                          func_t *pfn,
                          void (idaapi *func)(ea_t ea1, ea_t ea2, void *ud),
                          void *ud=NULL,
                          bool include_parents=false);


// Class to enumerate all function instructions and data sorted by addresses.
// The function entry chunk items are enumerated first regardless of their addresses
// Sample code:
//      func_item_iterator_t fii;
//      for ( bool ok=fii.set(pfn, ea); ok; ok=fii.next_addr() )
//        ea_t ea = fii.current();
//        ....
// If 'ea' is not specified in the call to set(), then the enumeration starts at
// the function entry point.
// If 'pfn' is specified as NULL then the set() function will fail,
// but it is still possible to use the class. In this case the iteration will be
// limited by the segment boundaries.
// It is also possible to enumerate addresses in an arbitrary area using set_range()

class func_item_iterator_t
{
  DECLARE_FUNC_ITERATORS(friend)
  func_tail_iterator_t fti;
  ea_t ea;
public:
  func_item_iterator_t(void) {}
  func_item_iterator_t(func_t *pfn, ea_t _ea=BADADDR) { set(pfn, _ea); }
  // set a function range. if pfn == NULL then a segment range will be set
  bool set(func_t *pfn, ea_t _ea=BADADDR)
  {
    ea = (_ea != BADADDR || pfn == NULL) ? _ea : pfn->startEA;
    return fti.set(pfn, _ea);
   }
  // set an arbitrary range
  bool set_range(ea_t ea1, ea_t ea2) { ea = ea1; return fti.set_range(ea1, ea2); }
  bool first(void) { if ( !fti.main() ) return false; ea=fti.chunk().startEA; return true; }
  bool last(void) { if ( !fti.last() ) return false; ea=fti.chunk().endEA; return true; }
  ea_t current(void) const { return ea; }
  const area_t &chunk(void) const { return fti.chunk(); }
  bool next(testf_t *func, void *ud) { return func_item_iterator_next(this, func, ud); }
  bool prev(testf_t *func, void *ud) { return func_item_iterator_prev(this, func, ud); }
  bool next_addr(void) { return next(f_any, NULL); }
  bool next_head(void) { return next(f_isHead, NULL); }
  bool next_code(void) { return next(f_isCode, NULL); }
  bool next_data(void) { return next(f_isData, NULL); }
  bool next_not_tail(void) { return next(f_isNotTail, NULL); }
  bool prev_addr(void) { return prev(f_any, NULL); }
  bool prev_head(void) { return prev(f_isHead, NULL); }
  bool prev_code(void) { return prev(f_isCode, NULL); }
  bool prev_data(void) { return prev(f_isData, NULL); }
  bool prev_not_tail(void) { return prev(f_isNotTail, NULL); }
  bool decode_prev_insn(void) { return func_item_iterator_decode_prev_insn(this); }
  bool decode_preceding_insn(eavec_t *visited, bool *p_farref)
    { return func_item_iterator_decode_preceding_insn(this, visited, p_farref); }
};

// Class to enumerate all function parents sorted by addresses.
// Enumeration is started with first() or last()
// The loop may continue until the next() or prev() function returns false.
// The parent functions are always sorted by their addresses.
// The tail chunk is locked during the iteration.
// Sample code:
//      func_parent_iterator_t fpi(fnt);
//      for ( bool ok=fpi.first(); ok; ok=fpi.next() )
//        ea_t parent = fpi.parent();
//        ....

class func_parent_iterator_t
{
  DECLARE_FUNC_ITERATORS(friend)
  func_t *fnt;
  int idx;
public:
  func_parent_iterator_t(void) : fnt(NULL) {}
  func_parent_iterator_t(func_t *_fnt) : fnt(NULL) { set(_fnt); }
  ~func_parent_iterator_t(void)
  {
    if ( fnt != NULL )
      areacb_t_unlock_area(&funcs, fnt);
  }
  bool set(func_t *_fnt) { return func_parent_iterator_set2(this, _fnt); }
  ea_t parent(void) const { return fnt->referers[idx]; }
  bool first(void) { idx = 0; return is_func_tail(fnt) && fnt->refqty > 0; }
  bool last(void) { idx = fnt->refqty - 1; return idx >= 0; }
  bool next(void) { if ( idx+1 < fnt->refqty ) { idx++; return true; } return false; }
  bool prev(void) { if ( idx > 0 ) { idx--; return true; } return false; }
  void reset_fnt(func_t *_fnt) { fnt = _fnt; } // for internal use only!
};


// Get previous/next address in the function
// Unlike func_item_iterator_t which always enumerates the main function
// chunk first, these functions respect linear address ordering.

idaman ea_t ida_export get_prev_func_addr(func_t *pfn, ea_t ea);
idaman ea_t ida_export get_next_func_addr(func_t *pfn, ea_t ea);


//--------------------------------------------------------------------
// Functions to work with temporary register argument definitions

idaman void ida_export read_regargs(func_t *pfn);
idaman void ida_export add_regarg(func_t *pfn, int reg, const type_t *type, const char *name);
void del_regargs(ea_t ea);      // low level
int write_regargs(func_t *pfn);
regarg_t *find_regarg(func_t *pfn, int reg);
void free_regarg(regarg_t *v);

//--------------------------------------------------------------------
//      L I B R A R Y   M O D U L E   S I G N A T U R E S
//--------------------------------------------------------------------

// Error codes for signature functions:

#define IDASGN_OK       0       // ok
#define IDASGN_BADARG   1       // bad number of signature
#define IDASGN_APPLIED  2       // signature is already applied
#define IDASGN_CURRENT  3       // signature is currently being applied
#define IDASGN_PLANNED  4       // signature is planned to be applied


// Add a signature file to the list of planned signature files.
//      fname - file name. should not contain directory part.
// returns: 0-failed, otherwise number of planned (and applied) signatures

idaman int ida_export plan_to_apply_idasgn(const char *fname); // plan to use library


// Start application of signature file
//      advance - 0: apply the current file from the list of planned
//                   signature files
//                1: apply the next file from the list of planned
//                   signature files
// returns: 1-signature file is successfully loaded
//          0-failure, a warning was disaplyed

idaman bool ida_export apply_idasgn(int advance);         // switch to current/next library


// Apply a signature file to the specified address
//      signame    - short name of signature file (the file name without path)
//      ea         - address to apply the signature
//      is_startup - if set, then the signature is treated as a startup one
//                   for startup signature ida doesn't rename the first
//                   function of the applied module.
// returns: LIBFUNC_... codes, see below.

idaman int ida_export apply_idasgn_to(const char *signame, ea_t ea, bool is_startup);


// Get number of signatures in the list of planned and applied signatures
// Returns: 0..n

idaman int ida_export get_idasgn_qty(void);


// Get number of the the current signature
// Returns: 0..n-1

idaman int ida_export get_current_idasgn(void);


// Get state of a signature in the list of planned signatures
//      n - number of signature in the list (0..get_idasgn_qty()-1)
// Returns: state of signature or IDASGN_BADARG

idaman int ida_export calc_idasgn_state(int n);


// Remove signature from the list of planned signatures
//      n - number of signature in the list (0..get_idasgn_qty()-1)
// returns: IDASGN_OK, IDASGN_BADARG, IDASGN_APPLIED

idaman int ida_export del_idasgn(int n);


// Get information about a signature in the list
//      n       - number of signature in the list (0..get_idasgn_qty()-1)
//      signame - buffer for the name of the signature
//                (short form, only base name without the directory part
//                 will be stored)
//                if signame == NULL, then the name won't be returned
//      signamesize - sizeof(signame)
//      optlibs - buffer for the names of the optional libraries
//                if optlibs == NULL, then the optional libraries are not returned
//      optlibssize - sizeof(optlibs)
// Returns: number of successfully recognized modules using this signature
//          -1 means the 'n' is a bad argument, i.e. no signature with this
//              number exists.

idaman int32 ida_export get_idasgn_desc(
        int n,
        char *signame,
        size_t signamesize,
        char *optlibs,
        size_t optlibssize);


// Get full path of a signature file
//      signame - short name of a signature
//      buf     - the output buffer
//      bufsize - sizeof(buf)
// returns: full path to the signature file
// This function doesn't test the presence of the file

idaman char *ida_export get_sig_filename(
        char *buf,
        size_t bufsize,
        const char *signame);


// Get idasgn header by a short signature name
//      name - short name of a signature
// Returns NULL-can't find the signature

class idasgn_t;
idaman idasgn_t *ida_export get_idasgn_header_by_short_name(const char *name);


// Get full description of the signature by its short name
//      name - short name of a signature
//      buf     - the output buffer
//      bufsize - sizeof(buf)
// Returns NULL-can't find the signature
//         otherwise returns the description of the signature

idaman char *ida_export get_idasgn_title(
        const char *name,
        char *buf,
        size_t bufsize);

// Determine compiler/vendor using the startup signatures.
// If determined, then appropriate signature files are included into
// the list of planned signature files.

idaman void ida_export determine_rtl(void);


// Apply a startup signature file to the specified address
//      ea - address to apply the signature to; usually inf.beginEA
//      startup - the name of the signature file without path and extension
// returns: true if successfully applied the signature

idaman bool ida_export apply_startup_sig(ea_t ea, const char *startup);


// Apply the currently loaded signature file to the specified address.
// If a library function is found, then create a function and name
// it accordingly.
//      ea - any address in the program
// returns: code, see below.

idaman int ida_export try_to_add_libfunc(ea_t ea); // try to find and create library function

#define LIBFUNC_FOUND   0               // ok, library function is found
#define LIBFUNC_NONE    1               // no, this is not a library function
#define LIBFUNC_DELAY   2               // no decision because of lack of information

// KERNEL mode functions

// init/save/term signatures. only the kernel calls these functions

       void init_signatures(void);
inline void save_signatures(void) {}
       void term_signatures(void);


void init_funcs(void);  // Initialize work with functions
void save_funcs(void);  // Flush information about function to the disk
void term_funcs(void);  // Terminate work with functions

void move_funcs(ea_t from, ea_t to, asize_t size);

// set noret flag for "exit" functions
bool copy_noret_info(func_t *fn, ea_t to, const char *name=NULL);
void recalc_func_noret_flag(func_t *pfn);
bool plan_for_noret_analysis(ea_t insn_ea);

bool invalidate_sp_analysis(func_t *pfn);
inline bool invalidate_sp_analysis(ea_t ea)
  { return invalidate_sp_analysis(get_func(ea)); }

void create_func_eas_array(void);       // for old databases

ea_t auto_add_func_tails(ea_t ea);      // auto: append function tail
bool read_tails(func_t *pfn);

#pragma pack(pop)
#endif
