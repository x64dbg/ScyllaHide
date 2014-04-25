/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2008 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _SEGMENT_HPP
#define _SEGMENT_HPP
#pragma pack(push, 1)           // IDA uses 1 byte alignments!

//
//      This file contains functions that deal with program segmentation.
//      IDA requires that all program addresses belong to segments
//      (each address must belong to exactly one segment).
//      Situation when an address doesn't belong to any segment
//      is allowed as temporary situation only when the user changes program
//      segmentation. Bytes outside a segment can't be converted to
//      instructions, have names, comments, etc.
//      Each segment has its start address, ending address and represents
//      a contiguous range of addresses. There might be unused holes between
//      segments.
//
//      Each segment has its unique segment selector. This selector is used
//      to distinguish the segment from other segments. For 16-bit programs
//      the selector is equal to the segment base paragraph. For 32-bit
//      programs there is special array to translate the selectors to
//      the segment base paragraphs. A selector is a 32/64 bit value.
//
//      The segment base paragraph determines the offsets in the segment.
//      If the start address of the segment == (base << 4) then the first
//      offset in the segment will be 0. The start address should be
//      higher or equal to (base << 4).
//      We will call the offsets in the segment 'virtual addresses'.
//      So, virtual address of the first byte of segment is
//
//              (start address of segment - segment base linear address)
//
//      For IBM PC, virtual address corresponds to offset part of address.
//      For other processors (Z80, for example), virtual address corresponds
//      to Z80 addresses and linear addresses are used only internally.
//      For MS Windows programs the segment base paragraph is 0 and therefore
//      the segment virtual addresses are equal to linear addresses.
//

//-------------------------------------------------------------------------
#include <ida.hpp>
#include <area.hpp>             // segments are range of addresses
                                // with characteristics

// area control block for segments

idaman areacb_t ida_export_data segs;


// Maximum number of segment registers is 16 (see srarea.hpp)

#define SREG_NUM 16


//-------------------------------------------------------------------------
//      D E F I N I T O N   O F   S E G M E N T   S T R U C T U R E
//-------------------------------------------------------------------------

class segment_t : public area_t
{
public:
  // constructor
  segment_t(void)       { memset(this,0,sizeof(segment_t)); color = DEFCOLOR; }

/*  8 */  uval_t name;          // use get/set_segm_name() functions
/* 12 */  uval_t sclass;        // use get/set_segm_class() functions
/* 16 */  uval_t orgbase;       // this field is IDP dependent.
                                // you may keep your information about
                                // the segment here

// Segment alignment codes

/* 20 */  uchar align;

#define saAbs           0 // Absolute segment.
#define saRelByte       1 // Relocatable, byte aligned.
#define saRelWord       2 // Relocatable, word (2-byte) aligned.
#define saRelPara       3 // Relocatable, paragraph (16-byte) aligned.
#define saRelPage       4 // Relocatable, aligned on 256-byte boundary
#define saRelDble       5 // Relocatable, aligned on a double word (4-byte)
                          // boundary.
#define saRel4K         6 // This value is used by the PharLap OMF for page (4K)
                          // alignment. It is not supported by LINK.
#define saGroup         7 // Segment group
#define saRel32Bytes    8 // 32 bytes
#define saRel64Bytes    9 // 64 bytes
#define saRelQword     10 // 8 bytes
#define saRel128Bytes  11 // 128 bytes
#define saRel512Bytes  12 // 512 bytes
#define saRel1024Bytes 13 // 1024 bytes
#define saRel2048Bytes 14 // 2048 bytes


// Segment combination codes

/* 21 */  uchar comb;

#define scPriv     0    // Private. Do not combine with any other program
                        // segment.
#define scGroup    1    // Segment group
#define scPub      2    // Public. Combine by appending at an offset that meets
                        // the alignment requirement.
#define scPub2     4    // As defined by Microsoft, same as C=2 (public).
#define scStack    5    // Stack. Combine as for C=2. This combine type forces
                        // byte alignment.
#define scCommon   6    // Common. Combine by overlay using maximum size.
#define scPub3     7    // As defined by Microsoft, same as C=2 (public).


/* 22 */  uchar perm;           // Segment permissions (0-no information)
#define SEGPERM_EXEC  1 // Execute
#define SEGPERM_WRITE 2 // Write
#define SEGPERM_READ  4 // Read

/* 23 */  uchar bitness;// Number of bits in the segment addressing
                        // 0 - 16 bits
                        // 1 - 32 bits
                        // 2 - 64 bits
          bool use32(void) const { return bitness >= 1; }
          bool use64(void) const { return bitness == 2; }
          int  abits(void) const { return 1<<(bitness+4); }  // number of address bits
          int  abytes(void) const { return abits() / 8; }    // number of address bytes

/* 24 */  ushort flags;
#define SFL_COMORG      0x01
                        // IDP dependent field (IBM PC: if set, ORG directive is not commented out)
  bool comorg(void) const { return (flags & SFL_COMORG) != 0; }
  void set_comorg(void) { flags |= SFL_COMORG; }
  void clr_comorg(void) { flags &= ~SFL_COMORG; }

#define SFL_OBOK        0x02
                        // orgbase is present? (IDP dependent field)
  bool ob_ok(void) const { return (flags & SFL_OBOK) != 0; }
  void set_ob_ok(void) { flags |= SFL_OBOK; }
  void clr_ob_ok(void) { flags &= ~SFL_OBOK; }

#define SFL_HIDDEN      0x04
                        // is the segment hidden?
  bool is_visible_segm(void) const { return (flags & SFL_HIDDEN) == 0; }
  void set_visible_segm(bool visible) { setflag(flags, SFL_HIDDEN, !visible); }

#define SFL_DEBUG       0x08
                        // is the segment created for the debugger?
                        // such segments are temporary and do not have permanent flags
  bool is_debugger_segm(void) const { return (flags & SFL_DEBUG) != 0; }
  void set_debugger_segm(bool debseg) { setflag(flags, SFL_DEBUG, debseg); }

#define SFL_LOADER      0x10
                        // is the segment created by the loader?
  bool is_loader_segm(void) const { return (flags & SFL_LOADER) != 0; }
  void set_loader_segm(bool ldrseg) { setflag(flags, SFL_LOADER, ldrseg); }

#define SFL_HIDETYPE    0x20
                        // hide segment type (do not print it in the listing)
  bool is_hidden_segtype(void) const { return (flags & SFL_HIDETYPE) != 0; }
  void set_hidden_segtype(bool hide) { setflag(flags, SFL_HIDETYPE, hide); }

  // Ephemeral segments are not analyzed automatically
  // (no flirt, no functions unless required, etc)
  // Most likely these segments will be destroyed at the end of the
  // debugging session uness the user changes their status.
  bool is_ephemeral_segm(void) const
    { return (flags & (SFL_DEBUG|SFL_LOADER)) == SFL_DEBUG; }

/* 26 */  sel_t sel;    // segment selector - should be unique. You can't
                        // change this field after creating the segment.
                        // Exception: 16bit OMF files may have several
                        // segments with the same selector, but this is not
                        // good (no way to denote a segment exactly)
                        // so it should be fixed in the future.

/* 30 */  sel_t defsr[SREG_NUM];// default segment register values.
                        // first element of this array keeps information
                        // about value of ph.regFirstSreg

/* 94 */  uchar type;   // Type of the segment. The kernel treats different
                        // segment types differently.
                        // Segments marked with '*' contain no instructions
                        // or data and are not declared as 'segments' in
                        // the disassembly.

#define SEG_NORM        0       // Unknown type, no assumptions
#define SEG_XTRN        1       // * segment with 'extern' definitions
                                //   no instructions are allowed
#define SEG_CODE        2       // code segment
#define SEG_DATA        3       // data segment
#define SEG_IMP         4       // java: implementation segment
#define SEG_GRP         6       // * group of segments
#define SEG_NULL        7       // zero-length segment
#define SEG_UNDF        8       // undefined segment type (not used)
#define SEG_BSS         9       // uninitialized segment
#define SEG_ABSSYM     10       // * segment with definitions of absolute symbols
#define SEG_COMM       11       // * segment with communal definitions
#define SEG_IMEM       12       // internal processor memory & sfr (8051)


/* 95 */  bgcolor_t color;  // The segment color

// Update segment information. You must call this function after modification
// of segment characteristics. Note that not all fields of segment structure
// may be modified directly, there are special functions to modify some fields.
// returns: 1-ok, 0-failure

  int update(void)      { return segs.update(this); }


}; // total 95 bytes


// Segment visibility:

inline bool is_visible_segm(segment_t *s) { return s->is_visible_segm(); }
inline bool is_finally_visible_segm(segment_t *s) // is segment visible?
 { return (inf.s_cmtflg & SW_SHHID_SEGM) != 0 || is_visible_segm(s); }
idaman void ida_export set_visible_segm(segment_t *s, bool visible);

// Has segment a special type?
// (SEG_XTRN, SEG_GRP, SEG_ABSSYM, SEG_COMM)

idaman bool ida_export is_spec_segm(uchar seg_type);


// Does the address belong to a segment with a special type?
// (SEG_XTRN, SEG_GRP, SEG_ABSSYM, SEG_COMM)
//      ea - linear address

idaman bool ida_export is_spec_ea(ea_t ea);


// Helper class to lock a segment pointer so it stays valid
class lock_segment
{
  const segment_t *segm;
public:
  lock_segment(const segment_t *_segm) : segm(_segm)
  {
    areacb_t_lock_area(&segs, segm);
  }
  ~lock_segment(void)
  {
    areacb_t_unlock_area(&segs, segm);
  }
};

// Is a segment pointer locked?
inline bool is_segm_locked(const segment_t *segm)
{
  return areacb_t_get_area_locks(&segs, segm) > 0;
}

//-------------------------------------------------------------------------
//      S E G M E N T   S E L E C T O R S
//
//      The kernel maintains a table to translate selector values to
//      segment base paragraphs. Paragraph is 16byte quantity.
//      This table and translation is nesessary because IBM PC uses
//      16bit selectors in instructions but segments may reside anywhere
//      in the linear addressing space. For example, if a segment with
//      selector 5 resides at 0x400000, we need to have selector translation
//              5 -> 0x400000
//      For 16bit programs the selector translation table is usually empty,
//      selector values are equal to segment base paragraphs.
//
//-------------------------------------------------------------------------

// Get description of selector (0..get_selector_qty()-1)

idaman bool ida_export getn_selector(int n, sel_t *sel, ea_t *base);


// Get number of defined selectors

idaman int ida_export get_selector_qty(void);


// Allocate a selector for a segment if necessary
//      segbase - a new segment base paragraph
// You must call this function before calling add_segm(segment_t *)
// The other add_segm() calls this function itself, so you don't need to
// allocate a selector.
// This function will allocate a selector if 'segbase' requires more than
// 16 bits and the current processor if IBM PC
// Otherwise it will return the segbase value
// Returns: the allocated selector number

idaman sel_t ida_export setup_selector(ea_t segbase);


// Allocate a selector for a segment unconditionally
//      segbase - a new segment base paragraph
// You must call this function before calling add_segm(segment_t *)
// The other add_segm() calls this function itself, so you don't need to
// allocate a selector.
// This function will allocate a new free selector and setup its mapping
// using find_free_selector() and set_selector() funtions.
// Returns: the allocated selector number

idaman sel_t ida_export allocate_selector(ea_t segbase);


// Find first unused selector
// returns: a number >= 1

idaman sel_t ida_export find_free_selector(void);


// Set mapping of selector to a paragraph
// You should call this function _before_ creating a segment
// which uses the selector, otherwise the creation of the segment will fail.
//      selector  - number of selector to map
//      paragraph - paragraph to map selector
// If selector==BADSEL, then return 0 (fail)
// If the selector has had a mapping, old mapping is destroyed.
// If the selector number is equal to paragraph value, then the mapping is
// destroyed becuase we don't need to keep trivial mappings.
// Returns: 1-ok,0-failure (bad selector or too many mappings)

idaman int ida_export set_selector(sel_t selector, ea_t paragraph);


// Delete mapping of a selector
//      selector  - number of selector to remove from the translation table
// Be wary of deleting selectors that are being used in the program, this
// may make a mess in the segments.

idaman void ida_export del_selector(sel_t selector);


// Get mapping of a selector
//      selector  - number of selector to translate
// returns: paragraph the specified selector is mapped to.
//          if there is no mapping, returns 'selector'.

idaman ea_t ida_export ask_selector(sel_t selector);    // returns paragraph


// Get mapping of a selector as linear address
//      selector  - number of selector to translate to linear address
// returns: linear address the specified selector is mapped to.
//          if there is no mapping, returns toEA(selector,0);

idaman ea_t ida_export sel2ea(sel_t selector);  // returns linear address


// Find a selector that has mapping to the specified paragraph
//      base - paragraph to search in the translation table
// returns: selector value or base

idaman sel_t ida_export find_selector(ea_t base);


// Enumerate all selectors from the translation table
// This function call 'func' for each selector in the translation table
// If 'func' returns non-zero code, enumeration is stopped and this code
// is returned.
//      func - callback function
//              sel  - selector number
//              para - selector mapping
// returns 0 or code returned by 'func'.

idaman int ida_export enumerate_selectors(int (idaapi* func)(sel_t sel,ea_t para));

// Enumerate all segments with the specified selector
// This function will call the callback function 'func' for each
// segment that has the specified selector. Enumeration starts
// from the last segment and stops at the first segment (reverse order).
// If the callback function 'func' returns a value != BADADDR, the
// enumration is stopped and this value is returned to the caller.
//      selector - segments that have this selector are enumerated
//      func     - callback function
//                      s    - pointer to segment structure
//                      ud   - user data
//      ud       - pointer to user data. this pointer will be passed
//                 to the callback function
// returns: BADADDR or the value returned by the callback function 'func'.

idaman ea_t ida_export enumerate_segments_with_selector(
                                sel_t selector,
                                ea_t (idaapi* func)(segment_t *s,void *ud),
                                void *ud);


// Get pointer to segment structure, in: segment selector
// This function find a segment by its selector. If there are several
// segments with the same selectors, the last one will be returned
//      selector - a segment with the specified selector will be returned
// returns: pointer to segment or NULL

idaman segment_t *ida_export get_segm_by_sel(sel_t selector);    // get pointer to segment


//-------------------------------------------------------------------------
//      S E G M E N T   M A N I P U L A T I O N   F U N C T I O N S
//-------------------------------------------------------------------------

// Add a new segment.
//      s      - pointer to filled segment structure
//               segment selector should have proper mapping (see set_selector)
//               if s.startEA==BADADDR then s.startEA <- get_segm_base(&s)
//               If s.endEA==BADADDR, then a segment up to the next segment
//               will be created (if the next segment doesn't exist, then
//               1 byte segment will be created).
//               type. If the s.endEA < s.startEA, then fail.
//               If s.endEA is too high and the new segment would overlap
//               the next segment, s.endEA is adjusted properly.
//      name   - name of new segment. may be NULL
//               if specified, the segment is immediately renamed
//      sclass - class of the segment. may be NULL
//               if specified, the segment class is immediately changed
//      flags  - additional processing, combination of ADDSEG_.. constants
// If a segment already exists at the specified range of addresses,
// this segment will be truncated. Instructions and data in the old
// segment will be deleted if the new segment has another addressing
// mode or another segment base address.
// returns:1-ok,0-failed, a warning message is displayed

idaman int ida_export add_segm_ex(segment_t *s,const char *name,const char *sclass,int flags);

#define ADDSEG_NOSREG   0x0001  // set all default segment register values
                                // to BADSELs
                                // (undefine all default segment registers)
#define ADDSEG_OR_DIE   0x0002  // qexit() if can't add a segment
#define ADDSEG_NOTRUNC  0x0004  // don't truncate the new segment at the beginning
                                // of the next segment if they overlap.
                                // destroy/truncate old segments instead.
#define ADDSEG_QUIET    0x0008  // silent mode, no "Adding segment..." in the messages window
#define ADDSEG_FILLGAP  0x0010  // If there is a gap between the new segment
                                // and the previous one, and this gap is less
                                // than 64K, then fill the gap by extending the
                                // previous segment and adding .align directive
                                // to it. This way we avoid gaps between segments.
                                // Too many gaps lead to a virtual array failure.
                                // It can not hold more than ~1000 gaps.
#define ADDSEG_SPARSE   0x0020  // Use sparse storage method for the new segment

// Add a new segment, second form.
//      para   - segment base paragraph
//               if paragraph can't fit in 16bit, then a new selector is
//               allocated and mapped to the paragraph
//      start  - start address of the segment
//               if start==BADADDR then start <- toEA(para,0)
//      end    - end address of the segment. end address should be higher than
//               start address. For emulate empty segments, use SEG_NULL segment
//               type. If the end address is lower than start address, then fail.
//               If end==BADADDR, then a segment up to the next segment
//               will be created (if the next segment doesn't exist, then
//               1 byte segment will be created).
//               If 'end' is too high and the new segment would overlap
//               the next segment, 'end' is adjusted properly.
//      name   - name of new segment. may be NULL
//      sclass - class of the segment. may be NULL
//               type of the new segment is modified if class is one of
//               predefined names:
//                      "CODE"  -> SEG_CODE
//                      "DATA"  -> SEG_DATA
//                      "CONST" -> SEG_DATA
//                      "STACK" -> SEG_BSS
//                      "BSS"   -> SEG_BSS
//                      "XTRN"  -> SEG_XTRN
//                      "COMM"  -> SEG_COMM
//                      "ABS"   -> SEG_ABS
// Segment alignment is set to saRelByte.
// Segment combination is "public" or "stack" (if segment class is "STACK")
// Addressing mode of segment is taken as default (16bit or 32bit)
// Default segment registers are set to BADSELs.
// If a segment already exists at the specified range of addresses,
// this segment will be truncated. Instructions and data in the old
// segment will be deleted if the new segment has another addressing
// mode or another segment base address.
// returns:1-ok,0-failed, a warning message is displayed

idaman int ida_export add_segm(ea_t para,
                        ea_t start,
                        ea_t end,
                        const char *name,
                        const char *sclass);


// Delete a segment
//      ea    - any address belonging to the segment
//      flags - combination of SEGMOD_... constants
// returns 1-ok,0-failed, no segment at 'ea'.

idaman int ida_export del_segm(ea_t ea, int flags);

#define SEGMOD_KILL    0x0001 // disable addresses if segment gets
                              // shrinked or deleted
#define SEGMOD_KEEP    0x0002 // keep information (code & data, etc)
#define SEGMOD_SILENT  0x0004 // be silent
#define SEGMOD_KEEP0   0x0008 // flag for internal use, don't set
#define SEGMOD_KEEPSEL 0x0010 // do not try to delete unused selector


// Get number of segments

inline int get_segm_qty(void){ return segs.get_area_qty(); }


// Get pointer to segment by linear address
//      ea - linear address belonging to the segment
// returns: NULL or pointer to segment structure

inline segment_t *getseg(ea_t ea) { return (segment_t *)(segs.get_area(ea)); }


// Get pointer to segment by its number
//      n - segment number in the range (0..get_segm_qty()-1)
// returns: NULL or pointer to segment structure
// Obsoleted because can slow down the debugger (it has to refresh the whole
// memory segmentation to calculate the correct answer)

inline segment_t *getnseg(int n){ return (segment_t *)(segs.getn_area(n)); }


// Get pointer to the next/previous segment

inline segment_t *get_next_seg(ea_t ea) { return (segment_t *)segs.next_area_ptr(ea); }
inline segment_t *get_prev_seg(ea_t ea) { return (segment_t *)segs.prev_area_ptr(ea); }

inline segment_t *get_first_seg(void) { return (segment_t *)segs.first_area_ptr(); }
inline segment_t *get_last_seg(void) { return (segment_t *)segs.last_area_ptr(); }



// Get pointer to segment by its name
//      name - segment name. may be NULL.
// returns: NULL or pointer to segment structure
// If there are several segments with the same name, returns the first of them

idaman segment_t *ida_export get_segm_by_name(const char *name);


// Set segment end address
//      ea     - any address belonging to the segment
//      newend - new end address of the segment
//      flags  - combination of SEGMOD_... constants
// The next segment is shrinked to allow expansion of the specified segment.
// The kernel might even delete the next segment if necessary.
// The kernel will ask the user for a permission to destroy instructions
// or data going out of segment scope if such instructions exist.
// returns 1-ok,0-failed, a warning message is displayed

idaman int ida_export set_segm_end(ea_t ea, ea_t newend, int flags);


// Set segment start address
//      ea     - any address belonging to the segment
//      newstart - new start address of the segment
//               note that segment start address should be higher than
//               segment base linear address.
//      flags  - combination of SEGMOD_... constants
// The previous segment is trimmed to allow expansion of the specified segment.
// The kernel might even delete the previous segment if necessary.
// The kernel will ask the user for a permission to destroy instructions
// or data going out of segment scope if such instructions exist.
// returns 1-ok,0-failed, a warning message is displayed

idaman int ida_export set_segm_start(ea_t ea, ea_t newstart, int flags);


// Move segment start
// The main difference between this function and set_segm_start() is
// that this function may expand the previous segment while set_segm_start()
// never does it. So, this function allows change bounds of two segments
// simultaneosly. If the previous segment and the specified segment
// have the same addressing mode and segment base, then instructions
// and data are not destroyed - they simply move from one segment
// to another. Otherwise all instructions/data which migrate
// from one segment to another are destroyed.
//      ea     - any address belonging to the segment
//      newstart - new start address of the segment
//               note that segment start address should be higher than
//               segment base linear address.
//      mode   - 0: if it is nesessary to destroy defined items,
//                  display a dialog box and ask confirmation
//               1: if it is nesessary to destroy defined items,
//                  just destroy them without asking the user
//              -1: if it is nesessary to destroy defined items,
//                  don't destroy them (i.e. function will fail)
//              -2: don't destroy defined items (function will succeed)
// Note that this function never disables addresses.
// returns 1-ok,0-failed, a warning message is displayed

idaman int ida_export move_segm_start(ea_t ea,ea_t newstart,int mode);
                                                // move segment start, change
                                                // previous if nessesary


// Move a segment to a new address
// This function moves all information to the new address
// It fixes up address sensitive information in the kernel
// The total effect is equal to reloading the segment to the target address
// SDK: For the module dependent address sensitive information, ph.move_segm is called
// For the file format dependent address sensitive information, loader.move_segm is called
//      s     - segment to move
//      to    - new segment start address
//      flags - details. MFS_... constants
// returns: error code

#define MSF_SILENT    0x0001    // don't display a "please wait" box on the screen
#define MSF_NOFIX     0x0002    // don't call the loader to fix relocations
#define MSF_LDKEEP    0x0004    // keep the loader in the memory (optimization)
#define MSF_FIXONCE   0x0008    // valid for rebase_program(): call loader only once
                                // with the special calling method (see loader_t.move_segm)

idaman int ida_export move_segm(segment_t *s, ea_t to, int flags=0);


#define MOVE_SEGM_OK      0     // all ok
#define MOVE_SEGM_PARAM  -1     // The specified segment does not exist
#define MOVE_SEGM_ROOM   -2     // Not enough free room at the target address
#define MOVE_SEGM_IDP    -3     // IDP module forbids moving the segment
#define MOVE_SEGM_CHUNK  -4     // Too many chunks are defined, can't move
#define MOVE_SEGM_LOADER -5     // The segment has been moved but the loader complained
#define MOVE_SEGM_ODD    -6     // Can't move segments by an odd number of bytes


// Rebase the whole program by 'delta' bytes
//      delta - number of bytes to move the program
//      flags - combination of MFS_... constants
//              it is recommended to use MSF_FIXONCE so that the loader takes
//              care of global variables it stored in the database
// returns: error code MOVE_SEGM_...

idaman int ida_export rebase_program(adiff_t delta, int flags);


// Convert a debugger segment to a regular segment and vice versa
//      s           - segment to modify
//      is_deb_segm - new status of the segment
// When converting debug->regular, the memory contents will be copied
// to the database.
// returns:

#define CSS_OK      0           // ok
#define CSS_NODBG  -1           // debugger is not running
#define CSS_NOAREA -2           // could not find corresponding memory area
#define CSS_NOMEM  -3           // not enough memory (might be because the segment
                                // is too big)

idaman int ida_export change_segment_status(segment_t *s, bool is_deb_segm);


// take a memory snapshot of the running process
//   only_loader_segment - only is_loader_segm() segments will be affected
// returns: success

idaman bool ida_export take_memory_snapshot(bool only_loader_segs);


// is the database a miniidb created by the debugger?
// returns true if the database contains no segments
// or only debugger segments

idaman bool ida_export is_miniidb(void);


// internal function
idaman bool ida_export set_segm_base(segment_t *s, ea_t newbase);

//-------------------------------------------------------------------------
//      S E G M E N T   G R O U P S
//-------------------------------------------------------------------------

// Initialize groups.
// The kernel calls this function at the start of work.

       void init_groups(void);
inline void save_groups(void) {}
inline void term_groups(void) {}


// Create a new group of segments (used OMF files)
//      grp - selector of group segment (segment type is SEG_GRP)
//            You should create an 'empty' (1 byte) group segment
//              It won't contain anything and will be used to
//              redirect references to the group of segments to the
//              common selector.
//      sel - common selector of all segments belonging to the segment
//            You should create all segments within the group with the
//            same selector value.
// returns:1-ok, 0-too many groups

idaman int ida_export set_group_selector(sel_t grp,sel_t sel); // returns 1 - ok

#define MAX_GROUPS      8               // max number of segment groups


// Get common selector for a group of segments
//      grpsel - selector of group segment
// returns: common selector of the group or 'grpsel' if no such group is found

idaman sel_t ida_export get_group_selector(sel_t grpsel);


//-------------------------------------------------------------------------
//      S E G M E N T   T R A N S L A T I O N S
//
//      Segment translations are used to represent overlayed memory banks.
//      They are used to redirect access to overlayed segments so that
//      the correct overlay is accessed. Each segment has its own
//      translation list. For example, suppose we have
//      four segments:
//              A               1000-2000
//              B               1000-2000
//                C             2000-3000
//                D             2000-3000
//      A and B occupy the same virtual addresses. The same with C and D.
//      Segment A works with segment C, segment B works with segment D.
//      So all references from A to 2000-3000 should go to C. For this
//      we add translation C for segment A. The same with B,D: add
//      translation D for segment B. Also, we need to specify the correct
//      segment to be accessed from C, thus we add translation A for segment C.
//      And we add translation B for segment D.
//      After this, all references to virtual addresses 2000-3000 made from A
//      go to segment C (even if segment A would be large and occupy 1000-3000)
//      So, we need the following translations:
//              A:      C
//              B:      D
//              C:      A
//              D:      B
//
//      With translations, the segments may reside at any linear addresses,
//      all references will pass  through the translation mechanism and go to the
//      correct segment.
//
//      Segment translation works only for code segments (see codeSeg())
//
//-------------------------------------------------------------------------

// Add segment translation
//      segstart  - start address of the segment to add translation to
//      mappedseg - start address of the overlayed segment
// returns:1-ok, 0-too many translations or bad segstart

idaman bool ida_export add_segment_translation(ea_t segstart, ea_t mappedseg);

#define MAX_SEGM_TRANSLATIONS   64      // max number of segment translations


// Set new translation list
//      segstart  - start address of the segment to add translation to
//      transmap  - array of segment start addresses for the translation list.
//                  The first element of array contains number of segments
//                  If transmap==NULL, then translation list is deleted.
// returns:1-ok,0-too many translations or bad segstart

idaman bool ida_export set_segment_translations(ea_t segstart, const ea_t *transmap);


// Delete the translation list

inline bool del_segment_translations(ea_t ea)
{
  return set_segment_translations(ea, NULL);
}


// Get segment translation list
//      segstart  - start address of the segment to get information about
//      buf       - buffer for the answer
//      bufsize   - size of the buffer in bytes
// returns:NULL-no translation list or bad segstart or small or bad buffer
//         otherwise returns translation list.
//               the first element of the list contains number of segments.

idaman ea_t *ida_export get_segment_translations(ea_t segstart,
                                                 ea_t *buf,
                                                 int bufsize);


//-------------------------------------------------------------------------
//      S E G M E N T   C O M M E N T S
//
//      Segment comments are rarely used yet.
//      The user may define a segment comment by pressing ':'
//      while standing on the segment name at the segment start.
//      The main advantage of segment comments compared to anterior
//      lines (see lines.hpp) is that they are attached to a segment,
//      not to an address and they will move with the start of segment
//      if the segment boundaries change.
//
//      You may set segment comments in your LDR module to describe
//      characteristics of a segment in comments.
//
//      Repeatable segment comments are not used at all, because I don't
//      know where they should be repeated.
//
//-------------------------------------------------------------------------

// Get segment comment
//      s          - pointer to segment structure
//      repeatable - 0: get regular comment
//                   1: get repeatable comment
// returns: NULL or segment comment (The caller must qfree() the result.)

inline char *get_segment_cmt(const segment_t *s, bool repeatable)
{
  return segs.get_area_cmt(s,repeatable);
}


// Set segment comment
//      s          - pointer to segment structure
//      cmt        - comment string, may be multiline (with '\n')
//                   maximal size is 4096 bytes.
//      repeatable - 0: set regular comment
//                   1: set repeatable comment
//
inline void set_segment_cmt(segment_t *s,const char *cmt, bool repeatable)
{
  segs.set_area_cmt(s,cmt,repeatable);
}


// Delete segment comment
//      s          - pointer to segment structure
//      repeatable - 0: delete regular comment
//                   1: delete repeatable comment

inline void del_segment_cmt(segment_t *s, bool repeatable)
{
  segs.del_area_cmt(s, repeatable);
}


// Generate segment footer line as a comment line
//  ; end of 'segname'
// This function may be used in IDP modules to generate segment footer
// if the target assembler doesn't have 'ends' directive

idaman void ida_export std_gen_segm_footer(ea_t ea);


//-------------------------------------------------------------------------
//      S E G M E N T   N A M E S
//-------------------------------------------------------------------------

// Rename segment
//      s      - pointer to segment (may be NULL)
//      format - new name, printf() style format string
// The new name is validated (see validate_name2)
// A segment always has a name. If you hadn't specified a name,
// the kernel will assign it "seg###" name where ### is segment number.
// returns: 1-ok, name is good and segment is renamed
//          0-failure, name is bad or segment is NULL

idaman AS_PRINTF(2, 0) int ida_export vset_segm_name(
        segment_t *s,
        const char *format,
        va_list va);

AS_PRINTF(2, 3) inline int set_segm_name(segment_t *s, const char *format, ...)
{
  va_list va;
  va_start(va, format);
  int code = vset_segm_name(s, format, va);
  va_end(va);
  return code;
}


// Get true segment name by pointer to segment
//      s - pointer to segment
//      buf - output buffer. can not be NULL
//      bufsize - output buffersize
// returns: size of segment name (-1 if s==NULL)

idaman ssize_t ida_export get_true_segm_name(const segment_t *s, char *buf, size_t bufsize);


// Get segment name by pointer to segment
//      s - pointer to segment
//      buf - output buffer. can not be NULL
//      bufsize - output buffersize
// returns: size of segment name (-1 if s==NULL)

idaman ssize_t ida_export get_segm_name(const segment_t *s, char *buf, size_t bufsize);


// Get segment name, in: any address within the segment
//      ea - any linear address within the segment
//      buf - output buffer. can not be NULL
//      bufsize - output buffersize
// returns: size of segment name (-1 if s==NULL)

inline ssize_t idaapi get_segm_name(ea_t ea, char *buf, size_t bufsize)
{
  return get_segm_name(getseg(ea), buf, bufsize);
}


// Get colored segment name expression in the form (segname + displacement)
//      from - linear address of instruction operand or data referring to
//             the name. This address will be used to get fixup information,
//             so it should point to exact position of operand in the
//             instruction.
//      sel  - value to convert to segment expression
//      buf   - output buffer to hold segment expression
//      bufsize - size of the output buffer
// returns: NULL-can't convert to segment expression
//          othersize pointer to 'buf'

char *get_segm_expr(ea_t from, sel_t sel, char *buf, size_t bufsize);


//-------------------------------------------------------------------------
//      S E G M E N T   C L A S S E S  A N D  T Y P E S
//-------------------------------------------------------------------------

// Get segment class.
// Segment class is arbitrary text (max 8 characters)
//      s - pointer to segment
//      buf - output buffer. can not be NULL
//      bufsize - output buffersize
// returns: size of segment class (-1 if s==NULL or bufsize<=0)

idaman ssize_t ida_export get_segm_class(const segment_t *s, char *buf, size_t bufsize);


// Set segment class.
//      s      - pointer to segment (may be NULL)
//      sclass - segment class (may be NULL)
// If segment type is SEG_NORM and segment class is one of predefined
// names, then segment type is changed too:
//      "CODE"  -> SEG_CODE
//      "DATA"  -> SEG_DATA
//      "STACK" -> SEG_BSS
//      "BSS"   -> SEG_BSS
// If new segment class is "UNK", then segment type is reset t SEG_NORM.
// returns: 1-ok, name is good and segment is renamed
//          0-failure, name is NULL or bad or segment is NULL

idaman int ida_export set_segm_class(segment_t *s, const char *sclass);


// Get segment type
// This function returns segment type (SEG_...)
//      ea - any linear address within the segment
// returns: SEG_UNDF if no segment found at 'ea'
//          otherwise return segment type

idaman uchar ida_export segtype(ea_t ea);


//-------------------------------------------------------------------------
//      S E G M E N T   A L I G N M E N T   A N D   C O M B I N A T I O N
//-------------------------------------------------------------------------

// Get text representation of segment alignment code
// returns text digestable by IBM PC assembler.

idaman const char *ida_export get_segment_alignment(uchar align);


// Get text representation of segment combination code
// returns text digestable by IBM PC assembler.

idaman const char *ida_export get_segment_combination(uchar comb);


//-------------------------------------------------------------------------
//      S E G M E N T   A D D R E S S I N G
//-------------------------------------------------------------------------

// Get segment base paraphaph
//      s      - pointer to segment
// returns: 0 if s == NULL
//          segment base paraphaph
// Segment base paragraph may be converted to segment base linear address
// using toEA() function.
// In fact, toEA(get_segm_para(s), 0) == get_segm_base(s)

idaman ea_t ida_export get_segm_para(const segment_t *s);


// Get segment base linear address
//      s      - pointer to segment
// returns: 0 if s == NULL
//          segment base linear address
// Segment base linear address is used to calculate virtual addresses.
// The virtual address of the first byte of the segment will be
//      (start address of segment - segment base linear address)

idaman ea_t ida_export get_segm_base(const segment_t *s);


// Change segment addressing mode (16, 32, 64 bits)
// You must use this function to change segment addressing, never change
// the 'bitness' field directly.
// This function will delete all instructions, comments and names in the segment
//      s      - pointer to segment
//      bitness- new addressing mode of segment
//                 2: 64bit segment
//                 1: 32bit segment
//                 0: 16bit segment
// returns: 1-ok, 0-failure

idaman bool ida_export set_segm_addressing(segment_t *s, size_t bitness);


//-------------------------------------------------------------------------
//      I N T E R N A L   K E R N E L   F U N C T I O N S
//-------------------------------------------------------------------------

ssize_t get_based_segm_expr(ea_t from, sel_t basesel, sel_t sel, char *buf, size_t bufsize);


// Create internal kernel structures for program segmentation
// Called when a new file is loaded by the kernel.
//      file - name of input file

void    createSegmentation(const char *file);


// Initialize work with segments
// Called by the kernel itself.
//      file - name of input file
//      newfile - is a new file being loaded for disassembly?

void    initSegment     (const char *file, bool newfile);


// Flush kernel caches with segmentation information

void    save_segments   (void);


// Terminate work with the segments
// Called by the kernel at the end of work.

void    termSegment     (void);

void    DeleteAllSegments(void);


// Delete segments created by the debugger

void delete_debug_segments(void);


// Does the address belong to a debug segment?

inline bool is_debugger_segm(ea_t ea)
{
  segment_t *s = getseg(ea);
  return s != NULL && s->is_debugger_segm();
}

// Does the address belong to an ephemeral segment?

inline bool is_ephemeral_segm(ea_t ea)
{
  segment_t *s = getseg(ea);
  return s != NULL && s->is_ephemeral_segm();
}

//-------------------------------------------------------------------------
inline ea_t correct_address(ea_t ea, ea_t from, ea_t to, ea_t size)
{
  if ( ea >= from && ea < from+size )
    ea += to - from;
  return ea;
}

// truncate and sign extend a delta depending on the segment
idaman adiff_t ida_export segm_adjust_diff(const segment_t *s, adiff_t delta);

// truncate an address depending on the segment
idaman ea_t ida_export segm_adjust_ea(const segment_t *s, ea_t ea);

#ifndef NO_OBSOLETE_FUNCS
#define SEGDEL_PERM   0x0001 // permanently, i.e. disable addresses
#define SEGDEL_KEEP   0x0002 // keep information (code & data, etc)
#define SEGDEL_SILENT 0x0004 // be silent
#define SEGDEL_KEEP0  0x0008 // flag for internal use, don't set
#endif

#pragma pack(pop)
#endif // _SEGMENT_HPP
