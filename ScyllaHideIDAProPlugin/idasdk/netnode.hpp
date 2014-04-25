/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2008 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _NETNODE_HPP
#define _NETNODE_HPP
#pragma pack(push, 1)           // IDA uses 1 byte alignments!

//
//      This file contains functions that provide the lowest level interface
//      to the ida database, namely Btree. To learn more about Balanced Trees:
//      http://www.bluerwhite.org/btree/
//
//      We don't use Btree directly.
//      Instead, we have another layer built on the top of Btree.
//      Here is a brief explanation of this layer.
//
//      There is a graph. The graph consists of nodes and links between them.
//      We call a node "netnode". Netnodes are numbered with 32-bit values.
//      Usually there is a trivial mapping of the linear addresses used in
//      the program to the netnodes. If we have additional information about
//      an address (a comment is attached to it, for example), this
//      information is stored in the corresponding netnode.
//      See nalt.hpp if you want to see how the kernel uses netnodes.
//      Also, some netnodes have no corresponding linear address. They are
//      used to store information not related to a particular address.
//
//      Each netnode _may_ have the following attributes:
//
//        - a name (max length of name is MAXNAMESIZE)
//          there is no limitation on characters used in names.
//
//        - a value: arbitary sized object, max size is MAXSPECSIZE
//
//        - altvals: a sparse array of 32-bit values.
//          indexes in this array may be 8-bit or 32-bit values
//
//        - supvals: an array of arbitrary sized objects. (size of each
//          object is limited by MAXSPECSIZE)
//          indexes in this array may be 8-bit or 32-bit values
//
//        - charvals: a sparse array of 8-bit values.
//          indexes in this array may be 8-bit or 32-bit values
//
//        - hashvals: a hash (an associative array)
//          indexes in this array are strings
//          values are arbitrary sized (max size is MAXSPECSIZE)
//
//      Initially a new netnode contains no information so no disk space
//      is used for it. As you add new information, the netnode grows.
//      All arrays behave in the same manner: initally
//        - all members of altvals/charvals array are zeroes
//        - all members of supvals/hashvals array are undefined.
//
//      About values returned by the netnode function:
//      the returned string values may be modified
//      freely. They are returned in static buffers.
//      The size of each buffer is MAXSPECSIZE+1. There are 10 buffers and
//      they are used in a round-robin manner.
//
//      There are high-level functions to store arbitrary sized objects (blobs)
//      in supvals.
//
//      You may use netnodes to store additional information about the program.
//      Limitations on the use of netnodes are the following:
//
//        - use netnodes only if you could not find a kernel service to
//          store your type of information
//
//        - Do not create netnodes with valid identifier names.
//          Use the "$ " prefix (or any other prefix with characters not allowed
//          in the identifiers for the names of your netnodes.
//          Although you will probably not destroy anything by
//          accident, using already defined names for the names of your
//          netnodes is still discouraged.
//
//        - you may create as many netnodes as you want (creation of unnamed
//          netnode doesn't increase the size of the database).
//          however, since each netnode has a number, creating too many netnodes
//          could lead to the exhaustion of the netnode numbers (the numbering
//          starts at 0xFF000000)
//
//        - remember that netnodes are automatically saved to the disk
//          by the kernel.
//

//      Advanced info:
//      In fact a netnode may contain up to 256 arrays of arbitrary sized
//      objects. Each array has its 8-bit tag. Usually tags are represented
//      by characters constants. Altvals and supvals are simply 2 of
//      256 arrays, with tags 'A' and 'S' respectively.

//      Links between the netnodes are called netlinks. Each netlink has a type.
//      The ida kernel doesn't use the links.
//
//      The netlink type is represented as a 32-bit number and has a name.
//      The netlinks are used to build the graph.
//      Also, each particular netlink between
//      two netnodes may have arbitrary text attached to it.
//      Netlinks are deprecated!

//--------------------------------------------------------------------------

// The BTREE page size. This is not interesting for the end-users.

const int BTREE_PAGE_SIZE = 8192;  // don't use the default 2048 page size


// Maximum length of a netnode name

const int MAXNAMESIZE = 512;


// Maximum length of strings or objects stored in supval array element

const int MAXSPECSIZE = 1024;


// Netnode numbers are 64 bit for 64 bit IDA

#ifdef __EA64__
typedef uint64 nodeidx_t;
#else
typedef uint32 nodeidx_t;
#endif

// A number to represent bad netnode reference

#define BADNODE nodeidx_t(-1)

// Tags internally used in netnodes. You should not use them
// for your tagged alt/sup/char/hash arrays.

const char atag = 'A';                  // Array of altvals
const char stag = 'S';                  // Array of supvals
const char htag = 'H';                  // Array of hashvals
const char vtag = 'V';                  // Value of netnode
const char ntag = 'N';                  // Name of netnode
const char ltag = 'L';                  // Links between netnodes

//      Helper functions. They should not be called directly!

class netnode;
idaman bool  ida_export netnode_check           (netnode *, const char *name,size_t namlen,bool create);
idaman void  ida_export netnode_kill            (netnode *);
idaman bool  ida_export netnode_start           (netnode *);
idaman bool  ida_export netnode_end             (netnode *);
idaman bool  ida_export netnode_next            (netnode *);
idaman bool  ida_export netnode_prev            (netnode *);
idaman ssize_t ida_export netnode_name          (nodeidx_t num, char *buf, size_t bufsize);
idaman bool  ida_export netnode_rename          (nodeidx_t num, const char *newname,size_t namlen);
idaman ssize_t ida_export netnode_valobj        (nodeidx_t num, void *buf, size_t bufsize);
idaman ssize_t ida_export netnode_valstr        (nodeidx_t num, char *buf, size_t bufsize);
idaman bool  ida_export netnode_set             (nodeidx_t num, const void *value,size_t length);
idaman bool  ida_export netnode_delvalue        (nodeidx_t num);
idaman nodeidx_t ida_export netnode_altval      (nodeidx_t num, nodeidx_t alt,char tag);
idaman uchar ida_export netnode_charval         (nodeidx_t num, nodeidx_t alt,char tag);
idaman nodeidx_t ida_export netnode_altval_idx8 (nodeidx_t num, uchar alt,char tag);
idaman uchar ida_export netnode_charval_idx8    (nodeidx_t num, uchar alt,char tag);
idaman ssize_t ida_export netnode_supval        (nodeidx_t num, nodeidx_t alt,void *buf,size_t bufsize,char tag);
idaman ssize_t ida_export netnode_supstr        (nodeidx_t num, nodeidx_t alt,char *buf,size_t bufsize,char tag);
idaman bool  ida_export netnode_supset          (nodeidx_t num, nodeidx_t alt,const void *value,size_t length,char tag);
idaman bool  ida_export netnode_supdel          (nodeidx_t num, nodeidx_t alt,char tag);
idaman nodeidx_t ida_export netnode_sup1st      (nodeidx_t num, char tag);
idaman nodeidx_t ida_export netnode_supnxt      (nodeidx_t num, nodeidx_t cur,char tag);
idaman nodeidx_t ida_export netnode_suplast     (nodeidx_t num, char tag);
idaman nodeidx_t ida_export netnode_supprev     (nodeidx_t num, nodeidx_t cur,char tag);
idaman ssize_t ida_export netnode_supval_idx8   (nodeidx_t num, uchar alt,void *buf,size_t bufsize,char tag);
idaman ssize_t ida_export netnode_supstr_idx8   (nodeidx_t num, uchar alt,char *buf,size_t bufsize,char tag);
idaman bool  ida_export netnode_supset_idx8     (nodeidx_t num, uchar alt,const void *value,size_t length,char tag);
idaman bool  ida_export netnode_supdel_idx8     (nodeidx_t num, uchar alt,char tag);
idaman nodeidx_t ida_export netnode_sup1st_idx8 (nodeidx_t num, char tag);
idaman nodeidx_t ida_export netnode_supnxt_idx8 (nodeidx_t num, uchar alt,char tag);
idaman nodeidx_t ida_export netnode_suplast_idx8(nodeidx_t num, char tag);
idaman nodeidx_t ida_export netnode_supprev_idx8(nodeidx_t num, uchar alt,char tag);
idaman bool  ida_export netnode_supdel_all      (nodeidx_t num, char tag);
idaman int ida_export netnode_supdel_range      (nodeidx_t num, nodeidx_t idx1, nodeidx_t idx2, char tag);
idaman int ida_export netnode_supdel_range_idx8 (nodeidx_t num, nodeidx_t idx1, nodeidx_t idx2, char tag);
idaman ssize_t ida_export netnode_hashval       (nodeidx_t num, const char *idx,void *buf, size_t bufsize,char tag);
idaman ssize_t ida_export netnode_hashstr       (nodeidx_t num, const char *idx,char *buf, size_t bufsize,char tag);
idaman nodeidx_t ida_export netnode_hashval_long(nodeidx_t num, const char *idx,char tag);
idaman bool  ida_export netnode_hashset         (nodeidx_t num, const char *idx,const void *value,size_t length,char tag);
idaman bool  ida_export netnode_hashdel         (nodeidx_t num, const char *idx,char tag);
idaman ssize_t ida_export netnode_hash1st       (nodeidx_t num, char *buf, size_t bufsize,char tag);
idaman ssize_t ida_export netnode_hashnxt       (nodeidx_t num, const char *idx,char *buf, size_t bufsize,char tag);
idaman ssize_t ida_export netnode_hashlast      (nodeidx_t num, char *buf, size_t bufsize,char tag);
idaman ssize_t ida_export netnode_hashprev      (nodeidx_t num, const char *idx,char *buf, size_t bufsize,char tag);
idaman size_t ida_export netnode_blobsize       (nodeidx_t num, nodeidx_t start,char tag);
idaman void *ida_export netnode_getblob         (nodeidx_t num, void *buf, size_t *bufsize, nodeidx_t start, char tag);
idaman bool  ida_export netnode_setblob         (nodeidx_t num, const void *buf, size_t size, nodeidx_t start, char tag);
idaman int   ida_export netnode_delblob         (nodeidx_t num, nodeidx_t start,char tag);
idaman bool  ida_export netnode_inited          (void);
idaman size_t ida_export netnode_copy           (nodeidx_t num, nodeidx_t count, nodeidx_t target, bool move);
idaman size_t ida_export netnode_altshift       (nodeidx_t num, nodeidx_t from, nodeidx_t to, nodeidx_t size, char tag);
idaman size_t ida_export netnode_charshift      (nodeidx_t num, nodeidx_t from, nodeidx_t to, nodeidx_t size, char tag);
idaman size_t ida_export netnode_supshift       (nodeidx_t num, nodeidx_t from, nodeidx_t to, nodeidx_t size, char tag);
idaman void  ida_export netnode_altadjust       (nodeidx_t num, nodeidx_t from, nodeidx_t to, nodeidx_t size, bool (idaapi *should_skip)(nodeidx_t ea));
idaman bool  ida_export netnode_exist           (const netnode &n);

//--------------------------------------------------------------------------
//      N E T N O D E
//--------------------------------------------------------------------------

// Definition of netnode class.
// Note that the size of the 'netnode' class is 4 bytes and it can be
// freely casted to 'uint32' and back. This makes it easy to store
// information about the program location in the netnodes.
// Please pass netnodes to functions by value.

class netnode
{
  friend class netlink;
  friend bool ida_export netnode_check(netnode *, const char *name, size_t namlen, bool create);
  friend void ida_export netnode_kill (netnode *);
  friend bool ida_export netnode_start(netnode *);
  friend bool ida_export netnode_end  (netnode *);
  friend bool ida_export netnode_next (netnode *);
  friend bool ida_export netnode_prev (netnode *);
  friend size_t ida_export netnode_altshift (nodeidx_t num, nodeidx_t from, nodeidx_t to, nodeidx_t size, char tag);
  friend size_t ida_export netnode_charshift(nodeidx_t num, nodeidx_t from, nodeidx_t to, nodeidx_t size, char tag);
  friend size_t ida_export netnode_supshift (nodeidx_t num, nodeidx_t from, nodeidx_t to, nodeidx_t size, char tag);
public:

//--------------------------------------------------------------------------
// Contructors, conversions and assigments

// Empty constructor

  netnode(void)                 {}


// Constructor to create a netnode to access information about the
// specified linear address

  netnode(nodeidx_t num)            { netnodenumber = num; }


// Conversion from netnode to linear address

  operator nodeidx_t() const        { return netnodenumber; }


// Construct an instance of netnode class to access the specified netnode
//      _name     - name of netnode
//      namlen    - length of the name. may be omitted, in this
//                  case the length will be calcuated with strlen()
//      do_create - true:  create the netnode if it doesn't exist yet.
//                  false: don't create the netnode, set netnumber to BADNODE if
//                         it doesn't exist

  netnode(const char *_name, size_t namlen=0, bool do_create=false)
  {
    netnode_check(this, _name, namlen, do_create);
  }


//--------------------------------------------------------------------------
// Check for existence of a netnode.
// Create and delete netnodes.

// Does the specified netnode exist?
// This function returns 1 only if there is some information attached to the
// netnode. In the case of unnamed netnode without any information it will
// return 0.

  friend bool ida_export netnode_exist(const netnode &n);
  friend bool ida_export exist(const netnode &n) { return netnode_exist(n); }


// Create a named netnode
//      _name   - name of netnode to create
//               Names of user-defined netnodes must have the "$ " prefix
//               in order to avoid clashes with program byte names.
//      namlen - length of the name. If not specified, it will be
//               calculated using strlen()
// returns: 1 - ok, the node is created
//          0 - the node already exists. you may use the netnode class to
//              access it.

  bool create(const char *_name, size_t namlen=0)
  {
    return netnode_check(this, _name, namlen, true);
  }


// Create unnamed netnode
// returns: 1 - ok
//          0 - should not happen, indicates internal error

  bool create(void) { return create((char *)0); }


// Delete a netnode with all information attached to it

  void kill(void) { netnode_kill(this); }


//--------------------------------------------------------------------------
// Netnode names.


// Get name of netnode
// Name of netnode    - a name (max length of name is MAXNAMESIZE)
//                      there is no limitation on characters used in names.
// returns: -1 - netnode is unnamed, otherwise the name length

  ssize_t name(char *buf, size_t bufsize) const
  {
    return netnode_name(*this, buf, bufsize);
  }


// Rename a netnode
//      newname - new name of netnode. NULL or "" means to delete name
//                Names of user-defined netnodes must have the "$ " prefix
//                in order to avoid clashes with program byte names.
//      namlen  - length of new name. If not specified, it will be
//                calculated using strlen()
// returns: 1 - ok
//          0 - failed, newname is already used

  bool rename(const char *newname, size_t namlen=0)
  {
    return netnode_rename(*this, newname, namlen);
  }


//--------------------------------------------------------------------------
// Value of netnode


// Get value of netnode
// Value of netnode  - a value: arbitary sized object, max size is MAXSPECSIZE
// returns: length of value, -1 - no value present
// NB: do not use this function for strings, see valstr()

  ssize_t valobj(void *buf, size_t bufsize) const
  {
    return netnode_valobj(*this, buf, bufsize);
  }


// Get string value of netnode
// returns: length of value, -1 - no value present
// See explanations for supstr() function about the differences between valobj()
// and valstr()

  ssize_t valstr(char *buf, size_t bufsize) const
  {
    return netnode_valstr(*this, buf, bufsize);
  }


// Set value of netnode
//      value  - pointer to value
//      length - length of value. If not specified, it will be calculated
//               using strlen()
// returns: 1 - ok

  bool set(const void *value, size_t length=0)
  {
    return netnode_set(*this, value, length);
  }


// Delete value of netnode
// returns: 1 - ok
//          0 - failed, netnode is bad or other error

  bool delvalue(void)
  {
    return netnode_delvalue(*this);
  }

// Value of netnode as a long number:

  bool set_long(nodeidx_t x) { return set(&x, sizeof(x)); }
  bool value_exists(void) const { return valobj(NULL, 0) >= 0; }
  nodeidx_t long_value(void) const
  {
    nodeidx_t v = 0;
    if ( valobj(&v, sizeof(v)) > 0 )
      return v;
    return BADNODE;
  }


//--------------------------------------------------------------------------
// Arrays of altvals
// Arrays of altvals    - altvals: a sparse array of 32-bit values.
//                        indexes in this array may be 8-bit or 32-bit values


// Get altval element of the specified array
//      alt - index into array of altvals
//      tag - tag of array. may be omitted
// returns: value of altval element. Unexistent altval members are returned
//          as zeroes

  nodeidx_t altval(nodeidx_t alt, char tag=atag) const
  {
    return netnode_altval(*this, alt, tag);
  }


// Set value of altval array
//      alt   - index into array of altvals
//      value - new value of altval element
//      tag   - tag of array
// returns: 1 - ok
//          0 - failed, normally should not occur

  bool altset(nodeidx_t alt, nodeidx_t value, char tag=atag)
  {
    return supset(alt, &value, sizeof(value), tag);
  }


// Delete element of altval array
//      alt   - index into array of altvals
//      tag   - tag of array
// returns: 1 - ok
//          0 - failed, element doesn't exist

  bool altdel(nodeidx_t alt, char tag=atag)
  {
    return supdel(alt, tag);
  }


// Get first existing element of altval array
//      tag   - tag of array
// returns: index of first existing element of altval array
//          BADNODE if altval array is empty

  nodeidx_t alt1st(char tag=atag) const
  {
    return sup1st(tag);
  }


// Get next existing element of altval array
//      cur   - current index
//      tag   - tag of array
// returns: index of the next exitsing element of altval array
//          BADNODE if no more altval array elements exist

  nodeidx_t altnxt(nodeidx_t cur, char tag=atag) const
  {
    return supnxt(cur, tag);
  }


// Get last element of altval array
//      tag   - tag of array
// returns: index of last existing element of altval array
//          BADNODE if altval array is empty

  nodeidx_t altlast(char tag=atag) const
  {
    return suplast(tag);
  }


// Get previous existing element of altval array
//      cur   - current index
//      tag   - tag of array
// returns: index of the previous exitsing element of altval array
//          BADNODE if no more altval array elements exist

  nodeidx_t altprev(nodeidx_t cur, char tag=atag) const
  {
    return supprev(cur, tag);
  }


// Shift the altval array elements
// Moves the array elements at (from..from+size) to (to..to+size)
// Returns: number of shifted elements

  size_t altshift(nodeidx_t from, nodeidx_t to, nodeidx_t size, char tag=atag)
  {
    return netnode_altshift(*this, from, to, size, tag);
  }


// Adjust values of altval arrays elements
// All altvals in the range from+1..from+size+1 and adjusted to have
// values in the range to+1..to+size+1.
// The function should_skip can be used to skip the adjustment of some altvals

  void altadjust(nodeidx_t from, nodeidx_t to, nodeidx_t size, bool (idaapi *should_skip)(nodeidx_t ea)=NULL)
  {
    netnode_altadjust(*this, from, to, size, should_skip);
  }


// The following functions behave in the same manner as the functions
// described above. The only difference is that the array value is 8-bits.
//      index - 32 bits
//      value - 8  bits

  uchar charval(nodeidx_t alt, char tag) const      { return netnode_charval(*this, alt, tag); }
  bool charset(nodeidx_t alt, uchar val, char tag)  { return supset(alt, &val, sizeof(val), tag); }
  bool chardel(nodeidx_t alt, char tag)             { return supdel(alt, tag); }
  nodeidx_t char1st(char tag) const                 { return sup1st(tag); }
  nodeidx_t charnxt(nodeidx_t cur, char tag) const  { return supnxt(cur, tag); }
  nodeidx_t charlast(char tag) const                { return suplast(tag); }
  nodeidx_t charprev(nodeidx_t cur, char tag) const { return supprev(cur, tag); }
  size_t charshift(nodeidx_t from, nodeidx_t to, nodeidx_t size, char tag)
    { return netnode_charshift(*this, from, to, size, tag); }


// Another set of functions to work with altvals.
// The only difference is that the array index is 8-bits
// and therefore the array may contain up to 256 elements only.
//      index - 8  bits
//      value - 32 bits

  nodeidx_t altval_idx8(uchar alt, char tag) const   { return netnode_altval_idx8(*this, alt, tag); }
  bool altset_idx8(uchar alt, nodeidx_t val, char tag){ return supset_idx8(alt, &val, sizeof(val), tag); }
  bool altdel_idx8(uchar alt, char tag)              { return supdel_idx8(alt, tag); }
  nodeidx_t alt1st_idx8(char tag) const              { return sup1st_idx8(tag); }
  nodeidx_t altnxt_idx8(uchar cur, char tag) const   { return supnxt_idx8(cur, tag); }
  nodeidx_t altlast_idx8(char tag) const             { return suplast_idx8(tag); }
  nodeidx_t altprev_idx8(uchar cur, char tag) const  { return supprev_idx8(cur, tag); }


// Another set of functions to work with altvals.
//      index - 8 bits
//      value - 8 bits


  uchar charval_idx8(uchar alt, char tag) const     { return netnode_charval_idx8(*this, alt, tag); }
  bool charset_idx8(uchar alt, uchar val, char tag) { return supset_idx8(alt, &val, sizeof(val), tag); }
  bool chardel_idx8(uchar alt, char tag)            { return supdel_idx8(alt, tag); }
  nodeidx_t char1st_idx8(char tag) const            { return sup1st_idx8(tag); }
  nodeidx_t charnxt_idx8(uchar cur, char tag) const { return supnxt_idx8(cur, tag); }
  nodeidx_t charlast_idx8(char tag) const           { return suplast_idx8(tag); }
  nodeidx_t charprev_idx8(uchar cur, char tag) const{ return supprev_idx8(cur, tag); }


// Delete all elements of altval array
// This function may be applied to 32-bit and 8-bit altval arrays.
// This function deletes the whole altval array.
// returns: 1 - ok, 0 - some error

  bool altdel(void)
  {
    return supdel_all(atag);
  }


// Delete all elements of the specified altval array
// This function may be applied to 32-bit and 8-bit altval arrays.
// This function deletes the whole altval array.
//      tag   - tag of array
// returns: 1 - ok, 0 - some error

  bool altdel_all(char tag)
  {
    return supdel_all(tag);
  }

// To delete range of elements in an altval array -- see supdel_range

//--------------------------------------------------------------------------
// Arrays of supvals    - supvals: an array of arbitrary sized objects. (size of
//                        each object is limited by MAXSPECSIZE)
//                        indexes in this array may be 8-bit or 32-bit values

// Get value of the specified supval array element
//      alt   - index into array of supvals
//      buf   - output buffer, may be NULL
//      bufsize - size of output buffer
//      tag   - tag of array. Default: stag
// returns: size of value, -1 - element doesn't exist
// NB: do not use this function to retrieve strings, see supstr()!

  ssize_t supval(nodeidx_t alt, void *buf, size_t bufsize, char tag=stag) const
        { return netnode_supval(*this, alt, buf, bufsize, tag); }


// Get string value of the specified supval array element
//      alt   - index into array of supvals
//      buf   - output buffer, may be NULL
//      bufsize - size of output buffer
//      tag   - tag of array. Default: stag
// returns: length of the output string, -1 - element doesn't exist
// The differences between supval() and supstr() are in the following:
//  1. Strings are stored with the terminating zero in the old databases.
//     supval() returns the exact size of the stored object (with
//     the terminating zero) but supstr returns the string length without
//     the terminating zero. supstr() can handle strings stored with or
//     without the terminating zero.
//  2. supstr() makes sure that the string is terminated with 0 even if
//     the string was stored in the database without it or the output
//     buffer is too small to hold the entire string. In the latter case
//     the string will be truncated but still will have the terminating zero.
//
// If you do not use the string length returned by supval/supstr() functions
// and you are sure that the output buffer is big enough to hold the entire
// string and the string has been stored in the database with the terminating
// zero, then you can continue to use supval() instead of supstr()

  ssize_t supstr(nodeidx_t alt, char *buf, size_t bufsize, char tag=stag) const
        { return netnode_supstr(*this, alt, buf, bufsize, tag); }


// Set value of supval array element
//      alt   - index into array of supvals
//      value - pointer to supval value
//      length- length of 'value'. If not specified, the length is calculated
//              using strlen()+1.
//      tag   - tag of array
// returns: 1 - ok, 0 - error, should not occur

  bool supset(nodeidx_t alt, const void *value, size_t length=0, char tag=stag)
        { return netnode_supset(*this, alt, value, length, tag); }


// Delete supval element
//      alt   - index into array of supvals
//      tag   - tag of array
// returns: true - deleted, false - element does not exist

  bool supdel(nodeidx_t alt, char tag=stag)
        { return netnode_supdel(*this, alt, tag); }


// Get first existing element of supval array
//      tag   - tag of array
// returns: index of first existing element of supval array
//          BADNODE if supval array is empty

  nodeidx_t sup1st(char tag=stag) const
        { return netnode_sup1st(*this, tag); }


// Get next existing element of supval array
//      cur   - current index
//      tag   - tag of array
// returns: index of the next existing element of supval array
//          BADNODE if no more supval array elements exist

  nodeidx_t supnxt(nodeidx_t cur, char tag=stag) const
        { return netnode_supnxt(*this, cur, tag); }


// Get last existing element of supval array
//      tag   - tag of array
// returns: index of last existing element of supval array
//          BADNODE if supval array is empty

  nodeidx_t suplast(char tag=stag) const
        { return netnode_suplast(*this, tag); }


// Get previous existing element of supval array
//      cur   - current index
//      tag   - tag of array
// returns: index of the previous exitsing element of supval array
//          BADNODE if no more supval array elements exist

  nodeidx_t supprev(nodeidx_t cur, char tag=stag) const
        { return netnode_supprev(*this, cur, tag); }


// Shift the supval array elements
// Moves the array elements at (from..from+size) to (to..to+size)
// Returns: number of shifted elements

  size_t supshift(nodeidx_t from, nodeidx_t to, nodeidx_t size, char tag=stag)
    { return netnode_supshift(*this, from, to, size, tag); }


// The following functions behave in the same manner as the functions
// described above. The only difference is that the array index is 8-bits
// and therefore the array may contains up to 256 elements only.

  ssize_t   supval_idx8(uchar alt, void *buf, size_t bufsize, char tag) const { return netnode_supval_idx8(*this, alt, buf, bufsize, tag); }
  ssize_t   supstr_idx8(uchar alt, char *buf, size_t bufsize, char tag) const { return netnode_supstr_idx8(*this, alt, buf, bufsize, tag); }
  bool      supset_idx8(uchar alt, const void *value, size_t length, char tag) { return netnode_supset_idx8(*this, alt, value, length, tag); }
  bool      supdel_idx8(uchar alt, char tag)        { return netnode_supdel_idx8(*this, alt, tag); }
  nodeidx_t sup1st_idx8(char tag) const             { return netnode_sup1st_idx8(*this, tag); }
  nodeidx_t supnxt_idx8(uchar alt, char tag) const  { return netnode_supnxt_idx8(*this, alt, tag); }
  nodeidx_t suplast_idx8(char tag) const            { return netnode_suplast_idx8(*this, tag); }
  nodeidx_t supprev_idx8(uchar alt, char tag) const { return netnode_supprev_idx8(*this, alt, tag); }


// Delete all elements of supval array
// This function may be applied to 32-bit and 8-bit supval arrays.
// This function deletes the whole supval array.
// returns: 1 - ok, 0 - some error

  bool   supdel(void)
  {
    return supdel_all(stag);
  }


// Delete all elements of the specified supval array
// This function may be applied to 32-bit and 8-bit supval arrays.
// This function deletes the whole supval array.
// returns: 1 - ok, 0 - some error

  bool supdel_all(char tag)
  {
    return netnode_supdel_all(*this, tag);
  }

// Delete range of elements in the specified supval array
// Elements in range [idx1, idx2) will be deleted
//      idx1  - first element to delete
//      idx2  - last element to delete + 1
//      tag   - tag of array
// returns: number of deleted elements

  int supdel_range(nodeidx_t idx1, nodeidx_t idx2, char tag)
  {
    return netnode_supdel_range(*this, idx1, idx2, tag);
  }
  int supdel_range_idx8(uchar idx1, uchar idx2, char tag)
  {
    return netnode_supdel_range_idx8(*this, idx1, idx2, tag);
  }


//--------------------------------------------------------------------------
// Hashes (associative arrays indexed by strings)
// Array of hashvals    - hashvals: a hash (an associative array)
//                        indexes in this array are strings
//                        values are arbitrary sized (max size is MAXSPECSIZE)
//                        Hashes are associative arrays indexed by strings

// Get value of the specified hash element
//      idx   - index into hash
//      buf   - output buffer, may be NULL
//      bufsize - output buffer size
//      tag   - tag of hash. Default: htag
// returns: -1 - element doesn't exist or idx is NULL
//          otherwise the value size in bytes

  ssize_t hashval(const char *idx, void *buf, size_t bufsize, char tag=htag) const
        { return netnode_hashval(*this, idx, buf, bufsize, tag); }

  ssize_t hashstr(const char *idx, char *buf, size_t bufsize, char tag=htag) const
        { return netnode_hashstr(*this, idx, buf, bufsize, tag); }


// Get value of the specified hash element
//      idx   - index into hash
//      tag   - tag of hash. Default: htag
// returns: value of hash element (it should be set using hashset(nodeidx_t))
//          0 if the element does not exist

  nodeidx_t hashval_long(const char *idx, char tag=htag) const
        { return netnode_hashval_long(*this, idx, tag); }


// Set value of hash element
//      idx   - index into hash
//      value - pointer to value
//      length- length of 'value'. If not specified, the length is calculated
//              using strlen()+1.
//      tag   - tag of hash. Default: htag
// returns: 1 - ok, 0 - error, should not occur

  bool hashset(const char *idx, const void *value, size_t length=0, char tag=htag)
        { return netnode_hashset(*this, idx, value, length, tag); }


// Set value of hash element to long value
//      idx   - index into hash
//      value - new value of hash element
//      tag   - tag of hash. Default: htag
// returns: 1 - ok, 0 - error, should not occur

  bool hashset(const char *idx, nodeidx_t value, char tag=htag)
        { return hashset(idx, &value, sizeof(value), tag); }


// Delete hash element
//      idx   - index into hash
//      tag   - tag of hash. Default: htag
// returns: true - deleted, false - element does not exist

  bool hashdel(const char *idx, char tag=htag)
        { return netnode_hashdel(*this, idx, tag); }


// Get first existing element of hash
//      buf   - output buffer, may be NULL
//      bufsize - output buffer size
//      tag   - tag of hash. Default: htag
// returns: size of index of first existing element of hash
//          -1 if hash is empty
// note: elements of hash are kept sorted in lexical order

  ssize_t hash1st(char *buf, size_t bufsize, char tag=htag) const
        { return netnode_hash1st(*this, buf, bufsize, tag); }


// Get next existing element of hash
//      idx   - current index into hash
//      buf   - output buffer, may be NULL
//      bufsize - output buffer size
//      tag   - tag of hash. Default: htag
// returns: size of index of the next existing element of hash
//          -1 if no more hash elements exist
// note: elements of hash are kept sorted in lexical order

  ssize_t hashnxt(const char *idx, char *buf, size_t bufsize, char tag=htag) const
        { return netnode_hashnxt(*this, idx, buf, bufsize, tag); }


// Get last existing element of hash
//      buf   - output buffer, may be NULL
//      bufsize - output buffer size
//      tag   - tag of hash. Default: htag
// returns: size of index of last existing element of hash
//          -1 if hash is empty
// note: elements of hash are kept sorted in lexical order

  ssize_t hashlast(char *buf, size_t bufsize, char tag=htag) const
        { return netnode_hashlast(*this, buf, bufsize, tag); }


// Get previous existing element of supval array
//      idx   - current index into hash
//      buf   - output buffer, may be NULL
//      bufsize - output buffer size
//      tag   - tag of hash. Default: htag
// returns: size of index of the previous existing element of hash
//          -1 if no more hash elements exist
// note: elements of hash are kept sorted in lexical order

  ssize_t hashprev(const char *idx, char *buf, size_t bufsize, char tag=htag) const
        { return netnode_hashprev(*this, idx, buf, bufsize, tag); }


// Delete all elements of hash
// This function deletes the whole hash
//      tag   - tag of hash. Default: htag
// returns: 1 - ok, 0 - some error

  bool hashdel_all(char tag=htag)
  {
    return supdel_all(tag);
  }


//--------------------------------------------------------------------------
// Blobs - virtually unlimited size binary objects
// Blobs are stored in several supval array elements.


// Get size of blob
//      _start - index of the first supval element used to store blob
//      tag    - tag of supval array
// returns: number of bytes required to store a blob

  size_t blobsize(nodeidx_t _start, char tag)
  {
    return netnode_blobsize(*this, _start, tag);
  }


// Get blob from a netnode
//      buf     - buffer to read into. if NULL, the buffer will be
//                allocated using qalloc()
//      bufsize - in:  size of 'buf' in bytes (if buf == NULL then meaningless)
//                out: size of the blob if it exists
//                bufsize may be NULL
//      _start  - index of the first supval element used to store blob
//      tag     - tag of supval array
// returns: NULL - blob doesn't exist
//          otherwise returns pointer to blob

  void *getblob(void *buf,
                size_t *bufsize,
                nodeidx_t _start,
                char tag)
  {
    return netnode_getblob(*this, buf, bufsize, _start, tag);
  }


// Store a blob in a netnode
//      buf     - pointer to blob to save
//      size    - size of blob in bytes
//      _start  - index of the first supval element used to store blob
//      tag     - tag of supval array
// returns: 1 - ok, 0 - error

  bool setblob(const void *buf,
              size_t size,
              nodeidx_t _start,
              char tag)
  {
    return netnode_setblob(*this, buf, size, _start, tag);
  }

// Delete a blob
//      _start - index of the first supval element used to store blob
//      tag    - tag of supval array
// returns: number of deleted supvals

  int delblob(nodeidx_t _start, char tag)
  {
    return netnode_delblob(*this, _start, tag);
  }


//--------------------------------------------------------------------------
// Links between nodes -- deprecated!
// (We can not delete them because they are used in ancient databases)

// GNUC v4.x complains about the following functions
#if !defined(__GNUC__)

// Create a link between two nodes.
//      to       - target netnode
//      linktype - type of link to create
//      linkspec - arbitrary text stored in the link
// returns: 1 - ok

  int   link(netnode to, netlink linktype, const char *linkspec);


// Delete a link between two nodes
//      to       - target netnode
//      linktype - type of link to create

  void  unlink(netnode to, netlink linktype);


// Get text accoiated with the link
//      to       - target netnode
//      buf   - output buffer, may be NULL
//      bufsize - output buffer size
//      linktype - type of link
// returns: -1 - the link doesn't exist

  ssize_t linkspec(netnode to, char *buf, size_t bufsize, netlink linktype) const;

#endif

//--------------------------------------------------------------------------
// Enumerate all netnodes


// Get first netnode in the graph
// Sets netnodenumber to the lowest existing number.
// returns: 1 - ok, 0 - graph is empty

  bool start(void)
  {
    return netnode_start(this);
  }


// Get last netnode in the graph
// Sets netnodenumber to the highest existing number.
// returns: 1 - ok, 0 - graph is empty

  bool end(void)
  {
    return netnode_end(this);
  }


// Get next netnode in the graph
// Sets netnodenumber to the next existing number
// returns: 1 - ok, 0 - no more netnodes

  bool next(void)
  {
    return netnode_next(this);
  }


// Get prev netnode in the graph
// Sets netnodenumber to the previous existing number
// returns: 1 - ok, 0 - no more netnodes

  bool prev(void)
  {
    return netnode_prev(this);
  }



//--------------------------------------------------------------------------
// Move and copy netnodes

// target - the target netnode
// count - how many netnodes to copy
// returns: number of copied/moved keys, BADNODE-failure, not enough memory

  size_t copyto(netnode target, nodeidx_t count=1) { return netnode_copy(netnodenumber, count, target.netnodenumber, false); }
  size_t moveto(netnode target, nodeidx_t count=1) { return netnode_copy(netnodenumber, count, target.netnodenumber, true); }

//--------------------------------------------------------------------------
// Netnode comparisons

  bool operator==(netnode &n) const { return netnodenumber == n.netnodenumber; }
  bool operator!=(netnode &n) const { return netnodenumber != n.netnodenumber; }
  bool operator==(nodeidx_t x) const { return netnodenumber == x; }
  bool operator!=(nodeidx_t x) const { return netnodenumber != x; }


//--------------------------------------------------------------------------
//
//      The following netnode definitions are for the kernel only.
//
//      Functions for global base manipulating
//

  static bool truncate_zero_pages(const char *fname);
  static bool append_zero_pages(const char *fname);
  static bool createbase(const char *fname, nodeidx_t initial_nodeid=0); // Create base
  static int  checkbase(const char *fname);
#define NNBASE_OK      0        // ok
#define NNBASE_REPAIR  1        // repair database
#define NNBASE_IOERR   2        // i/o error
#define NNBASE_PAGE16  3        // 16-bit database
  static void set_close_flag(bool closeflag);   // Set "closed" flag of database
  static nodeidx_t reserve_nodes(nodeidx_t n);  // Reserve 'n' node numbers. Returns first reserved number
  static void validate(const char *badbase, const char *newbase, void (*cb)(uint32));
  static void upgrade(const char *oldbase, const char *newbase, void (*cb)(uint32));
  static void compress(const char *oldbase, const char *newbase, void (*cb)(uint32));

  static bool inited(void) { return netnode_inited(); }
  static void init(const char *file, size_t cachesize, bool can_modify);
  static void flush(void);
  static void term(void);
  static void killbase(nodeidx_t iniNumber=0);      // Clean up ALL base
  static int  getdrive(void);                   // Get current drive
  static int  getgraph(void)                    // Get current graph
                                                // (for compatibility:
               { return atag; }                 //   always returns 'A'
  static int  registerbase(const char *filename, size_t cachesize, bool writeFlag=true);
                                                // Register aux base file
                                                // 0 - too many bases
                                                // else - drive number
  static bool setbase(int drive, int graph=atag);// Set current base
                                                // Base -- got from setbasefile
                                                // 'graph' parameter is not used.
                                                // (must be equal to atag)
                                                // (for compatibility)

//--------------------------------------------------------------------------
// Private definitions

private:

// Number of netnode. Usually this is linear address the netnode keeps
// information about.

  nodeidx_t netnodenumber;                  // Reference number for the node



  bool check(const char *oldname, size_t namlen=0) // Check and access node type
        { return netnode_check(this, oldname, namlen, false); }

  qstring qsupval(nodeidx_t ea, char tag) const;
  void qsupset(nodeidx_t ea, const qstring &x, char tag);

};


//--------------------------------------------------------------------------
//      N E T L I N K
//--------------------------------------------------------------------------

class netlink
{
  friend class netnode;
  friend void select(const netlink *n);
  nodeidx_t linknumber;
  int check(const char *oldname);       // Check and access link type
public:

// Empty constructor

  netlink(void) {}


// Main constructor.
//      _name     - name of netlink type
//      do_create - 1: create the netlink if it doesn't exist yet.
//                  0: don't create the netlink, set linknumber to 0 if
//                     it doesn't exist

  netlink(const char *_name, bool do_create=false)
  {
    if ( do_create )
      create(_name);
    else
      check(_name);
  }


// Does a netlink exist?

  friend bool exist(const netlink &L) { return L.linknumber != 0; }


// Create a netlink
//      name - name of new netlink type
// returns: 1 - ok, 0 - netlink type already exists

  bool create(const char *name);


// Get name of netlink type
//      buf   - output buffer, may be NULL
//      bufsize - output buffer size
// returns -1 - bad netlink type

  ssize_t name(char *buf, size_t bufsize) const;


// Rename a netlink type
//      name - new name of netlink type
// returns: 1 - ok, 0 - netlink type already exists

  bool rename(const char *newname);


// Get first netlink type in the graph
// returns: 1 - ok, 0 - the graph doesn't contains netlinks

  bool start(void);


// Get next netlink type in the graph
// returns: 1 - ok, 0 - no more netlinks

  bool next(void);


// Get first netlink type used to link a netnode to other netnodes
//      from - source netnode
// returns: BADNODE - the netnode is not linked to other netnodes
//          otherwise returns a netnode linked to the source netnode using
//          the current netlink.

  netnode firstlink(netnode from) const;


// Get next netlink type used to link a netnode to other netnodes
//      from    - source netnode
//      current - current netnode
// returns: BADNODE - the netnode is not linked to no more netnodes
//          otherwise returns the next netnode linked to the source netnode
//          using the current netlink.

  netnode nextlink(netnode from, netnode current) const;


// Netlink comparisons

  bool operator==(netlink &n) const { return linknumber == n.linknumber; }
  bool operator!=(netlink &n) const { return linknumber != n.linknumber; }
};

//-----------------------------------------------------------------------

// The rootnode is used by the kernel, don't use it in your modules!

idaman netnode ida_export_data RootNode;             // name: "Root Node"


// Error message handler. Should display the message and exit

extern void (idaapi *netErrorHandler)(const char *message);       // error handler.

int netnode_key_count(void);

int for_all_supvals(nodeidx_t start,
                    int callback(nodeidx_t node,
                                 uchar tag,
                                 nodeidx_t idx,
                                 const uchar *data,
                                 size_t datlen,
                                 void *ud),
                    void *ud);

#pragma pack(pop)
#endif // _NETNODE_HPP
