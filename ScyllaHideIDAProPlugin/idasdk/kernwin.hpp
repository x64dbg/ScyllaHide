/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2008 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

//
//      This file defines the interface between the kernel and the user
//      interface (UI). It contains:
//              - the UI dispatcher notification codes
//              - convention functions for UI services
//              - structures which hold information about the
//                lines (disassembly, structures, enums) generated
//                by the kernel
//              - functions to interact with the user (dialog boxes)
//              - some string and conversion functions.
//

#ifndef __KERNWIN_HPP
#define __KERNWIN_HPP
#pragma pack(push, 1)           // IDA uses 1 byte alignments!

#ifndef SWIG
typedef uchar color_t;          // see <lines.hpp>
typedef uval_t bmask_t;         // see <enum.hpp>
typedef tid_t enum_t;           // see <enum.hpp>
struct areavec_t;               // see <area.hpp>
class location_t;               // see <moves.hpp>
#endif // SWIG

// Message box kinds:

enum mbox_kind_t
{
  mbox_internal,                // internal error
  mbox_info,
  mbox_warning,
  mbox_error,
  mbox_nomem,
  mbox_feedback,
  mbox_readerror,
  mbox_writeerror,
  mbox_filestruct,
  mbox_wait,
  mbox_hide,
  mbox_replace,
};


// List chooser types

enum choose_type_t
{
  chtype_generic,               // the generic choose() function (1-column)
  chtype_idasgn,                // signature
  chtype_entry,                 // entry point
  chtype_name,                  // name from list
  chtype_stkvar_xref,           // xref to stack variable
  chtype_xref,                  // xref to address
  chtype_enum,                  // enum
  chtype_enum_by_value,         // enum (restriction by value)
  chtype_func,                  // function
  chtype_segm,                  // segment
  chtype_segreg,                // segment register change point
  chtype_struc,                 // structure
  chtype_strpath,               // structure path
  chtype_generic2,              // the generic choose2() function (n-column)
  chtype_idatil,                // type information libraries
};


enum beep_t             // Beep types
{
  beep_default = 0
};


// Notify UI about various events. The kernel will call this function
// when something interesting for the UI happens.
// The UI should avoid calling the kernel from this callback.

class func_t;
class segment_t;
class segreg_t;
class struc_t;
class member_t;
class TView;
class plugin_t;
class minsn_t;
class idc_value_t;
class linput_t;
class snapshot_t;

#ifndef SWIG
union callui_t          // Return codes (size of this type should be 4 bytes at most)
{                       //              (otherwise different compilers return it differently)
  bool cnd;
  char i8;
  int i;
  short i16;
  int32 i32;
  uchar u8;
  ushort u16;
  uint32 u32;
  char *cptr;
  void *vptr;
  ssize_t ssize;
  func_t *fptr;
  segment_t *segptr;
  segreg_t *sregptr;
  struc_t *strptr;
  plugin_t *pluginptr;
};

CASSERT(sizeof(callui_t) <= sizeof(size_t)); // bad callui_t definition

// Events marked as '*' should be used as a parameter to callui()
// See convenience functions below (like get_screen_ea())
// Events marked as 'cb' are designed to be callbacks and should not
// be used in callui(). The user may hook to HT_UI events to catch them

enum ui_notification_t
{
  ui_null = 0,

  ui_range,             // cb: the disassembly range have been changed (inf.minEA..inf.maxEA)
                        // UI should redraw the scrollbars
                        // See also: lock_range_refresh
                        // Parameters: none
                        // Returns:    none

  ui_list,              // cb: the list (chooser) window contents have been changed
                        // (names, signatures, etc) UI should redraw them
                        // Parameters: none
                        // Returns:    none
                        // Please consider request_refresh() instead

  ui_idcstart,          // cb: Start of IDC engine work
                        // Parameters: none
                        // Returns:    none

  ui_idcstop,           // cb: Stop of IDC engine work
                        // Parameters: none
                        // Returns:    none

  ui_suspend,           // cb: Suspend graphical interface.
                        // Only the text version
                        // interface should response to it
                        // Parameters: none
                        // Returns:    none

  ui_resume,            // cb: Resume the suspended graphical interface.
                        // Only the text version
                        // interface should response to it
                        // Parameters: none
                        // Returns:    none

  ui_old_jumpto,        // * Jump to the specified address
                        // Parameters:
                        //      ea_t ea
                        //      int operand_num (-1: don't change x coord)
                        // Returns: bool success

  ui_readsel,           // * Get the selected area boundaries
                        // Parameters:
                        //      ea_t *startea
                        //      ea_t *endea
                        // Returns: bool
                        //          0 - no area is selected
                        //          1 - ok, startea and endea are filled
                        // See also: ui_readsel2

  ui_unmarksel,         // * Unmark selection
                        // Parameters: none
                        // Returns:    none

  ui_screenea,          // * Return the address at the screen cursor
                        // Parameters: ea_t *result
                        // Returns:    none

  ui_saving,            // cb: The kernel is flushing its buffers to the disk.
                        // The user interface should save its state.
                        // Parameters: none
                        // Returns:    none

  ui_saved,             // cb: The kernel has saved the database.
                        // This callback just informs the interface.
                        // Parameters: none
                        // Returns:    none

  ui_refreshmarked,     // * Refresh marked windows
                        // Parameters: none
                        // Returns:    none

  ui_refresh,           // * Refresh all disassembly views
                        // Parameters: none
                        // Returns:    none
                        // Forces an immediate refresh.
                        // Please consider request_refresh() instead

  ui_choose,            // * Allow the user to choose an object
                        // Parameters:
                        //      choose_type_t type
                        //      ...
                        // other parameters depend on the 'type'
                        // see below for inline functions using this
                        // notification code.
                        // Always use the helper inline functions below.
                        // Returns: depends on the 'type'

  ui_close_chooser,     // * Close a non-modal chooser
                        // Parameters:
                        //      const char *title
                        // Returns: bool success

  ui_banner,            // * Show a banner dialog box
                        // Parameters:
                        //      int wait
                        // Returns: bool 1-ok, 0-esc was pressed

  ui_setidle,           // * Set a function to call at idle times
                        // Parameters:
                        //      int (*func)(void);
                        // Returns: none

  ui_noabort,           // * Disable 'abort' menu item - the database was not
                        // compressed
                        // Parameters: none
                        // Returns:    none

  ui_term,              // cb: IDA is terminated
                        // The database is already closed.
                        // The UI may close its windows in this callback.
                        // Parameters: none
                        // Returns:    none

  ui_mbox,              // * Show a message box
                        // Parameters:
                        //      mbox_kind_t kind
                        //      const char *format
                        //      va_list va
                        // Returns: none

  ui_beep,              // * Beep
                        // Parameters:
                        //      beep_t beep_type
                        // Returns:    none

  ui_msg,               // * Show a message in the message window
                        // Parameters:
                        //      const char *format
                        //      va_list va
                        // Returns: number of bytes output

  ui_askyn,             // * Ask the user and get his yes/no response
                        // Parameters:
                        //      const char *yes_button
                        //      const char *no_button
                        //      const char *cancel_button
                        //      int default_answer (ASKBTN_XXX)
                        //      const char *format
                        //      va_list va
                        // Returns: ASKBTN_XXX value

  ui_askfile,           // * Ask the user a file name
                        // Parameters:
                        //      int savefile
                        //      const char *default_answer
                        //      const char *format
                        //      va_list va
                        // Returns: file name

  ui_form,              // * Show a dialog form
                        // Parameters:
                        //      const char *format
                        //      va_list va
                        // Returns: bool 0-esc, 1-ok

  ui_close_form,        // * Close the form
                        // This function may be called from pushbutton
                        // callbacks in ui_form
                        //      TView *fields[]
                        //      int is_ok
                        // Returns: none

  ui_clearbreak,        // * clear ctrl-break flag
                        // Parameters: none
                        // Returns: none
                        // NB: this call is also used to get ida version

  ui_wasbreak,          // * test the ctrl-break flag
                        // Parameters: none
                        // Returns: 1 - Ctrl-Break is detected, a message is displayed
                        //          2 - Ctrl-Break is detected again, a message is not displayed
                        //          0 - Ctrl-Break is not detected

  ui_asktext,           // * Ask text
                        // Parameters:
                        //      size_t size
                        //      char *answer
                        //      const char *default_value
                        //      const char *format
                        //      va_list va
                        // Returns: the entered text

  ui_askstr,            // * Ask a string
                        // Parameters:
                        //      int history_number
                        //      const char *default_value
                        //      const char *format
                        //      va_list va
                        // Returns: the entered string

  ui_askident,          // * Ask an identifier
                        // Parameters:
                        //      const char *default_value
                        //      const char *format
                        //      va_list va
                        // Returns: cptr the entered identifier

  ui_askaddr,           // * Ask an address
                        // Parameters:
                        //      ea_t *answer
                        //      const char *format
                        //      va_list va
                        // Returns: bool success

  ui_askseg,            // * Ask a segment
                        // Parameters:
                        //      sel_t *answer
                        //      const char *format
                        //      va_list va
                        // Returns: bool success

  ui_asklong,           // * Ask a long
                        // Parameters:
                        //      sval_t *answer
                        //      const char *format
                        //      va_list va
                        // Returns: bool success

  ui_showauto,          // * Show the autoanalysis state
                        // Parameters:
                        //      ea_t ea
                        //      int auto_t (see auto.hpp)
                        // Returns: none

  ui_setstate,          // * Show READY, BUSY, THINKING, etc
                        // Parameters:
                        //      int idastate_t (see auto.hpp)
                        // Returns: int: old ida state

  ui_add_idckey,        // * Add hotkey for IDC function
                        // After this function the UI should call the
                        // specified IDC function
                        // when the hotkey is pressed
                        // Parameters:
                        //      const char *hotkey
                        //      const char *idcfuncname
                        // Returns: int code
#define IDCHK_OK        0       // ok
#define IDCHK_ARG       -1      // bad argument(s)
#define IDCHK_KEY       -2      // bad hotkey name
#define IDCHK_MAX       -3      // too many IDC hotkeys

  ui_del_idckey,        // * Delete IDC function hotkey
                        // Parameters:
                        //      hotkey  - hotkey name
                        // Returns: bool success

  ui_old_get_marker,    // * Get pointer to function
                        // "void mark_idaview_for_refresh(ea_t ea)"
                        // This function will be called by the kernel when the
                        // database is changed
                        // Parameters: none
                        // Returns: vptr: (idaapi*marker)(ea_t ea) or NULL
                        // OBSOLETE

  ui_analyzer_options,  // * Allow the user to set analyzer options
                        // (show a dialog box)
                        // Parameters: none
                        // Returns: none

  ui_is_msg_inited,     // * Can we use msg() functions?
                        // Parameters: none
                        // Returns: bool cnd

  ui_load_file,         // Display a load file dialog and load file
                        // Parameters:
                        //      const char *filename
                        //              the name of input file as is
                        //              (if the input file is from library,
                        //               then this is the name in the library)
                        //      linput_t *li
                        //              loader input source
                        //      ushort neflags
                        //              combination of NEF_... bits
                        //              (see loader.hpp)
                        // Returns: bool cnd;

  ui_run_dbg,           // * Load a debugger plugin and run the specified program
                        // Parameters:
                        //      const char *dbgopts - value of the -r command line switch
                        //      const char *exename - name of the file to run
                        //      int argc            - number of arguments for the executable
                        //      char **argv         - argument vector
                        // Returns: bool cnd

  ui_get_cursor,        // * Get the cursor position on the screen
                        // Parameters:
                        //             int *x
                        //             int *y
                        // Returns:    bool cnd
                        //               true: x,y pointers are filled
                        //               false: no disassembly window open

  ui_get_curline,       // * Get current line from the disassemble window
                        // Parameters: none
                        // Returns:    cptr current line with the color codes
                        // (use tag_remove function to remove the color codes)

  ui_get_hwnd,          // * Get HWND of the main IDA window
                        // Parameters: none
                        // Returns:    txt version: NULL
                        //             gui version: HWND
                        //             qt version under windows: HWND
                        // HWND is returned in result.vptr

  ui_copywarn,          // * Display copyright warning
                        // Parameters: none
                        // Returns:    bool yes/no

  ui_getvcl,            // * Get VCL variables
                        // Parameters:
                        //              TApplication **app
                        //              TScreen **screen
                        //              TMouse **mouse
                        // Returns: int sizeof(TApplication)+sizeof(TScreen)+sizeof(TMouse)
                        // The text version fills the pointers with NULLs and returns 0

  ui_idp_event,         // cb: A processor module event has been generated (idp.hpp, idp_notify)
                        // Parameteres:
                        //      ph::idp_notify event_code
                        //      va_list va
                        // Returns:
                        //      int code; code==0 - process the event
                        //                otherwise return code as the result
                        // This event should not be used as a parameter to callui()
                        // The kernel uses it to notify the ui about the events

  ui_lock_range_refresh,// * Lock the ui_range refreshes. The ranges will not
                        // be refreshed until the corresponding unlock_range_refresh
                        // is issued.
                        // See also: unlock_range_refresh
                        // Parameters: none
                        // Returns:    none

  ui_unlock_range_refresh,// * Unlock the ui_range refreshes. If the number of locks
                        // is back to zero, then refresh the ranges.
                        // See also: ui_range
                        // Parameters: none
                        // Returns:    none

  ui_setbreak,          // * set ctrl-break flag
                        // Parameters: none
                        // Returns: none

  ui_genfile_callback,  // cb: handle html generation
                        // parameters: html_header_cb_t **,
                        //             html_footer_cb_t **,
                        //             html_line_cb_t **
                        // returns: nothing

  ui_open_url,          // * open url
                        // Parameters: const char *url
                        // Returns: none

  ui_hexdumpea,         // * Return the current address in a hex view
                        // Parameters: ea_t *result
                        //             int hexdump_num
                        // Returns:    none

  ui_set_xml,           // * set/update one or more XML values. The 'name' element
                        // or attribute (use @XXX for an attribute) is created in
                        // all XML elements returned by the evaluation of the
                        // 'path' XPath expression, and receives the given 'value'.
                        // If 'name' is empty, the returned elements or attributes
                        // are directly updated to contain the new 'value'.
                        // Parameters: const char *path
                        //             const char *name
                        //             const char *value
                        // Returns:    bool

  ui_get_xml,           // * return an XML value by evaluating the 'path' XPath
                        // expression.
                        // Parameters: const char *path
                        //             idc_value_t *value
                        // Returns:    bool

  ui_del_xml,           // * delete XML values corresponding to the evaluation of the
                        // 'path' XPath expression.
                        // Parameters: const char *path
                        // Returns:    bool

  ui_push_xml,          // * push an XML element on a stack whose uppermost element will be
                        // used to evaluate future relative XPath expressions.
                        // Parameters: const char *path
                        // Returns:    bool

  ui_pop_xml,           // * pop the uppermost XML element from the stack.
                        // Parameters: none
                        // Returns:    bool

  ui_get_key_code,      // * get keyboard key code by its name
                        // Parameters: const char *keyname
                        // Returns:    short code

  ui_setup_plugins_menu,// * setup plugins submenu
                        // Parameters: none
                        // Returns:    none

  ui_refresh_navband,   // * refresh navigation band if changed
                        // Parameters: bool force
                        // Returns:    none

  ui_new_custom_viewer, // * create new ida viewer based on place_t (gui)
                        // Parameters:
                        //      const char *title
                        //      TWinControl *parent
                        //      const place_t *minplace
                        //      const place_t *maxplace
                        //      const place_t *curplace
                        //      int y
                        //      void *ud
                        // returns: TCustomControl *
                        // see also: ui_new_ea_viewer

  ui_add_menu_item,     // * add a menu item
                        // Parameters: const char *menupath,
                        //             const char *name,
                        //             const char *hotkey,
                        //             int flags,
#define SETMENU_POSMASK     0x1
#define SETMENU_INS         0x0         // add menu item before the specified path (default)
#define SETMENU_APP         0x1         // add menu item after the specified path
#define SETMENU_CTXMASK     0x7C000000  // context flags for the menu item
#define SETMENU_CTXAPP      0x00000000  // global (default)
#define SETMENU_CTXIDA      0x04000000  // disassembly
#define SETMENU_CTXSTR      0x08000000  // structures
#define SETMENU_CTXENUM     0x0C000000  // enumerations
#define SETMENU_CTXEA       0x10000000  // ea views (disassembly, hex)
#define SETMENU_CTXVIEW     0x14000000  // any kind of view (disassembly, hex, structures, etc.)
                        //             menu_item_callback_t *callback,
                        //             void *ud
                        // Returns:    bool

  ui_del_menu_item,     // * del a menu item
                        // Parameters: const char *menupath
                        // Returns:    bool

  ui_debugger_menu_change, // cb: debugger menu modification detected
                        // Parameters: bool enable
                        // enable=true: debugger menu has been added
                        // enable=false: debugger menu will be removed

  ui_get_curplace,      // * Get current place in a custom viewer
                        // Parameters:
                        // TCustomControl *v
                        // bool mouse_position (otherwise keyboard position)
                        // int *x
                        // int *y
                        // returns: place_t *

  ui_create_tform,      // * create a new tform (only gui version)
                        // Parameters: const char *caption
                        //             HWND *handle
                        // If you need the handle of the new window,
                        // you can get it using the 'handle' parameter.
                        // You will need it if you do not use VCL.
                        // If a window with the specified caption exists, return
                        // a pointer to it. 'handle' will be NULL is this case.
                        // Returns: TForm * of a new or existing window
                        // The text version always returns NULL
                        // NB: Do not use 'handle' to populate the window
                        // because it can be destroyed by the user interface
                        // at any time. Also, the handle is invalid at the
                        // form creation time. It is present only for
                        // the compatibility reasons.
                        // Hook to ui_tform_visible event instead.

  ui_open_tform,        // * open tform (only gui version)
                        // Parameters: TForm *form
                        //             int options
//#define FORM_MDI      0x01 // start by default as MDI
#define FORM_TAB      0x02 // attached by default to a tab
#define FORM_RESTORE  0x04 // restore state from desktop config
#define FORM_ONTOP    0x08 // form should be "ontop"
#define FORM_MENU     0x10 // form must be listed in the windows menu
                           // (automatically set for all plugins)
#define FORM_CENTERED 0x20 // form will be centered on the screen
                        // Returns: nothing
#define FORM_PERSIST  0x40 // form will persist until explicitly closed with close_tform()
                        // Returns: nothing
#define FORM_QWIDGET  0x80 // windows: use QWidget* instead of HWND in ui_tform_visible
                           // this flag is ignored in unix because we never use HWND there.
                           // around 2011/09 we plan to get rid of HWND and always use QWidget*
                           // regardless of this flag.
#define FORM_CLOSED_BY_ESC     0x100 // override idagui.cfg:CLOSED_BY_ESC: esc will close
#define FORM_NOT_CLOSED_BY_ESC 0x200 // override idagui.cfg:CLOSED_BY_ESC: esc will not close

  ui_close_tform,       // * close tform (only gui version)
                        // Parameters: TForm *form
                        //             int options
#define FORM_SAVE           0x1 // save state in desktop config
#define FORM_NO_CONTEXT     0x2 // don't change the current context (useful for toolbars)
#define FORM_DONT_SAVE_SIZE 0x4 // don't save size of the window
#define FORM_CLOSE_LATER    0x8 // assign the deletion of the form to the UI loop
                        // Returns: nothing

  ui_switchto_tform,    // * activate tform (only gui version)
                        // Parameters: TForm *form
                        //             bool take_focus
                        // Returns: nothing

  ui_find_tform,        // * find tform with the specified caption  (only gui version)
                        // Parameters: const char *caption
                        // Returns: TFrom *
                        // NB: this callback works only with the tabbed forms!

  ui_get_current_tform, // * get current tform (only gui version)
                        // Parameters: none
                        // Returns: TFrom *
                        // NB: this callback works only with the tabbed forms!

  ui_get_tform_handle,  // * get tform handle
                        // Parameters: TForm *form
                        // Returns: HWND
                        // tform handles can be modified by the interface
                        // (for example, when the user switch from mdi to desktop)
                        // This function returns the current tform handle.
                        // It is better to hook to the 'ui_tform_visible'
                        // event and populate the window with controls at
                        // that time.

  ui_tform_visible,     // tform is displayed on the screen
                        // Use this event to populate the window with controls
                        // Parameters: TForm *form
                        //             HWND hwnd or QWidget* widget
                        // In unix, always work with QWigdet*
                        // In windows, use HWND if FORM_QWIDGET was not specified in open_tform()
                        // Returns: nothing

  ui_tform_invisible,   // tform is being closed
                        // Use this event to destroy the window controls
                        // Parameters: TForm *form
                        //             HWND hwnd or QWidget* widget
                        // See comment for ui_tform_visible
                        // Returns: nothing

  ui_get_ea_hint,       // cb: ui wants to display a simple hint for an address
                        // Use this event to generate a custom hint
                        // Parameters: ea_t ea
                        //             char *buf
                        //             size_t bufsize
                        // Returns: bool: true if generated a hint
                        // See also more generic ui_get_item_hint

  ui_get_item_hint,     // cb: ui wants to display multiline hint for an item
                        // Parameters: ea_t ea (or item id like a structure or enum member)
                        //             int max_lines -- maximal number of lines
                        //             int *important_lines  -- out: number of important lines
                        //                                           if zero, output is ignored
                        //             qstring *hint  -- the output string
                        // Returns: bool: true if generated a hint
                        // See also more generic ui_get_custom_viewer_hint

  ui_set_nav_colorizer, // * setup navigation band color calculator (gui)
                        // Parameters: nav_colorizer_t *func
                        // Returns: vptr: pointer to old colorizer

  ui_refresh_custom_viewer, // * refresh custom ida viewer
                        // Parameters:
                        // TCustomControl *custom_viewer
                        // returns: nothing

  ui_destroy_custom_viewer, // * destroy custom ida viewer
                        // Parameters:
                        // TCustomControl *custom_viewer
                        // returns: nothing

  ui_jump_in_custom_viewer, // * set cursor position in custom ida viewer
                        // Parameters:
                        // TCustomControl *custom_viewer
                        // place_t *new_position
                        // int x
                        // int y
                        // returns: bool success

  ui_set_custom_viewer_popup, // * clear custom viewer popup menu
                        // TCustomControl *custom_viewer
                        // TPopupMenu *popup (NULL-clear menu)
                        // returns: nothing

  ui_add_custom_viewer_popup, // * add custom viewer popup menu item
                        // TCustomControl *custom_viewer
                        // const char *title
                        // const char *hotkey
                        // menu_item_callback_t *cb
                        // void *ud
                        // returns: nothing

  ui_set_custom_viewer_handlers,
                        // * set handlers for custom viewer events
                        // TCustomControl *custom_viewer
                        // custom_viewer_keydown_t *keyboard_handler
                        // custom_viewer_popup_t *popup_handler
                        // custom_viewer_dblclick_t *dblclick_handler
                        // custom_viewer_curpos_t *curpos_handler
                        // custom_viewer_close_t *close_handler
                        // void *user_data
                        // Any of these handlers may be NULL
                        // returns: nothing
                        // see also: ui_set_custom_viewer_handler

  ui_get_custom_viewer_curline,
                        // * get custom viewer current line
                        // TCustomControl *custom_viewer
                        // bool mouse (current for mouse pointer?)
                        // returns: cptr: const char * or NULL
                        // The returned line is with color codes

  ui_get_current_viewer,// * get current ida viewer (idaview or custom viewer)
                        // returns: TCustomControl *viewer

  ui_is_idaview,        // * is idaview viewer? (otherwise-custom viewer)
                        // TCustomControl *custom_viewer
                        // returns: bool

  ui_get_custom_viewer_hint,
                        // cb: ui wants to display a hint for a viewer (idaview or custom)
                        // TCustomControl *viewer - viewer
                        // place_t *place         - current position in it
                        // int *important_lines  -- out: number of important lines
                        //                               if zero, the result is ignored
                        // qstring *hint -- the output string
                        // Returns: bool: true if generated a hint

  ui_readsel2,          // * Get the selected area boundaries
                        // Parameters:
                        //      TCustomControl *custom_viewer
                        //      twinpos_t *start
                        //      twinpos_t *end
                        // Returns: bool
                        //          0 - no area is selected
                        //          1 - ok, start and end are filled
                        // This is more complex version of ui_readsel.
                        // If you see only the addresses, use ui_readsel.

  ui_set_custom_viewer_range,
                        // * set position range for custom viewer
                        // Parameters:
                        //      TCustomControl *custom_viewer
                        //      const place_t *minplace
                        //      const place_t *maxplace
                        // returns: nothing

  ui_database_inited,   // cb: database initialization has completed
                        // the kernel is about to run idc scripts
                        // Parameters: int is_new_database
                        //             const char *idc_script (maybe NULL)
                        // Returns:    none

  ui_ready_to_run,      // cb: all UI elements have been initialized.
                        // Automatic plugins may hook to this event to
                        // perform their tasks.
                        // Parameters: none
                        // Returns: nothing

  ui_set_custom_viewer_handler,
                        // * set a handler for a custom viewer event
                        // TCustomControl *custom_viewer
                        // custom_viewer_handler_id_t handler_id
                        // void *handler_or_data
                        // returns: old value of the handler or data
                        // see also: ui_set_custom_viewer_handlers

  ui_refresh_chooser,   // * Mark a non-modal custom chooser for a refresh
                        // Parameters:
                        //      const char *title
                        // Returns: bool success

  ui_add_chooser_cmd,   // * add a menu item to a chooser window
                        // const char *chooser_caption
                        // const char *cmd_caption
                        // chooser_cb_t *chooser_cb
                        // int menu_index
                        // int icon
                        // int flags
                        // const char *hotkey (only when CHOOSER_HOTKEY is specified)
                        // Returns: bool success

  ui_open_builtin,      // * open a window of a built-in type
                        // int window_type (one of BWN_... constants)
                        // additional params depend on the window type
                        // see below for the inline convenience functions
                        // Returns: TForm * window pointer

  ui_preprocess,        // cb: ida ui is about to handle a user command
                        // const char *name: ui command name
                        //   these names can be looked up in ida[tg]ui.cfg
                        // returns: int 0-ok, nonzero: a plugin has handled the command

  ui_postprocess,       // cb: an ida ui command has been handled

  ui_set_custom_viewer_mode,
                        // * switch between graph/text modes
                        // TCustomControl *custom_viewer
                        // bool graph_view
                        // bool silent
                        // Returns: bool success

  ui_gen_disasm_text,   // * generate disassembly text for a range
                        // ea_t ea1
                        // ea_t ea2
                        // text_t *text
                        // bool truncate_lines (on inf.margin)
                        // returns: nothing, appends lines to 'text'

  ui_gen_idanode_text,  // cb: generate disassembly text for a node
                        // qflow_chart_t *fc
                        // int node
                        // text_t *text
                        // Plugins may intercept this event and provide
                        // custom text for an IDA graph node
                        // They may use gen_disasm_text() for that.
                        // Returns: bool text_has_been_generated

  ui_install_cli,       // * install command line interpreter
                        // cli_t *cp,
                        // bool install
                        // Returns: nothing

  ui_execute_sync,      // * execute code in the main thread
                        // exec_request_t *req
                        // Returns: int code

  ui_enable_input_hotkeys,
                        // * enable or disable alphanumeric hotkeys
                        //   which can interfere with user input
                        // bool enable
                        // Returns: bool new_state

  ui_get_chooser_obj,
                        // * get underlying object of the specified chooser
                        // const char *chooser_caption
                        // Returns: void *chooser_object

  ui_enable_chooser_item_attrs,
                        // * enable item-specific attributes for a chooser
                        // const char *chooser_caption
                        // bool enable
                        // Returns: success

  ui_get_chooser_item_attrs,
                        // cb: get item-specific attributes for a chooser
                        // void *chooser_object
                        // uint32 n
                        // chooser_item_attrs_t *attrs
                        // Returns: nothing
                        // This callback is generated only after enable_chooser_attrs()

  ui_set_dock_pos,      // * sets the docking position of a form
                        // const char *src_form
                        // const char *dest_form
                        // const int orientation (one of DP_XXXX flags)
                        // const int left, top, right, bottom
                        // Returns: boolean
#define DP_LEFT            0x0001
#define DP_TOP             0x0002
#define DP_RIGHT           0x0004
#define DP_BOTTOM          0x0008
#define DP_INSIDE          0x0010
#define DP_BEFORE          0x0020
#define DP_RAW             0x0040
#define DP_FLOATING        0x0080

  ui_get_opnum,         // * get current operand number
                        // Returns int operand number. -1 means no operand

  ui_install_custom_datatype_menu,
                        // * install/remove custom data type menu item
                        // int dtid - data type id
                        // bool install
                        // Returns: success

  ui_install_custom_optype_menu,
                        // * install/remove custom operand type menu item
                        // int fid - format id
                        // bool install
                        // Returns: success

  ui_get_range_marker,  // * Get pointer to function
                        // "void mark_range_for_refresh(ea_t ea, asize_t size)"
                        // This function will be called by the kernel when the
                        // database is changed
                        // Parameters: none
                        // Returns: vptr: (idaapi*marker)(ea_t ea, asize_t) or NULL

  ui_get_highlighted_identifier,
                        // * Returns the highlighted identifier in the current IDAView
                        // char *buf - buffer to copy identifier to
                        // size_t bufsize - buffer size
                        // int flags - currently not used (pass 0)
                        // Returns: bool (false if no identifier is highlighted)

  ui_lookup_key_code,   // * Get shortcut code previously created by get_key_code
                        // Parameters: int key
                        //             int shift
                        //             bool is_qt
                        // Returns:    short code

  ui_load_custom_icon_file,
                        // * Loads an icon and returns its id
                        // Parameters: const char *file_name
                        // Returns: int

  ui_load_custom_icon,  // * Loads an icon and returns its id
                        // Parameters: const void *ptr
                        //             uint len
                        //             const char *format
                        // Returns: int

  ui_free_custom_icon,  // * Frees an icon loaded with ui_load_custom_icon(_file)
                        // Parameters: int icon_id

  ui_process_action,    // * Processes a UI action by name
                        // Parameters: const char *name
                        //             int flags (reserved / not used)
                        //             void *param (reserved / not used)

  ui_new_code_viewer,   // * Create a code viewer
                        // Parameters: TWinControl *parent
                        //             TCustomControl *custview
                        //             int flags (combination of CDVF_* flags)
                        // returns: TCustomControl *

#define CDVF_NOLINES        0x0001    // don't show line numbers
#define CDVF_LINEICONS      0x0002    // icons can be drawn over the line control
#define CDVF_STATUSBAR      0x0004    // keep the status bar in the custom viewer

  ui_addons,            // * work with registered add-ons

  ui_execute_ui_requests,
                        // * Execute a variable number of UI requests.
                        // (the UI requests will be dispatched in the context of the main thread)
                        // Parameters: ui_request_t *req (the first request)
                        //             ... (variable arg ui_request_t *)
                        //             NULL (to terminate the var arg request list)

  ui_execute_ui_requests_list,
                        // * Execute a list of UI requests
                        // (the UI requests will be dispatched in the context of the main thread)
                        // Parameters: ui_requests_t *

  ui_register_timer,    // * Register a timer
                        // Timer functions are thread-safe and the callback is executed
                        // in the context of the main thread.
                        // Parameters: int interval (in milliseconds)
                        //             int (idaapi *callback)(void *ud)
                        //                 (the callback can return -1 to unregister the timer;
                        //                  any other value >= 0 defines the new interval for the timer)
                        //             void *ud
                        // Returns: qtimer_t (use this handle to unregister the timer)

  ui_unregister_timer,  // * Unregister a timer
                        // Parameters: qtimer_t t (handle to a registered timer)

  ui_take_database_snapshot,
                        // * Take a database snapshot
                        // Parameters: snapshot_t *ss - in/out parameter.
                        //                            - in: description, flags
                        //                            - out: filename, id
                        //             qstring *err_msg - optional error msg buffer
                        // Returns: bool

  ui_restore_database_snapshot,
                        // * Restore a database snapshot
                        // Parameters: const snapshot_t *ss - snapshot instance (see build_snapshot_tree())
                        //             ss_restore_cb_t cb - A callback that will be triggered with a NULL string
                        //             on success and an actual error message on failure.
                        //             void *ud - user data passed to be passed to the callback
                        // Note: This call is asynchronous. When it is completed, the callback will be triggered.
                        // Returns: boolean. False if restoration could not be started (snapshot file was not found).
                        //          If the returned value is True then check if the operation succeeded from the callback.

  ui_set_code_viewer_line_handlers,
                        // * Set handlers for code viewer line events
                        // Parameters: TCustomControl *code_viewer
                        //             code_viewer_lines_click_t *click_handler
                        //             code_viewer_lines_click_t *popup_handler
                        //             code_viewer_lines_click_t *dblclick_handler
                        //             code_viewer_lines_icon_t *drawicon_handler
                        //             code_viewer_lines_linenum_t *linenum_handler
                        //             Any of these handlers may be NULL
                        // Returns: nothing

  ui_refresh_custom_code_viewer,
                        // * Refresh custom code viewer
                        // Parameters: TCustomControl *code_viewer
                        // Returns: nothing

  ui_new_source_viewer, // * Create new source viewer
                        // Parameters: TWinControl *parent
                        //             TCustomControl *custview
                        //             const char *path
                        //             strvec_t *lines
                        //             int lnnum
                        //             int colnum
                        //             itn flags (SVF_... bits)
                        // Returns: source_view_t *

#define SVF_COPY_LINES  0x0000   // keep a local copy of '*lines'
#define SVF_LINES_BYPTR 0x0001   // remeber the 'lines' ptr. do not make a copy of '*lines'

  ui_get_tab_size,      // * Get the size of a tab in spaces
                        // Parameters: const char *path
                        //             (The path of the source view for which the tab size is requested.
                        //              If NULL, the default size is returned.)
                        // Returns: int

  ui_set_menu_item_icon,// * Set the icon of a menu item
                        // Parameters: const char *item_name
                        //             int icon_id
                        // Returns: bool

  ui_repaint_qwidget,   // * Repaint the widget immediately
                        // Parameters: QWidget *widget
                        // Returns: nothing

  ui_enable_menu_item,  // * Enable or disable a menu item
                        // Parameters: const char *item_name
                        //             bool enable
                        // Returns: bool

  ui_custom_viewer_set_userdata,
                        // * Change place_t user data for a custom view
                        // Parameters: TCustomControl *custom_viewer
                        //             void *user_data
                        // Returns: old user_data

  ui_new_ea_viewer,     // * create new ea viewer based on place_t (gui)
                        // Parameters:
                        //      const char *title
                        //      TWinControl *parent
                        //      const place_t *minplace
                        //      const place_t *maxplace
                        //      const place_t *curplace
                        //      int y
                        //      void *ud
                        //      int flags
                        //      eaviewer_cb_t *fillloc
                        //      eaviewer_cb_t *jumploc
                        //      location_t **loc
                        // returns: TCustomControl *
                        // see also: ui_new_custom_viewer

  ui_jumpto,            // * Jump to the specified address
                        // Parameters:
                        //      ea_t ea
                        //      int operand_num (-1: don't change x coord)
                        //      int uijmp_flags
                        // Returns: bool success

  ui_choose_info,       // * Invoke the chooser with a choose_info_t structure
                        // Parameters:
                        //      chooser_info_t *chi
                        // Returns: see the choose function

  ui_last,              // The last notification code

  // debugger callgates. should not be used directly, see dbg.hpp for details

  ui_dbg_begin = 1000,
  ui_dbg_run_requests = ui_dbg_begin,
  ui_dbg_get_running_request,
  ui_dbg_get_running_notification,
  ui_dbg_clear_requests_queue,
  ui_dbg_get_process_state,
  ui_dbg_start_process,
  ui_dbg_request_start_process,
  ui_dbg_suspend_process,
  ui_dbg_request_suspend_process,
  ui_dbg_continue_process,
  ui_dbg_request_continue_process,
  ui_dbg_exit_process,
  ui_dbg_request_exit_process,
  ui_dbg_get_thread_qty,
  ui_dbg_getn_thread,
  ui_dbg_select_thread,
  ui_dbg_request_select_thread,
  ui_dbg_step_into,
  ui_dbg_request_step_into,
  ui_dbg_step_over,
  ui_dbg_request_step_over,
  ui_dbg_run_to,
  ui_dbg_request_run_to,
  ui_dbg_step_until_ret,
  ui_dbg_request_step_until_ret,
  ui_dbg_get_oldreg_val,                // obsolete
  ui_dbg_set_oldreg_val,                // obsolete
  ui_dbg_request_set_oldreg_val,        // obsolete
  ui_dbg_get_bpt_qty,
  ui_dbg_getn_oldbpt,                   // obsolete
  ui_dbg_get_oldbpt,                    // obsolete
  ui_dbg_add_oldbpt,                    // obsolete
  ui_dbg_request_add_oldbpt,            // obsolete
  ui_dbg_del_oldbpt,                    // obsolete
  ui_dbg_request_del_oldbpt,            // obsolete
  ui_dbg_update_oldbpt,                 // obsolete
  ui_dbg_enable_oldbpt,                 // obsolete
  ui_dbg_request_enable_oldbpt,         // obsolete
  ui_dbg_set_trace_size,
  ui_dbg_clear_trace,
  ui_dbg_request_clear_trace,
  ui_dbg_is_step_trace_enabled,
  ui_dbg_enable_step_trace,
  ui_dbg_request_enable_step_trace,
  ui_dbg_get_step_trace_options,
  ui_dbg_set_step_trace_options,
  ui_dbg_request_set_step_trace_options,
  ui_dbg_is_insn_trace_enabled,
  ui_dbg_enable_insn_trace,
  ui_dbg_request_enable_insn_trace,
  ui_dbg_get_insn_trace_options,
  ui_dbg_set_insn_trace_options,
  ui_dbg_request_set_insn_trace_options,
  ui_dbg_is_func_trace_enabled,
  ui_dbg_enable_func_trace,
  ui_dbg_request_enable_func_trace,
  ui_dbg_get_func_trace_options,
  ui_dbg_set_func_trace_options,
  ui_dbg_request_set_func_trace_options,
  ui_dbg_get_tev_qty,
  ui_dbg_get_tev_info,
  ui_dbg_get_insn_tev_oldreg_val,       // obsolete
  ui_dbg_get_insn_tev_oldreg_result,    // obsolete
  ui_dbg_get_call_tev_callee,
  ui_dbg_get_ret_tev_return,
  ui_dbg_get_bpt_tev_ea,
  ui_dbg_get_reg_value_type,
  ui_dbg_get_process_qty,
  ui_dbg_get_process_info,
  ui_dbg_attach_process,
  ui_dbg_request_attach_process,
  ui_dbg_detach_process,
  ui_dbg_request_detach_process,
  ui_dbg_get_first_module,
  ui_dbg_get_next_module,
  ui_dbg_bring_to_front,
  ui_dbg_get_current_thread,
  ui_dbg_wait_for_next_event,
  ui_dbg_get_debug_event,
  ui_dbg_set_debugger_options,
  ui_dbg_set_remote_debugger,
  ui_dbg_load_debugger,
  ui_dbg_retrieve_exceptions,
  ui_dbg_store_exceptions,
  ui_dbg_define_exception,
  ui_dbg_suspend_thread,
  ui_dbg_request_suspend_thread,
  ui_dbg_resume_thread,
  ui_dbg_request_resume_thread,
  ui_dbg_get_process_options,
  ui_dbg_check_bpt,
  ui_dbg_set_process_state,
  ui_dbg_get_manual_regions,
  ui_dbg_set_manual_regions,
  ui_dbg_enable_manual_regions,
  ui_dbg_set_process_options,
  ui_dbg_is_busy,
  ui_dbg_hide_all_bpts,
  ui_dbg_edit_manual_regions,
  ui_dbg_get_reg_val,
  ui_dbg_set_reg_val,
  ui_dbg_request_set_reg_val,
  ui_dbg_get_insn_tev_reg_val,
  ui_dbg_get_insn_tev_reg_result,
  ui_dbg_register_provider,
  ui_dbg_unregister_provider,
  ui_dbg_handle_debug_event,
  ui_dbg_add_vmod,
  ui_dbg_del_vmod,
  ui_dbg_compare_bpt_locs,
  ui_dbg_save_bpts,
  ui_dbg_old_getn_bpt,              // obsolete
  ui_dbg_old_get_bpt,               // obsolete
  ui_dbg_old_update_bpt,            // obsolete
  ui_dbg_set_bptloc_string,
  ui_dbg_get_bptloc_string,
  ui_dbg_internal_appcall,
  ui_dbg_internal_cleanup_appcall,
  ui_dbg_internal_get_sreg_base,
  ui_dbg_internal_ioctl,
  ui_dbg_read_memory,
  ui_dbg_write_memory,
  ui_dbg_read_registers,
  ui_dbg_write_register,
  ui_dbg_get_memory_info,
  ui_dbg_get_event_cond,
  ui_dbg_set_event_cond,
  ui_dbg_old_find_bpt,              // obsolete
  ui_dbg_enable_bpt,
  ui_dbg_request_enable_bpt,
  ui_dbg_old_add_bpt,               // obsolete
  ui_dbg_old_request_add_bpt,       // obsolete
  ui_dbg_del_bpt,
  ui_dbg_request_del_bpt,
  ui_dbg_map_source_path,
  ui_dbg_map_source_file_path,
  ui_dbg_modify_source_paths,
  ui_dbg_is_bblk_trace_enabled,
  ui_dbg_enable_bblk_trace,
  ui_dbg_request_enable_bblk_trace,
  ui_dbg_get_bblk_trace_options,
  ui_dbg_set_bblk_trace_options,
  ui_dbg_request_set_bblk_trace_options,
  // trace management
  ui_dbg_load_trace_file,
  ui_dbg_save_trace_file,
  ui_dbg_is_valid_trace_file,
  ui_dbg_set_trace_file_desc,
  ui_dbg_get_trace_file_desc,
  ui_dbg_choose_trace_file,
  ui_dbg_diff_trace_file,
  ui_dbg_graph_trace,
  ui_dbg_get_tev_memory_info,
  ui_dbg_get_tev_event,
  ui_dbg_get_insn_tev_reg_mem,
  // breakpoint management (new codes were introduced in v6.3)
  ui_dbg_getn_bpt,
  ui_dbg_get_bpt,
  ui_dbg_find_bpt,
  ui_dbg_add_bpt,
  ui_dbg_request_add_bpt,
  ui_dbg_update_bpt,
  ui_dbg_for_all_bpts,

  ui_dbg_end
};


//--------------------------------------------------------------------------
//
//      The user interface must call init_kernel before calling
//      any kernel functions. It should pass a function named
//      CALLUI to init_kernel. The CALLUI function is a dispatcher
//      The user interface should have it.
//

idaman void ida_export init_kernel(
                  callui_t (idaapi*_callui)(ui_notification_t what,...),
                  int argc,
                  char *argv[]);

// Pointer to the user-interface dispatcher function
// This pointer is in the kernel
idaman callui_t ida_export_data (idaapi*callui)(ui_notification_t what,...);



// After calling init_kernel the ui must call init_database()
// This function will open the database specified in the command line
// If the database did not exist, a new database will be created and
// the input file will be loaded
// Returns: 0-ok, otherwise an exit code

idaman int ida_export init_database(int argc, const char *const *argv, int *newfile);


// The kernel termination function
// This function should be called to close the database

idaman void ida_export term_database(void);


// The kernel termination function
// This function will be automatically called IDA exits
// There is no need to call it from plugins

idaman void ida_export term_kernel(void);


#define KERNEL_VERSION_MAGIC1 0x23967034
#define KERNEL_VERSION_MAGIC2 0xAAEE67BE

// Get IDA kernel version, a string like "5.1"
// For old versions which do not support this call, returns false
inline bool get_kernel_version(char *buf, size_t bufsize)
{
  return callui(ui_clearbreak, KERNEL_VERSION_MAGIC1, KERNEL_VERSION_MAGIC2, buf, bufsize).cnd;
}

// Display an error message and die. See also: error(), warning(), info(), msg()

idaman NORETURN AS_PRINTF(1, 0) void ida_export verror(const char *format, va_list va);


// Display hex dump in the messages window

idaman AS_PRINTF(3, 0) void ida_export vshow_hex(
        const void *dataptr,
        size_t len,
        const char *format,
        va_list va);


// Display hex dump of a file in the messages window

idaman AS_PRINTF(4, 0) void ida_export vshow_hex_file(
        linput_t *li,
        int32 pos,
        size_t count,
        const char *format,
        va_list va);


#endif // SWIG
#ifndef SWIG
//--------------------------------------------------------------------------
//      K E R N E L   S E R V I C E S   F O R   U I
//--------------------------------------------------------------------------
//
// Generating text for the disassembly, enum, and structure windows.
//
// place_t is a class that denotes a displayed line.
// (location_t would be a better name but it is too late to rename it now)
//
// An object may be displayed on one or more lines. All lines of an object are
// generated at once and kept in a linearray_t class.
//
// place_t is an abstract class, another class must be derived from it.
// Currently the following classes are used in IDA:
//
//              idaplace_t      - disassembly view
//              enumplace_t     - enum view
//              structplace_t   - structure view
//
// Example (idaplace_t):
//
//  004015AC
//  004015AC loc_4015AC:                             ; CODE XREF: sub_4014B8+C5j
//  004015AC                 xor     eax, eax
//
// The first line is denoted by idaplace_t with ea=4015AC, lnnum=0
// The second line is denoted by idaplace_t with ea=4015AC, lnnum=1
// The third line is denoted by idaplace_t with ea=4015AC, lnnum=2

// NB: the place_t class may change in the future, do not rely on it

class place_t                   // Class to denote a displayed line
{                               // (the line itself is stored elsewhere)
public:
  short lnnum;                  // Number of line within the current object
  place_t(void) {}
  place_t(short ln) : lnnum(ln) {}
  DEFINE_MEMORY_ALLOCATION_FUNCS()

  // Generate a short description of the location.
  //    ud - pointer to user-defined context data. Is supplied by linearray_t
  //    buf - the output buffer
  //    bufsize - size of the output buffer
  // The short description is used on the status bar

  virtual void idaapi print(void *ud,char *buf, size_t bufsize) const  = 0;


  // Map the location to a number
  //    ud - pointer to user-defined context data. Is supplied by linearray_t
  // This mapping is used to draw the vertical scrollbar.

  virtual uval_t idaapi touval(void *ud) const                         = 0;


  // Clone the location. A copy of the current location will be made in
  // the dynamic memory and a pointer to it will be returned.

  virtual place_t *idaapi clone(void) const                            = 0;


  // Copy the specified location object to the current object

  virtual void idaapi copyfrom(const place_t *from)                    = 0;


  // Map a number to a location
  // When the user clicks on the scrollbar and drags it, we need to determine
  // the location corresponding to the new scrollbar position. This function
  // is used to determine it. It builds a location object for the specified 'x'
  // and returns a pointer to it.
  //    ud - pointer to user-defined context data. Is supplied by linearray_t
  //    x - number to map
  //    lnnum - line number to initialize 'lnnum'
  // The returned object is a static object, no need to destroy it.

  virtual place_t *idaapi makeplace(void *ud, uval_t x, short lnnum) const= 0;


  // Compare two locations except line numbers (lnnum)
  // This function is used to organize loops.
  // For example, if the user has selected an area, its boundaries are remembered
  // as location objects. Any operation within the selection will have the following
  // look: for ( loc=starting_location; loc < ending_location; loc.next() )
  // In this loop, the comparison function is used.
  // Returns: -1: if the current location is less than 't2'
  //           0: if the current location is equal to than 't2'
  //           1: if the current location is greater than 't2'

  virtual int idaapi compare(const place_t *t2) const                  = 0;


  // Adjust the current location to point to a displayable object
  // This function validates the location and makes sure that it points to
  // an existing object. For example, if the location points to the middle
  // of an instruction, it will be adjusted to point to the beginning of the
  // instruction.
  //    ud - pointer to user-defined context data. Is supplied by linearray_t

  virtual void idaapi adjust(void *ud)                                 = 0;


  // Move to the previous displayable location
  //    ud - pointer to user-defined context data. Is supplied by linearray_t
  // Returns: success

  virtual bool idaapi prev(void *ud)                                   = 0;


  // Move to the next displayable location
  //    ud - pointer to user-defined context data. Is supplied by linearray_t
  // Returns: success

  virtual bool idaapi next(void *ud)                                   = 0;


  // Are at the first displayable object?
  //    ud - pointer to user-defined context data. Is supplied by linearray_t
  // Returns: true-the current location points to the first displayable object

  virtual bool idaapi beginning(void *ud) const                        = 0;


  // Are at the last displayable object?
  //    ud - pointer to user-defined context data. Is supplied by linearray_t
  // Returns: true-the current location points to the last displayable object

  virtual bool idaapi ending(void *ud) const                           = 0;


  // Generate text lines for the current location
  //    ud - pointer to user-defined context data. Is supplied by linearray_t
  //  lines- array of pointers to output lines. the pointers will be overwritten
  //         by lines that are allocated using qstrdup. the caller must qfree them.
  //  maxsize - maximal number of lines to generate
  // default_lnnum - pointer to the cell that will contain the number of
  //                 the most 'interesting' generated line
  // pfx_color - pointer to the cell that will contain the line prefix color
  // bg_color  - pointer to the cell that will contain the background colo
  // Returns: number of generated lines

  virtual int idaapi generate(
        void *ud,
        char *lines[],
        int maxsize,
        int *default_lnnum,
        color_t *pfx_color,
        bgcolor_t *bgcolor) const                = 0;
};

// compare places and their lnnums
idaman int ida_export l_compare(const place_t *t1, const place_t *t2);

//--------------------------------------------------------------------------
#define define_place_exported_functions(classname)                                  \
class classname;                                                                    \
idaman void     ida_export classname ## __print(const classname *,void*,char*, size_t);    \
idaman uval_t   ida_export classname ## __touval(const classname *,void*);                 \
idaman place_t *ida_export classname ## __clone(const classname *);                        \
idaman void     ida_export classname ## __copyfrom(classname *,const place_t*);            \
idaman place_t *ida_export classname ## __makeplace(const classname *,void*,uval_t,short); \
idaman int      ida_export classname ## __compare(const classname *,const place_t*);       \
idaman void     ida_export classname ## __adjust(classname *,void*);                       \
idaman bool     ida_export classname ## __prev(classname *,void*);                         \
idaman bool     ida_export classname ## __next(classname *,void*);                         \
idaman bool     ida_export classname ## __beginning(const classname *,void*);              \
idaman bool     ida_export classname ## __ending(const classname *,void*);                 \
idaman int      ida_export classname ## __generate(const classname *,void*,char**,int,int*,color_t*,bgcolor_t*);

#define define_place_virtual_functions(class)                           \
  void idaapi print(void *ud,char *buf, size_t bufsize) const           \
        {        class ## __print(this,ud,buf,bufsize); }               \
  uval_t idaapi touval(void *ud) const                                  \
        { return class ## __touval(this,ud); }                          \
  place_t *idaapi clone(void) const                                     \
        { return class ## __clone(this); }                              \
  void idaapi copyfrom(const place_t *from)                             \
        {        class ## __copyfrom(this,from); }                      \
  place_t *idaapi makeplace(void *ud,uval_t x,short _lnnum) const       \
        { return class ## __makeplace(this,ud,x,_lnnum); }              \
  int  idaapi compare(const place_t *t2) const                          \
        { return class ## __compare(this,t2); }                         \
  void idaapi adjust(void *ud)                                          \
        {        class ## __adjust(this,ud); }                          \
  bool idaapi prev(void *ud)                                            \
        { return class ## __prev(this,ud); }                            \
  bool idaapi next(void *ud)                                            \
        { return class ## __next(this,ud); }                            \
  bool idaapi beginning(void *ud) const                                 \
        { return class ## __beginning(this,ud); }                       \
  bool idaapi ending (void *ud) const                                   \
        { return class ## __ending(this,ud); }                          \
  int idaapi generate (void *ud,char *lines[],int maxsize,int *_lnnum,  \
                       color_t *pfx_color, bgcolor_t *bg_color) const   \
        { return class ## __generate(this,ud,lines,maxsize,_lnnum,      \
                                                pfx_color, bg_color); }

//--------------------------------------------------------------------------
//
//  IDA custom viewer sample user: simpleline interface
//
//  It is enough to create an object of strvec_t class, put all lines
//  into it and create a custom ida viewer (new_custom_viewer).
//
//    strvec_t sv;
//    ... fill it with lines...
//    simpleline_place_t s1;
//    simpleline_place_t s2(sv.size()-1);
//    cv = (TCustomControl *)callui(ui_new_custom_viewer,
//                           "My title",
//                           parent_form,
//                           &s1,
//                           &s2,
//                           &s1,
//                           0,
//                           &sv).vptr;
//
//  This will produce a nice colored text view
//

struct simpleline_t
{
  qstring line;
  color_t color;
  bgcolor_t bgcolor;
  simpleline_t(void) : color(1), bgcolor(DEFCOLOR) {} // default colors
  simpleline_t(color_t c, const char *str) : line(str), color(c), bgcolor(DEFCOLOR) {}
  simpleline_t(const char *str) : line(str), color(1), bgcolor(DEFCOLOR) {}
  simpleline_t(const qstring &str) : line(str), color(1), bgcolor(DEFCOLOR) {}
  DEFINE_MEMORY_ALLOCATION_FUNCS()
};
typedef qvector<simpleline_t> strvec_t;

define_place_exported_functions(simpleline_place_t)
class simpleline_place_t : public place_t
{
public:
  size_t n; // line number in strvec_t
  simpleline_place_t(void) { n = 0; lnnum = 0; }
  simpleline_place_t(int _n) { n = _n; lnnum = 0; }
  define_place_virtual_functions(simpleline_place_t);
};

//--------------------------------------------------------------------------
// user defined data for linearray_t: use ptr to result of calc_default_idaplace_flags()
define_place_exported_functions(idaplace_t)
class idaplace_t : public place_t {             // a place pointer
public:
  ea_t ea;
  idaplace_t(void) {}
  idaplace_t(ea_t x,short ln) : place_t(ln), ea(x) {}
  define_place_virtual_functions(idaplace_t);
};

//--------------------------------------------------------------------------
// user defined data for linearray_t: NULL
define_place_exported_functions(enumplace_t)
class enumplace_t : public place_t {            // a place pointer
public:
  size_t idx;
  bmask_t bmask;
  uval_t value;
  uchar serial;
  enumplace_t(void) {}
  enumplace_t(size_t i, bmask_t m, uval_t v, uchar s, short ln)
    : place_t(ln), idx(i), bmask(m), value(v), serial(s) {}
  define_place_virtual_functions(enumplace_t);
};

//--------------------------------------------------------------------------
// user defined data for linearray_t: ea_t *pea
// if pea != NULL then the function stack frame is displayed, *pea == function start
// else                normal structure list is displayed
define_place_exported_functions(structplace_t)
class structplace_t : public place_t {          // a place pointer
public:
  uval_t idx;
  uval_t offset;
  structplace_t(void) {}
  structplace_t(uval_t i, uval_t o, short ln) : place_t(ln), idx(i), offset(o) {}
  define_place_virtual_functions(structplace_t);
};

struct saved_structplace_t                      // the saved position in the database
{
  ushort lnnum;
  ushort x,y;
  uval_t idx;
  uval_t offset;
};

//----------------------------------------------------------------------
class twinpos_t                 // a pointer in a text window
{
public:
  place_t *at;
  int x;
  twinpos_t(void)                 {}
  twinpos_t(place_t *t)           { at=t; }
  twinpos_t(place_t *t,int x0)    { at=t; x=x0; }
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  bool operator != (const twinpos_t &r)
  {
    if ( x != r.x ) return true;
    if ( (at == NULL) != (r.at == NULL) ) return true;
    if ( at != NULL && (at->compare(r.at) != 0 || at->lnnum != r.at->lnnum) ) return true;
    return false;
  }
  bool operator == (const twinpos_t &r) { return !(*this != r); }
};

class twinline_t                // a line in a text window
{
public:
  place_t *at;
  char *line;
  color_t prefix_color;
  bgcolor_t bg_color;
  bool is_default;              // is the default line of the current location?
  twinline_t(void) {}
  twinline_t(place_t *t,char *l,color_t pc, bgcolor_t bc)
  {
    at           = t;
    line         = l;
    prefix_color = pc;
    bg_color     = bc;
    is_default   = false;
  }
  DEFINE_MEMORY_ALLOCATION_FUNCS()
};

typedef qvector<twinline_t> text_t;
typedef qvector<text_t> texts_t;

//----------------------------------------------------------------------
// Internal class, not documented
idaman int ida_export_data lnar_size; // Maximum number of lines for one item (one instruction or data)


#define DECLARE_LINEARRAY_HELPERS(decl) \
decl void  ida_export linearray_t_ctr      (linearray_t *, void *ud); \
decl void  ida_export linearray_t_dtr      (linearray_t *); \
decl void  ida_export linearray_t_set_place(linearray_t *, const place_t *new_at); \
decl bool  ida_export linearray_t_beginning(const linearray_t *); \
decl bool  ida_export linearray_t_ending   (const linearray_t *); \
decl char *ida_export linearray_t_down     (linearray_t *); \
decl char *ida_export linearray_t_up       (linearray_t *);

class linearray_t;
DECLARE_LINEARRAY_HELPERS(idaman)

class linearray_t
{
  DECLARE_LINEARRAY_HELPERS(friend)
  void  _set_place(const place_t *new_at);
  char *_down     (void);
  char *_up       (void);

  char **lines;                 // [lnar_size]; we own all these lines
  place_t *at;
  void *ud;                     // user defined data (UD)
                                // its meaning depends on the place_t used
  int linecnt;                  // number of lines
  color_t prefix_color;         // prefix color
  bgcolor_t bg_color;           // background color
  char *extra;                  // the last line of the previous location after moving down
  int dlnnum;                   // default line number (if unknown, -1)

  void  getlines        (void);
  void  cleanup         (void);

public:

  linearray_t(void *_ud)                     { linearray_t_ctr(this, _ud); }
  ~linearray_t(void)                         { linearray_t_dtr(this); }
  DEFINE_MEMORY_ALLOCATION_FUNCS()

// this function must be called before calling any other member functions.
// it positions the array. linearray_t doesn't own place_t structures.
// the caller must take care of place_t objects.
  void set_place(const place_t *new_at)      { linearray_t_set_place(this, new_at); }

// return the current place
// if called before down(), then returns place of line which will be returned by down()
// if called after up(), then returns place if line returned by up()
  place_t* get_place    (void) const         { return at; }

// get current color
// (the same behaviour as with get_place: good before down() and after up())
  bgcolor_t get_bg_color(void) const         { return bg_color; }
  bgcolor_t get_pfx_color(void) const        { return prefix_color; }

// get default line number
// (the same behaviour as with get_place: good before down() and after up())
  int   get_dlnnum      (void) const         { return dlnnum; }

// get number of lines for the current place
// (the same behaviour as with get_place: good before down() and after up())
  int   get_linecnt     (void) const         { return linecnt; }

// return pointer to user data
  void *userdata        (void) const         { return ud; }
// change the user data
  void set_userdata     (void *userd)        { ud = userd; }

// 1 if we are at the beginning
  bool beginning(void) const                 { return linearray_t_beginning(this); }

// 1 if we are at the end
  bool ending(void) const                    { return linearray_t_ending(this); }

// get a line from up/down directions
  char *down(void)         // place is ok BEFORE
        { return linearray_t_down(this); }
  char *up(void)           // place is ok AFTER
        { return linearray_t_up(this); }

};
#endif // SWIG


// Bitmask of builtin window types to be refreshed:
idaman int ida_export_data dirty_infos;

// Request a refresh of a builtin window:
// mask is a combination of IWID_... constants
inline void request_refresh(int mask)
{
  dirty_infos |= mask;
}

#define BWN_EXPORTS  0 // exports
#define BWN_IMPORTS  1 // imports
#define BWN_NAMES    2 // names
#define BWN_FUNCS    3 // functions
#define BWN_STRINGS  4 // strings
#define BWN_SEGS     5 // segments
#define BWN_SEGREGS  6 // segment registers
#define BWN_SELS     7 // selectors
#define BWN_SIGNS    8 // signatures
#define BWN_TILS     9 // type libraries
#define BWN_LOCTYPS 10 // local types
#define BWN_CALLS   11 // function calls
#define BWN_PROBS   12 // problems
#define BWN_BPTS    13 // breakpoints
#define BWN_THREADS 14 // threads
#define BWN_MODULES 15 // modules
#define BWN_TRACE   16 // trace view
#define BWN_STACK   17 // stack
#define BWN_XREFS   18 // xrefs
#define BWN_SEARCHS 19 // search results
#define BWN_FRAME   25 // function frame
#define BWN_NAVBAND 26 // navigation band
#define BWN_ENUMS   27 // enumerations
#define BWN_STRUCTS 28 // structures
#define BWN_DISASMS 29 // disassembly views
#define BWN_DUMPS   30 // hex dumps
#define BWN_NOTEPAD 31 // notepad

#define IWID_EXPORTS  (1 << BWN_EXPORTS) //  0 exports
#define IWID_IMPORTS  (1 << BWN_IMPORTS) //  1 imports
#define IWID_NAMES    (1 << BWN_NAMES  ) //  2 names
#define IWID_FUNCS    (1 << BWN_FUNCS  ) //  3 functions
#define IWID_STRINGS  (1 << BWN_STRINGS) //  4 strings
#define IWID_SEGS     (1 << BWN_SEGS   ) //  5 segments
#define IWID_SEGREGS  (1 << BWN_SEGREGS) //  6 segment registers
#define IWID_SELS     (1 << BWN_SELS   ) //  7 selectors
#define IWID_SIGNS    (1 << BWN_SIGNS  ) //  8 signatures
#define IWID_TILS     (1 << BWN_TILS   ) //  9 type libraries
#define IWID_LOCTYPS  (1 << BWN_LOCTYPS) // 10 local types
#define IWID_CALLS    (1 << BWN_CALLS  ) // 11 function calls
#define IWID_PROBS    (1 << BWN_PROBS  ) // 12 problems
#define IWID_BPTS     (1 << BWN_BPTS   ) // 13 breakpoints
#define IWID_THREADS  (1 << BWN_THREADS) // 14 threads
#define IWID_MODULES  (1 << BWN_MODULES) // 15 modules
#define IWID_TRACE    (1 << BWN_TRACE  ) // 16 trace view
#define IWID_STACK    (1 << BWN_STACK  ) // 17 call stack
#define IWID_XREFS    (1 << BWN_XREFS  ) // 18 xrefs
#define IWID_SEARCHS  (1 << BWN_SEARCHS) // 19 search results
#define IWID_FRAME    (1 << BWN_FRAME  ) // 25 function frame
#define IWID_NAVBAND  (1 << BWN_NAVBAND) // 26 navigation band
#define IWID_ENUMS    (1 << BWN_ENUMS  ) // 27 enumerations
#define IWID_STRUCTS  (1 << BWN_STRUCTS) // 28 structures
#define IWID_DISASMS  (1 << BWN_DISASMS) // 29 disassembly views
#define IWID_DUMPS    (1 << BWN_DUMPS  ) // 30 hex dumps
#define IWID_NOTEPAD  (1 << BWN_NOTEPAD) // 31 notepad
#define IWID_IDAMEMOS (IWID_DISASMS|IWID_DUMPS)

#define IWID_ALL     0xFFFFFFFF

#ifndef SWIG
//---------------------------------------------------------------------------
//      D E B U G G I N G   F U N C T I O N S
//---------------------------------------------------------------------------

idaman uint32 ida_export_data debug;

#define IDA_DEBUG_DREFS         0x00000001      // drefs
#define IDA_DEBUG_OFFSET        0x00000002      // offsets
#define IDA_DEBUG_FLIRT         0x00000004      // flirt
#define IDA_DEBUG_IDP           0x00000008      // idp module
#define IDA_DEBUG_LDR           0x00000010      // ldr module
#define IDA_DEBUG_PLUGIN        0x00000020      // plugin module
#define IDA_DEBUG_IDS           0x00000040      // ids files
#define IDA_DEBUG_CONFIG        0x00000080      // config file
#define IDA_DEBUG_CHECKMEM      0x00000100      // check heap consistency
#define IDA_DEBUG_CHECKARG      0x00000200      // checkarg
#define IDA_DEBUG_DEMANGLE      0x00000400      // demangler
#define IDA_DEBUG_QUEUE         0x00000800      // queue
#define IDA_DEBUG_ROLLBACK      0x00001000      // rollback
#define IDA_DEBUG_ALREADY       0x00002000      // already data or code
#define IDA_DEBUG_TIL           0x00004000      // type system
#define IDA_DEBUG_NOTIFY        0x00008000      // show all notifications
#define IDA_DEBUG_DEBUGGER      0x00010000      // debugger
#define IDA_DEBUG_APPCALL       0x00020000      // appcall
#define IDA_DEBUG_SRCDBG        0x00040000      // source debugging
#define IDA_DEBUG_ALWAYS        0xFFFFFFFF      // everything

// to display debug messages use deb() function:

AS_PRINTF(2, 3) inline int deb(int ida_debug_bits, const char *format, ...)
{
  int nbytes = 0;
  if ( debug & ida_debug_bits )
  {
    va_list va;
    va_start(va, format);
    nbytes = callui(ui_msg, format, va).i;
    va_end(va);
  }
  return nbytes;
}

// print the tick count from the last call to debug_time()
// the first time prints -1
#ifdef __NT__
#define debug_time()  ida_debug_time(__FILE__, __LINE__)
void ida_debug_time(const char *file, int line);
#else
#define debug_time()
#endif


// Checking heap is not available anymore.
#define checkmem() do {} while (0) // ida_checkmem(__FILE__, __LINE__)
idaman void ida_export ida_checkmem(const char *file, int line);

AS_PRINTF(3, 4) inline void show_hex(
        const void *dataptr,
        size_t len,
        const char *format,
        ...)
{
  va_list va;
  va_start(va,format);
  vshow_hex(dataptr, len, format, va);
  va_end(va);
}

AS_PRINTF(4, 5) inline void show_hex_file(
        linput_t *li,
        int32 pos,
        size_t count,
        const char *format,
        ...)
{
  va_list va;
  va_start(va,format);
  vshow_hex_file(li, pos, count, format, va);
  va_end(va);
}
#endif // SWIG

//-------------------------------------------------------------------------
//      U I   S E R V I C E  F U N C T I O N S
//-------------------------------------------------------------------------

#ifndef SWIG
// Common function prototypes
// These functions are inlined for the kernel
// They are not inlined for the user-interfaces

AS_PRINTF(5, 0) int askbuttons_cv(
        const char *Yes,
        const char *No,
        const char *Cancel,
        int deflt,
        const char *format,
        va_list va);
AS_PRINTF(3, 0) char *vaskstr(
        int hist,
        const char *defval,
        const char *format,
        va_list va);
AS_PRINTF(4, 0) char *vasktext(
        size_t size,
        char *answer,
        const char *defval,
        const char *format,
        va_list va);
AS_PRINTF(1, 0) int vmsg(const char *format, va_list va);
AS_PRINTF(1, 0) void vwarning(const char *format, va_list va);
AS_PRINTF(1, 0) void vinfo(const char *format, va_list va);
AS_PRINTF(1, 0) NORETURN void vnomem(const char *format, va_list va);


// generic chooser flags
#define CH_MODAL 0x01 // Modal chooser
#define CH_MULTI 0x02 // The chooser will allow multi-selection (only for GUI choosers).
                      // If multi-selection is enabled, a multi-selection 'del' callback
                      // will be called with:
                      //   uint32 = START_SEL   before calling the first selected item
                      //   uint32 =  1..n       for each selected item
                      //   uint32 = END_SEL     after calling the last  selected item
                      // If the callback returns 'false', further processing
                      //   of selected items is cancelled.
#define CH_MULTI_EDIT 0x04
                      // The 'edit' callback will be called for all selected items
                      // using the START_SEL/END_SEL protocol.
                      // This bit implies CH_MULTI (valid only for gui)
#define CH_NOBTNS 0x08 // do not display ok/cancel/help/search buttons
                      // meaningful only for gui modal windows because non-modal
                      // windows do not have any buttons anyway. text mode does
                      // not have them neither
#define CH_ATTRS 0x10 // generate ui_get_chooser_item_attrs (gui only)
#define CH_NOIDB 0x20 // use the chooser even without an open database, same as x0=-2 (see below)
#define CH_BUILTIN_MASK 0xF80000
                      // Mask for builtin chooser numbers. Plugins should not use them
#define CH_BUILTIN(id) ((id+1) << 19)
#define CH_GETCN(flags) (((flags & CH_BUILTIN_MASK) >> 19) - 1)

// column flags (are specified in the widths array)
#define CHCOL_PLAIN     0x00000000  // plain string
#define CHCOL_PATH      0x00010000  // file path
#define CHCOL_HEX       0x00020000  // hexadecimal number
#define CHCOL_DEC       0x00030000  // decimal number
#define CHCOL_FORMAT    0x00070000  // column format mask

// chooser multi-selection callback special events (passed as indexes to callbacks)
typedef int32 chooser_event_t;
const chooser_event_t
  EMPTY_SEL =  0, // no item was selected
  START_SEL = -1, // before calling the first selected item
  END_SEL   = -2; // after calling the last selected item
// chooser multi-selection callback convenience macros
#define IS_EMPTY_SEL(n)     ((chooser_event_t)(size_t)n == EMPTY_SEL)
#define IS_START_SEL(n)     ((chooser_event_t)(size_t)n == START_SEL)
#define IS_END_SEL(n)       ((chooser_event_t)(size_t)n == END_SEL)
#define IS_CHOOSER_EVENT(n) (IS_EMPTY_SEL(n) \
                          || IS_START_SEL(n) \
                          || IS_END_SEL(n))
#define IS_SEL(n)           (!IS_CHOOSER_EVENT(n))

// prefixes to be used in the chooser title:
#define CHOOSER_NOMAINMENU  "NOMAINMENU\n"   // do not display main menu
#define CHOOSER_NOSTATUSBAR "NOSTATUSBAR\n"  // do not display status bar

typedef uint32 idaapi chooser_cb_t(void *obj, uint32 n);

struct chooser_item_attrs_t
{
  int cb;               // size of this structure
                        // the callback must check this field and fill only
                        // the existing fields. the first 2 fields always exist:
  int flags;            // various bits
#define CHITEM_BOLD   0x0001 // display the item in bold
#define CHITEM_ITALIC 0x0002 // display the item in italic
#define CHITEM_UNDER  0x0004 // underline the item
#define CHITEM_STRIKE 0x0008 // strikeout the item
  bgcolor_t color;      // item color
  void reset(void)
  {
    cb    = sizeof(chooser_item_attrs_t);
    flags = 0;
    color = DEFCOLOR;
  }
};

// Chooser structure: used to embed a chooser in a form
struct chooser_info_t
{
  uint32 cb;          // size of the struct

  int flags;
  int width, height;  // in chars
  const char *title;

  void *obj;
  int columns;
  const int *widths;

  int icon;           // default icon
  uint32 deflt;       // default selection


  const char *const *popup_names;

  uint32 (idaapi *sizer)(void *obj);
  void (idaapi *getl)(void *obj, uint32 n, char *const *arrptr);
  uint32 (idaapi *del)(void *obj, uint32 n);
  void (idaapi *ins)(void *obj);
  uint32 (idaapi *update)(void *obj, uint32 n);
  void (idaapi *edit)(void *obj, uint32 n);
  void (idaapi *enter)(void *obj, uint32 n);
  void (idaapi *destroyer)(void *obj);
  int (idaapi *get_icon)(void *obj, uint32 n);
  void (idaapi *select)(void *obj, const intvec_t & sel);
  void (idaapi *refresh)(void *obj);
  void (idaapi *get_attrs)(void *obj, uint32 n, chooser_item_attrs_t *attrs);
  void (idaapi *initializer)(void *obj);
};

// Multi line text control: used to embed a text control in a form
struct textctrl_info_t
{
   size_t  cb;                 // size of this structure
   qstring text;               // in, out: text control value
   uint16  flags;
#define TXTF_AUTOINDENT 0x0001 // auto-indent on new line
#define TXTF_ACCEPTTABS 0x0002 // Tab key inserts 'tabsize' spaces
#define TXTF_READONLY   0x0004 // text cannot be edited (but can be selected and copied)
#define TXTF_SELECTED   0x0008 // shows the field with its text selected
#define TXTF_MODIFIED   0x0010 // gets/sets the modified status
#define TXTF_FIXEDFONT  0x0020 // the control uses IDA's fixed font
   uint16  tabsize;            // how many spaces a single tab will indent
   textctrl_info_t(): cb(sizeof(textctrl_info_t)), flags(0), tabsize(0) { }
};

// Generic list choosers. These functions display a window with a list and allow
// the user to select an item from the list.

// Generic list chooser (1-column)
//      Returns: -1   - the chooser was already open and is now active (only for non-modal choosers)
//               0    - the chooser was created but the user refused to choose anything
//               else - number of them selected item
uint32 choose(
        int flags,                      // various flags: see above for description (CH_XXX)
        int x0,int y0,                  // x0=-1 for autoposition
        int x1,int y1,                  // set x0=-2 if you need to use the chooser before opening the database
        void *obj,                      // object to show
        int width,                      // Max width of lines
        uint32 (idaapi*sizer)(void *obj),      // Number of items
        char *(idaapi*getl)(void *obj,uint32 n,char *buf),// Description of n-th item (1..n)
                                        // 0-th item if header line
                                        // 'buf' cannot be larger than MAXSTR
        const char *title,              // menu title (includes ptr to help)
                                        // may have chooser title prefixes (see above)
        int icon,                       // number of the default icon to display
        uint32 deflt=-1,                // item number to focus (1-based)
                                        // -1 - if a non-modal chooser was already open, do not change selection
                                        //      otherwise focus on the first item
        chooser_cb_t *del=NULL,         // callback for "Delete" (may be NULL)
                                        // supports multi-selection scenario too
                                        // returns: 1-ok, 0-failed
        void (idaapi*ins)(void *obj)=NULL, // callback for "New" (may be NULL)
        chooser_cb_t *update=NULL,      // callback for "Update"(may be NULL)
                                        // update the whole list
                                        // returns the new location of item 'n'
        void (idaapi*edit)(void *obj,uint32 n)=NULL,   // callback for "Edit" (may be NULL)
        void (idaapi*enter)(void * obj,uint32 n)=NULL, // callback for non-modal "Enter" (may be NULL)
        void (idaapi*destroy)(void *obj)=NULL,        // callback to call when the window is closed (may be NULL)
        const char * const *popup_names=NULL,         // Default: insert, delete, edit, refresh
        int (idaapi*get_icon)(void *obj,uint32 n)=NULL); // callback for get_icon (may be NULL)


// convenience function: modal chooser
inline uint32 choose(
        void *obj,
        int width,
        uint32 (idaapi*sizer)(void *obj),
        char *(idaapi*getl)(void *obj,uint32 n,char *buf),
        const char *title,
        int icon=-1,
        uint32 deflt=-1,
        chooser_cb_t *del=NULL,
        void (idaapi*ins)(void *obj)=NULL,
        chooser_cb_t *update=NULL,
        void (idaapi*edit)(void *obj,uint32 n)=NULL,
        void (idaapi*enter)(void * obj,uint32 n)=NULL,
        void (idaapi*destroy)(void *obj)=NULL,
        const char * const *popup_names=NULL,
        int (idaapi*get_icon)(void *obj,uint32 n)=NULL)
{
  return choose(CH_MODAL,-1,-1,-1,-1, obj, width, sizer,
                getl, title, icon, deflt, del, ins,
                update, edit, enter, destroy, popup_names, get_icon);
}

// Generic list chooser (n-column)
// See choose() above for the description of the undescribed parameters
uint32 choose2(
        int flags,
        int x0,int y0,                  // x0=-1 for autoposition
        int x1,int y1,                  // set x0=-2 if you need to use the chooser before opening the database
        void *obj,                      // object to show
        int ncol,                       // Number of columns
        const int *widths,              // Widths of columns (may be NULL)
                                        // low 16 bits of each value hold the column width
                                        // high 16 bits are flags (CHCOL_...)
        uint32 (idaapi*sizer)(void *obj),
        void (idaapi*getl)(void *obj,uint32 n,char * const *arrptr),
        const char *title,
        int icon,
        uint32 deflt=-1,
        chooser_cb_t *del=NULL,
        void (idaapi*ins)(void *obj)=NULL,
        chooser_cb_t *update=NULL,
        void (idaapi*edit)(void *obj,uint32 n)=NULL,
        void (idaapi*enter)(void * obj,uint32 n)=NULL,
        void (idaapi*destroy)(void *obj)=NULL,
        const char * const *popup_names=NULL,
        int (idaapi*get_icon)(void *obj,uint32 n)=NULL);


// convenience function: modal chooser2
inline uint32 choose2(
        void *obj,
        int ncol,
        const int *widths,
        uint32 (idaapi*sizer)(void *),
        void (idaapi*getl)(void *,uint32,char*const*),
        const char *title,
        int icon=-1,
        uint32 deflt=-1,
        chooser_cb_t *del=NULL,
        void (idaapi*ins)(void *)=NULL,
        chooser_cb_t *update=NULL,
        void (idaapi*edit)(void *,uint32)=NULL,
        void (idaapi*enter)(void *,uint32)=NULL,
        void (idaapi*destroy)(void *)=NULL,
        const char * const *popup_names=NULL,
        int (idaapi*get_icon)(void *obj,uint32 n)=NULL)
{
  return choose2(CH_MODAL,-1,-1,-1,-1, obj, ncol, widths,
                 sizer, getl, title, icon, deflt, del,
                 ins, update, edit, enter, destroy, popup_names, get_icon);
}

// New method to invoke the chooser
// this function benefits from additional callbacks
uint32 choose3(const chooser_info_t *chi);


#endif // SWIG

// definitions for add_chooser_command():
// the flags parameter is combination of the following bits:
#define CHOOSER_NO_SELECTION    0x01 // enable even if there's no selected item (n will be -1 for callback)
#define CHOOSER_MULTI_SELECTION 0x02 // enable for multiple selections
#define CHOOSER_POPUP_MENU      0x04 // command will appear in popup menu
#define CHOOSER_HOTKEY          0x08 // hotkey is present
// main menu indexes (each chooser has 3 top level menus)
#define CHOOSER_MENU_EDIT   0
#define CHOOSER_MENU_JUMP   1
#define CHOOSER_MENU_SEARCH 2


// Navigation band colorizer function
//      ea - address to calculate the color of
//      nbytes - number of bytes, this can be ignored for quick&dirty approach
// Returns: color of the specified address in RGB

typedef uint32 idaapi nav_colorizer_t(ea_t ea, asize_t nbytes);


// Callback function for menu commands
// If returns true, IDA will refresh the disassembly view and the list contents

typedef bool idaapi menu_item_callback_t(void *ud);


// Custom Viewer event handler types

namespace Controls
{
  class TWinControl;
  class TCustomControl; // ptr to custom ida viewer
}
using Controls::TWinControl;
using Controls::TCustomControl;

// Custom viewer & code viewer handler types
enum custom_viewer_handler_id_t
{
  CVH_USERDATA,
  CVH_KEYDOWN,
  CVH_POPUP,
  CVH_DBLCLICK,
  CVH_CURPOS,
  CVH_CLOSE,
  CVH_CLICK,
  CVH_QT_AWARE,

  // code viewer handlers
  CDVH_USERDATA = 1000,
  CDVH_SRCVIEW,
  CDVH_LINES_CLICK,
  CDVH_LINES_DBLCLICK,
  CDVH_LINES_POPUP,
  CDVH_LINES_DRAWICON,
  CDVH_LINES_LINENUM,
  CDVH_LINES_ICONMARGIN,
  CDVH_LINES_RADIX,
  CDVH_LINES_ALIGNMENT
};

// The user has pressed a key
typedef bool idaapi custom_viewer_keydown_t(TCustomControl *cv, int vk_key, int shift, void *ud);

// The user right clicked
typedef void idaapi custom_viewer_popup_t(TCustomControl *cv, void *ud);

// The user clicked
typedef bool idaapi custom_viewer_click_t(TCustomControl *cv, int shift, void *ud);

// The user double clicked
typedef bool idaapi custom_viewer_dblclick_t(TCustomControl *cv, int shift, void *ud);

// Cursor position has been changed
typedef void idaapi custom_viewer_curpos_t(TCustomControl *cv, void *ud);

// Custom viewer is being destroyed
typedef void idaapi custom_viewer_close_t(TCustomControl *cv, void *ud);

// Code viewer handlers for the lineinfo widget located to the left of the text.

// The user clicked, right clicked or double clicked
// pos - the clicked icon number. -1 means the click occurred on space not reserved to icons.
typedef void idaapi code_viewer_lines_click_t(TCustomControl *c, const place_t *p, int pos, int shift, void *ud);

// Icon drawing
// pos - the icon number, will be 0,1,2,3...
//       can be modified to skip positions and draw at the specified one
// Returns: the id of the icon to draw. If bitwise or'ed with 0x80000000,
//          IDA calls this function once more with pos+1 to retrieve one more icon.
typedef int idaapi code_viewer_lines_icon_t(TCustomControl *cv, const place_t *p, int *pos, void *ud);

// Calculate the line number. Return false to not print any number.
typedef bool idaapi code_viewer_lines_linenum_t(TCustomControl *cv, const place_t *p, uval_t *num, void *ud);


//------------------------------------------------------------------------
// Command line interpreters
// They provide functionality for the command line (located at the bottom of the main window)
// Only GUI version of IDA supports CLIs.

struct cli_t                    // Command line interpreter
{
  size_t size;                  // Size of this structure
  int32 flags;                  // Feature bits. One of CLIF_....:
#define CLIF_QT_AWARE    1      // keydown event will use Qt key codes

  const char *sname;            // Short name (displayed on the button)
  const char *lname;            // Long name (displayed in the menu)
  const char *hint;             // Hint for the input line

  // callback: the user pressed Enter
  // CLI is free to execute the line immediately or ask for more lines
  // Returns: true-executed line, false-ask for more lines
  bool (idaapi *execute_line)(const char *line);

  // callback: the user pressed Tab
  // Find a completion number N for prefix PREFIX
  // LINE is given as context information. X is the index where PREFIX starts in LINE
  // New prefix should be stored in PREFIX.
  // Returns: true if generated a new completion
  // This callback is optional
  bool (idaapi *complete_line)(
        qstring *completion,
        const char *prefix,
        int n,
        const char *line,
        int x);


  // callback: a keyboard key has been pressed
  // This is a generic callback and the CLI is free to do whatever
  // it wants.
  //    line - current input line (in/out argument)
  //    p_x  - pointer to current x coordinate of the cursor (in/out)
  //    p_sellen - pointer to current selection length (usually 0)
  //    p_vk_key - pointer to virtual key code (in/out)
  //           if the key has been handled, it should be reset to 0 by CLI
  //    shift - shift state
  // Returns: true-modified input line or x coordinate or selection length
  // This callback is optional
  bool (idaapi *keydown)(
        qstring *line,
        int *p_x,
        int *p_sellen,
        int *vk_key,
        int shift);
};

//---------------------------------------------------------------------------
// The mff parameter for execute_sync() may be one of the following:
#define MFF_FAST   0x0000       // Execute code as soon as possible.
                                // this mode is ok call ui related functions
                                // that do not query the database.
#define MFF_READ   0x0001       // Execute code only when ida is idle and it is safe
                                // to query the database.
                                // this mode is recommended only
                                // for code that does not modify the database.
                                // (nb: ida may be in the middle of executing
                                // another user request, for example it may be waiting
                                // for him to enter values into a modal dialog box)
#define MFF_WRITE  0x0002       // Execute code only when ida is idle and it is safe
                                // to modify the database. in particular,
                                // this flag will suspend execution if there is
                                // a modal dialog box on the screen
                                // this mode can be used to call any ida api function
                                // MFF_WRITE implies MFF_READ
#define MFF_NOWAIT 0x0004       // Do not wait for the request to be executed.
                                // the caller should ensure that the request is not
                                // destroyed until the execution completes.
                                // if not, the request will be ignored.
                                // the return code of execute_sync() is meaningless
                                // in this case.
                                // This flag can be used to delay the code execution
                                // until the next UI loop run even from the main thread.


// Execute code in the main thread. To be used with execute_sync()
// If the execute() callback raises an exception, execute_sync() never returns.
struct exec_request_t
{
  enum { MFF_MAGIC = 0x12345678 };
  bool valid(void) const
  {
    return (code & ~7) == MFF_MAGIC && (sem != NULL || (code & MFF_NOWAIT) != 0);
  }
  int code;                     // temporary location, used internally
  qsemaphore_t sem;             // semaphore to communicate with the main thread
                                // if NULL, will be initialized by execute_sync()
  virtual int idaapi execute(void) = 0;
  exec_request_t(void) : sem(NULL) {}
  // FIXME: windows: gcc compiled plugins can not use exec_request_t because the destructor
  // is generated differently!
  virtual ~exec_request_t(void) { qsem_free(sem); sem = NULL; code = 0; }
};

//---------------------------------------------------------------------------
// Base class for defining UI requests
// Override the run() method and insert your code.
class ui_request_t
{
public:
  // Run the UI request
  // return:
  //   - false: remove the request from the queue
  //   - true : reschedule the request and run it again
  virtual bool idaapi run() = 0;
  DEFINE_VIRTUAL_DTOR(ui_request_t);
};

// List of UI requests. The ui_request_t is allocated by the caller
// but its ownership is transferred to the execute_ui_request()
// The ui_request_t instance will be deleted as soon as it is executed and
// was not rescheduled for another run.
typedef qlist<ui_request_t *> ui_requests_t;

// Snapshot restoration completion callback
typedef void (idaapi *ss_restore_cb_t)(const char *errmsg, void *ud);

// EAView callback
typedef void idaapi eaviewer_cb_t(location_t *loc, void *ud);

// Bit definitions for the flags argument of jumpto()
#define UIJMP_ACTIVATE 0x0001  // activate the new window
#define UIJMP_DONTPUSH 0x0002  // do not remember the current address
                               // in the nagivation history
#define UIJMP_IDAVIEW  0x0004  // jump in idaview (by default any eaview is good)

#ifndef __UI__         // Not for the UI

// Convenience functions offered by the user interface

// Execute a list of UI requests
inline void execute_ui_requests(ui_requests_t *reqs) { callui(ui_execute_ui_requests_list, reqs); }

// Execute a variable number of UI requests (NULL terminated)
inline void execute_ui_requests(ui_request_t *req, ...)
{
  va_list va;
  va_start(va, req);
  callui(ui_execute_ui_requests, req, va);
  va_end(va);
}

inline bool jumpto(ea_t ea,int opnum=-1, int uijmp_flags=UIJMP_ACTIVATE)
{
  return callui(ui_jumpto, ea, opnum, uijmp_flags).cnd;
}

inline bool banner(int wait)               { return callui(ui_banner, wait).cnd;}
THREAD_SAFE inline bool is_msg_inited(void){ return callui(ui_is_msg_inited).cnd; }
inline void refresh_idaview(void)          { callui(ui_refreshmarked);}
inline void refresh_idaview_anyway(void)   { callui(ui_refresh);      }
inline void analyzer_options(void)         { callui(ui_analyzer_options); }
inline ea_t get_screen_ea(void)            { ea_t ea; callui(ui_screenea, &ea); return ea; }
inline int get_opnum(void)                 { return callui(ui_get_opnum).i; }
inline bool get_cursor(int *x, int *y)     { return callui(ui_get_cursor, x, y).cnd; }
inline char *get_curline(void)             { return callui(ui_get_curline).cptr; }
inline bool read_selection(ea_t *ea1, ea_t *ea2) { return callui(ui_readsel, ea1, ea2).cnd; }
inline void unmark_selection(void)         { callui(ui_unmarksel); }
inline void open_url(const char *url)      { callui(ui_open_url, url); }
inline ea_t get_hexdump_ea(int hexdump_num) { ea_t ea; callui(ui_hexdumpea, &ea, hexdump_num); return ea; }
inline bool set_xml(const char *path, const char *name, const char *value) { return callui(ui_set_xml, path, name, value).cnd; }
inline bool get_xml(const char *path, idc_value_t *value) { return callui(ui_get_xml, path, value).cnd; }
inline bool del_xml(const char *path)      { return callui(ui_del_xml, path).cnd; }
inline bool push_xml(const char *path)     { return callui(ui_push_xml, path).cnd; }
inline bool pop_xml(void)                  { return callui(ui_pop_xml).cnd; }
inline ushort get_key_code(const char *keyname) { return callui(ui_get_key_code, keyname).i16; }
inline ushort lookup_key_code(int key, int shift, bool is_qt) { return callui(ui_lookup_key_code, key, shift, is_qt).i16; }
inline void refresh_navband(bool force)     { callui(ui_refresh_navband, force); }
inline bool refresh_chooser(const char *title) { return callui(ui_refresh_chooser, title).cnd; }
inline bool close_chooser(const char *title) { return callui(ui_close_chooser, title).cnd; }
inline void install_command_interpreter(const cli_t *cp) { callui(ui_install_cli, cp, true); }
inline void remove_command_interpreter(const cli_t *cp) { callui(ui_install_cli, cp, false); }
inline void gen_disasm_text(ea_t ea1, ea_t ea2, text_t &text, bool truncate_lines) { callui(ui_gen_disasm_text, ea1, ea2, &text, truncate_lines); }
THREAD_SAFE inline int execute_sync(exec_request_t &req, int reqf) { return callui(ui_execute_sync, &req, reqf).i; }
inline bool set_dock_pos(const char *src_ctrl, const char *dest_ctrl, int orient, int left = 0, int top = 0, int right = 0, int bottom = 0)
{
  return callui(ui_set_dock_pos, src_ctrl, dest_ctrl, orient, left, top, right, bottom).cnd;
}
inline bool enable_input_hotkeys(bool enable) { return callui(ui_enable_input_hotkeys, enable).cnd; }
inline int load_custom_icon(const char *file_name) { return callui(ui_load_custom_icon_file, file_name).i; }
inline int load_custom_icon(const void *ptr, unsigned int len, const char *format) { return callui(ui_load_custom_icon, ptr, len, format).i; }
inline void free_custom_icon(int icon_id) { callui(ui_free_custom_icon, icon_id); }
inline bool process_ui_action(const char *name, int flags=0, void *param=NULL)
{
  return callui(ui_process_action, name, flags, param).cnd;
}

// snapshot management
inline bool take_database_snapshot(
      snapshot_t *ss,
      qstring *err_msg)
{
  return callui(ui_take_database_snapshot, ss, err_msg).cnd;
}

inline bool restore_database_snapshot(
      const snapshot_t *ss,
      ss_restore_cb_t cb,
      void *ud)
{
  return callui(ui_restore_database_snapshot, ss, cb, ud).cnd;
}

// timer opaque handle
typedef struct __qtimer_t {} *qtimer_t;
inline qtimer_t register_timer(int interval, int (idaapi *callback)(void *ud), void *ud)
{
  return (qtimer_t)(callui(ui_register_timer, interval, callback, ud).vptr);
}
inline bool unregister_timer(qtimer_t t)
{
  return callui(ui_unregister_timer, t).cnd;
}


// Add a menu item
//      menupath - path to the menu item after or before which the insertion will
//                 take place. Example: Debug/StartProcess
//                 Whitespace, punctuation are ignored.
//                 It is allowed to specify only the prefix of the menu item.
//                 Comparision is case insensitive.
//                 menupath may start with the following prefixes:
//                   [S] - modify the main menu of the structure window
//                   [E] - modify the main menu of the enum window
//      name     - name of the menu item (~x~ is used to denote Alt-x hot letter and
//                 '-' is used to create a separator)
//      hotkey   - hotkey for the menu item. may be NULL.
//      flags    - a combination of SETMENU_... consts
//      callback - function which gets called when the user selects it
//                 if the callback returns true, the screen will be refreshed
//      ud       - user data for the callback function
// If you want to modify the debugger menu, do it at the ui_debugger_menu_change
// event (ida might destroy your menu item if you do it elsewhere).
// You should not change the Edit, Plugins submenu.
// You should not modify the top level menu.

inline bool add_menu_item(
        const char *menupath,
        const char *name,
        const char *hotkey,
        int flags,
        menu_item_callback_t *callback,
        void *ud)
{
  return callui(ui_add_menu_item, menupath, name, hotkey, flags, callback, ud).cnd;
}


// Delete a menu item
//      menupath - path to the menu item. Example: Debug/Reset

inline bool del_menu_item(const char *menupath)
{ return callui(ui_del_menu_item, menupath).cnd; }

// Set the icon of a menu item
inline bool set_menu_item_icon(const char *item_name, int icon_id)
{ return callui(ui_set_menu_item_icon, item_name, icon_id).cnd; }

// Enable or disable a menu item
inline bool enable_menu_item(const char *item_name, bool enable)
{ return callui(ui_enable_menu_item, item_name, enable).cnd; }

//------------------------------------------------------------------------
// Get VCL global variables

#ifndef SWIG
#if defined(__BORLANDC__)
namespace Forms
{
  class TApplication;
  class TScreen;
}

namespace Controls
{
  class TMouse;
};

inline size_t getvcl(Forms::TApplication **app,
                     Forms::TScreen **screen,
                     Controls::TMouse **mouse)
{
  return callui(ui_getvcl, app, screen, mouse).i;
}

#endif // __BORLANDC__
#endif // SWIG

namespace Forms
{
  class TForm;
};
using Forms::TForm;

namespace Menus
{
  class TPopupMenu;
}
using Menus::TPopupMenu;

#ifndef _WINDOWS_
typedef struct HWND__ *HWND;
#endif

// Use of 'handle' value after this call is strongly discouraged
// because it may be invalidated by the UI at any time.
inline TForm *create_tform(const char *caption, HWND *handle)
{
  return (TForm *)callui(ui_create_tform, caption, handle).vptr;
}

// deprecated because the handle may be invalidated by ui unexpectedly.
// use ui_tform_visible and ui_tform_invisible.
inline HWND get_tform_handle(TForm *form)
{
  return (HWND)callui(ui_get_tform_handle, form).vptr;
}

inline void open_tform(TForm *form, int options)
{
  callui(ui_open_tform, form, options);
}

inline void close_tform(TForm *form, int options)
{
  callui(ui_close_tform, form, options);
}

inline void switchto_tform(TForm *form, bool take_focus)
{
  callui(ui_switchto_tform, form, take_focus);
}

inline TForm *find_tform(const char *caption)
{
  return (TForm *)callui(ui_find_tform, caption).vptr;
}

inline TForm *get_current_tform(void)
{
  return (TForm *)callui(ui_get_current_tform).vptr;
}

inline TCustomControl *create_custom_viewer(
        const char *title,
        TWinControl *parent,
        const place_t *minplace,
        const place_t *maxplace,
        const place_t *curplace,
        int y,
        void *ud)
{
  return (TCustomControl*)callui(ui_new_custom_viewer, title, parent,
                minplace, maxplace, curplace, y, ud).vptr;
}

// special kind of custom_viewer, with address support
inline TCustomControl *create_ea_viewer(
        const char *title,
        TWinControl *parent,
        const place_t *minplace,
        const place_t *maxplace,
        const place_t *curplace,
        int y,
        void *ud,
        int flags=0, // reserved
        eaviewer_cb_t *fillloc=NULL,
        eaviewer_cb_t *jumploc=NULL,
        location_t **p_loc=NULL)
{
  return (TCustomControl*)callui(ui_new_ea_viewer, title, parent,
                minplace, maxplace, curplace, y,
                ud, flags, fillloc, jumploc, p_loc).vptr;
}

inline void refresh_custom_viewer(TCustomControl *custom_viewer)
{
  callui(ui_refresh_custom_viewer, custom_viewer);
}

inline void repaint_custom_viewer(TCustomControl *custom_viewer)
{ // immediately refresh the screen
  callui(ui_repaint_qwidget, custom_viewer);
}

inline void destroy_custom_viewer(TCustomControl *custom_viewer)
{
  callui(ui_destroy_custom_viewer, custom_viewer);
}

inline bool jumpto(TCustomControl *custom_viewer, place_t *place, int x, int y)
{
  return callui(ui_jump_in_custom_viewer, custom_viewer, place, x, y).cnd;
}

inline place_t *get_custom_viewer_place(
        TCustomControl *custom_viewer,
        bool mouse,
        int *x,
        int *y)
{
  return (place_t *)callui(ui_get_curplace, custom_viewer, mouse, x, y).vptr;
}

inline void set_custom_viewer_popup_menu(
        TCustomControl *custom_viewer,
        TPopupMenu *menu)
{
  callui(ui_set_custom_viewer_popup, custom_viewer, menu);
}

// Returns true if running inside IDA Qt
inline bool is_idaq()
{
  return callui(ui_clearbreak, KERNEL_VERSION_MAGIC1, KERNEL_VERSION_MAGIC2+2, NULL, NULL).cnd;
}

inline void add_custom_viewer_popup_item(
        TCustomControl *custom_viewer,
        const char *title,
        const char *hotkey,
        menu_item_callback_t *cb,
        void *ud)
{
  callui(ui_add_custom_viewer_popup, custom_viewer, title, hotkey, cb, ud);
}

inline void set_custom_viewer_handlers(
        TCustomControl *custom_viewer,
        custom_viewer_keydown_t *keyboard_handler,
        custom_viewer_popup_t *popup_handler,
        custom_viewer_dblclick_t *dblclick_handler,
        custom_viewer_curpos_t *curpos_handler,
        custom_viewer_close_t *close_handler,
        void *user_data)
{
  callui(ui_set_custom_viewer_handlers, custom_viewer, keyboard_handler,
         popup_handler, dblclick_handler, curpos_handler, close_handler,
         user_data);
}

inline void *set_custom_viewer_handler(
        TCustomControl *custom_viewer,
        custom_viewer_handler_id_t handler_id,
        void *handler_or_data)
{
  return callui(ui_set_custom_viewer_handler, custom_viewer, handler_id,
                handler_or_data).vptr;
}

inline bool set_custom_viewer_qt_aware(TCustomControl *custom_viewer)
{
  return callui(ui_set_custom_viewer_handler, custom_viewer, CVH_QT_AWARE).cnd;
}

inline const char *get_custom_viewer_curline(TCustomControl *custom_viewer, bool mouse)
{
  return callui(ui_get_custom_viewer_curline, custom_viewer, mouse).cptr;
}

inline TCustomControl *get_current_viewer(void)
{
  return (TCustomControl *)callui(ui_get_current_viewer).vptr;
}

inline void set_custom_viewer_range(
        TCustomControl *custom_viewer,
        const place_t *minplace,
        const place_t *maxplace)
{
  callui(ui_set_custom_viewer_range, custom_viewer, minplace, maxplace);
}

inline bool is_idaview(TCustomControl *v)
{
  return callui(ui_is_idaview, v).cnd;
}

inline bool readsel2(TCustomControl *v, twinpos_t *p1, twinpos_t *p2)
{
  return callui(ui_readsel2, v, p1, p2).cnd;
}

inline TCustomControl *create_code_viewer(
        TForm *parent,
        TCustomControl *custview,
        int flags = 0)
{
  return (TCustomControl*)callui(ui_new_code_viewer, parent, custview, flags).vptr;
}

inline void *set_code_viewer_handler(
        TCustomControl *code_viewer,
        custom_viewer_handler_id_t handler_id,
        void *handler_or_data)
{
  return callui(ui_set_custom_viewer_handler, code_viewer, handler_id,
                handler_or_data).vptr;
}

inline bool set_code_viewer_user_data(TCustomControl *code_viewer, void *ud)
{
  return callui(ui_set_custom_viewer_handler, code_viewer, CDVH_USERDATA, ud).cnd;
}

inline void set_code_viewer_line_handlers(
        TCustomControl *code_viewer,
        code_viewer_lines_click_t *click_handler,
        code_viewer_lines_click_t *popup_handler,
        code_viewer_lines_click_t *dblclick_handler,
        code_viewer_lines_icon_t *drawicon_handler,
        code_viewer_lines_linenum_t *linenum_handler)
{
  callui(ui_set_code_viewer_line_handlers, code_viewer, click_handler,
         popup_handler, dblclick_handler, drawicon_handler, linenum_handler);
}

inline bool set_code_viewer_lines_icon_margin(TCustomControl *code_viewer, int margin)
{
  return callui(ui_set_custom_viewer_handler, code_viewer, CDVH_LINES_ICONMARGIN, margin).cnd;
}

inline bool set_code_viewer_lines_alignment(TCustomControl *code_viewer, int align)
{
  return callui(ui_set_custom_viewer_handler, code_viewer, CDVH_LINES_ALIGNMENT, align).cnd;
}

inline bool set_code_viewer_lines_radix(TCustomControl *code_viewer, int radix)
{
  return callui(ui_set_custom_viewer_handler, code_viewer, CDVH_LINES_RADIX, radix).cnd;
}

inline bool set_code_viewer_is_source(TCustomControl *code_viewer)
{
  return callui(ui_set_custom_viewer_handler, code_viewer, CDVH_SRCVIEW).cnd;
}

inline int get_tab_size(const char *path)
{
  return callui(ui_get_tab_size, path).i;
}

// Clear Ctrl-Break flag.

inline void clearBreak(void) { callui(ui_clearbreak); }


// Set Ctrl-Break flag.

inline void setBreak(void) { callui(ui_setbreak); }


// Check for Ctrl-Break.

inline bool wasBreak(void) { return callui(ui_wasbreak).cnd; }


inline bool ui_load_new_file(const char *filename,
                             linput_t *li,
                             ushort neflags)
{
  return callui(ui_load_file, filename, li, neflags).cnd;
}


inline bool ui_run_debugger(const char *dbgopts,
                            const char *exename,
                            int argc,
                            const char *const *argv)
{
  return callui(ui_run_dbg, dbgopts, exename, argc, argv).cnd;
}


// Add hotkey for IDC function
//      hotkey  - hotkey name
//      idcfunc - IDC function name
// returns: IDCHK_.. error codes (see above)

inline int add_idc_hotkey(const char *hotkey,const char *idcfunc)
{
  return callui(ui_add_idckey, hotkey, idcfunc).i;
}


// Delete IDC function hotkey
//      hotkey  - hotkey name
// returns: 1-ok, 0-failed

inline bool del_idc_hotkey(const char *hotkey)
{
  return callui(ui_del_idckey, hotkey).cnd;
}


#ifndef SWIG
// Pointer to range marker function (for idaviews and hexviews)
// This pointer is initialized by setup_range_marker()

extern void (idaapi*range_marker)(ea_t ea, asize_t size);


// Initialize pointer to idaview marker

inline void setup_range_marker(void)
{
  void *ptr = callui(ui_get_range_marker).vptr;
  if ( ptr != NULL )
    range_marker = reinterpret_cast<void (idaapi*)(ea_t, asize_t)>(ptr);
}

// Get highlighted identifier
inline bool get_highlighted_identifier(char *buf, size_t bufsize, int flags)
{
  return callui(ui_get_highlighted_identifier, buf, bufsize, flags).cnd;
}


// Inform the UI about any modifications of [ea, ea+size)

inline void mark_range_for_refresh(ea_t ea, asize_t size)
{
  if ( range_marker != NULL )
    range_marker(ea, size);
}

// Tell UI to refresh all idaviews and hexviews

inline void mark_all_eaviews_for_refresh(void)
{
  if ( range_marker != NULL )
    range_marker(0, BADADDR);
}
#endif // SWIG

inline TForm *open_exports_window(ea_t ea)
{
  return (TForm *)callui(ui_open_builtin, BWN_EXPORTS, ea).vptr;
}
inline TForm *open_imports_window(ea_t ea)
{
  return (TForm *)callui(ui_open_builtin, BWN_IMPORTS, ea).vptr;
}
inline TForm *open_names_window(ea_t ea)
{
  return (TForm *)callui(ui_open_builtin, BWN_NAMES, ea).vptr;
}
inline TForm *open_funcs_window(ea_t ea)
{
  return (TForm *)callui(ui_open_builtin, BWN_FUNCS, ea).vptr;
}
inline TForm *open_strings_window(ea_t ea, ea_t selstart=BADADDR, ea_t selend=BADADDR)
{
  return (TForm *)callui(ui_open_builtin, BWN_STRINGS, ea, selstart, selend).vptr;
}
inline TForm *open_segments_window(ea_t ea)
{
  return (TForm *)callui(ui_open_builtin, BWN_SEGS, ea).vptr;
}
inline TForm *open_segregs_window(ea_t ea)
{
  return (TForm *)callui(ui_open_builtin, BWN_SEGREGS, ea).vptr;
}
inline TForm *open_selectors_window(void)
{
  return (TForm *)callui(ui_open_builtin, BWN_SELS, 0).vptr;
}
inline TForm *open_signatures_window(void)
{
  return (TForm *)callui(ui_open_builtin, BWN_SIGNS, 0).vptr;
}
inline TForm *open_tils_window(void)
{
  return (TForm *)callui(ui_open_builtin, BWN_TILS, 0).vptr;
}
inline TForm *open_loctypes_window(int ordinal)
{
  return (TForm *)callui(ui_open_builtin, BWN_LOCTYPS, ordinal).vptr;
}
inline TForm *open_calls_window(ea_t ea)
{
  return (TForm *)callui(ui_open_builtin, BWN_CALLS, ea).vptr;
}
inline TForm *open_problems_window(ea_t ea)
{
  return (TForm *)callui(ui_open_builtin, BWN_PROBS, ea).vptr;
}
inline TForm *open_bpts_window(ea_t ea)
{
  return (TForm *)callui(ui_open_builtin, BWN_BPTS, ea).vptr;
}
inline TForm *open_threads_window(void)
{
  return (TForm *)callui(ui_open_builtin, BWN_THREADS, 0).vptr;
}
inline TForm *open_modules_window(void)
{
  return (TForm *)callui(ui_open_builtin, BWN_MODULES, 0).vptr;
}
inline TForm *open_trace_window(void)
{
  return (TForm *)callui(ui_open_builtin, BWN_TRACE, 0).vptr;
}
inline TForm *open_stack_window(void)
{
  return (TForm *)callui(ui_open_builtin, BWN_STACK, 0).vptr;
}
inline TForm *open_xrefs_window(ea_t ea)
{
  return (TForm *)callui(ui_open_builtin, BWN_XREFS, ea).vptr;
}
inline TForm *open_frame_window(func_t *pfn, uval_t offset)
{
  return (TForm *)callui(ui_open_builtin, BWN_FRAME, pfn, offset).vptr;
}
inline TForm *open_navband_window(ea_t ea, int zoom)
{
  return (TForm *)callui(ui_open_builtin, BWN_NAVBAND, ea, zoom).vptr;
}
inline TForm *open_enums_window(tid_t const_id=BADADDR)
{
  return (TForm *)callui(ui_open_builtin, BWN_ENUMS, const_id).vptr;
}
inline TForm *open_structs_window(tid_t id=BADADDR, uval_t offset=0)
{
  return (TForm *)callui(ui_open_builtin, BWN_STRUCTS, id, offset).vptr;
}
inline TForm *open_disasm_window(const char *window_title, const areavec_t *ranges=NULL)
{ // if range != NULL, then display a flow chart with the specified ranges
  return (TForm *)callui(ui_open_builtin, BWN_DISASMS, window_title, BADADDR, ranges, 0).vptr;
}
inline TForm *open_hexdump_window(const char *window_title)
{
  return (TForm *)callui(ui_open_builtin, BWN_DUMPS, window_title, BADADDR, 0).vptr;
}
inline TForm *open_notepad_window(void)
{
  return (TForm *)callui(ui_open_builtin, BWN_NOTEPAD, 0).vptr;
}

inline char *choose_idasgn(void)
{
  return callui(ui_choose, chtype_idasgn).cptr;
}

inline bool choose_til(char *buf, size_t bufsize)
{
  return callui(ui_choose, chtype_idatil, buf, bufsize).cnd;
}

inline ea_t choose_entry(const char *title)
{
  ea_t ea;
  callui(ui_choose, chtype_entry, &ea, title);
  return ea;
}

inline ea_t choose_name(const char *title)
{
  ea_t ea;
  callui(ui_choose, chtype_name, &ea, title);
  return ea;
}

inline ea_t choose_stkvar_xref(func_t *pfn, member_t *mptr)
{
  ea_t ea;
  callui(ui_choose, chtype_stkvar_xref, &ea, pfn, mptr);
  return ea;
}

inline ea_t choose_xref(ea_t to)
{
  ea_t ea;
  callui(ui_choose, chtype_xref, &ea, to);
  return ea;
}

inline enum_t choose_enum(const char *title, enum_t default_id)
{
  enum_t enum_id = default_id;
  callui(ui_choose, chtype_enum, &enum_id, title);
  return enum_id;
}

inline enum_t choose_enum_by_value(const char *title, enum_t default_id,
                                                uval_t value, uchar *serial)
{
  enum_t enum_id = default_id;
  callui(ui_choose, chtype_enum_by_value, &enum_id, title, value, serial);
  return enum_id;
}

inline func_t *choose_func(const char *title, ea_t default_ea)
{
  return callui(ui_choose, chtype_func, title, default_ea).fptr;
}

inline segment_t *choose_segm(const char *title, ea_t default_ea)
{
  return callui(ui_choose, chtype_segm, title, default_ea).segptr;
}

inline segreg_t *choose_segreg(const char *title)
{
  return callui(ui_choose, chtype_segreg, title).sregptr;
}

inline struc_t *choose_struc(const char *title)
{
  return callui(ui_choose, chtype_struc, title).strptr;
}

#ifndef SWIG
inline int choose_struc_path(const char *title, tid_t strid,
                      uval_t offset, adiff_t delta, bool appzero, tid_t *path)
{
  return callui(ui_choose, chtype_strpath, title, strid,
                                            offset, delta, appzero, path).i;
}

// Generic list chooser (1-column)
// See the description of this function above in this file
// (to find it, search for "list choosers")
inline uint32 choose(
        int flags,
        int x0,int y0,
        int x1,int y1,
        void *obj,
        int width,
        uint32 (idaapi*sizer)(void *obj),
        char *(idaapi*getl)(void *obj,uint32 n,char *buf),
        const char *title,
        int icon,
        uint32 deflt,
        chooser_cb_t *del,
        void (idaapi*ins)(void *obj),
        chooser_cb_t *update,
        void (idaapi*edit)(void *obj,uint32 n),
        void (idaapi*enter)(void * obj,uint32 n),
        void (idaapi*destroy)(void *obj),
        const char * const *popup_names,
        int (idaapi*get_icon)(void *obj,uint32 n))
{
  return callui(ui_choose, chtype_generic, flags, x0, y0, x1, y1, obj, width,
                sizer, getl, title, icon, deflt, del, ins, update,
                edit, enter, destroy, popup_names, get_icon).i32;
}


// Generic list chooser (n-column)
// See the description of this function above in this file
// (to find it, search for "list choosers")
inline uint32 choose2(
        int flags,
        int x0,int y0,
        int x1,int y1,
        void *obj,
        int ncol,
        const int *widths,
        uint32 (idaapi*sizer)(void *obj),
        void (idaapi*getl)(void *obj,uint32 n,char * const *arrptr),
        const char *title,
        int icon,
        uint32 deflt,
        chooser_cb_t *del,
        void (idaapi*ins)(void *obj),
        chooser_cb_t *update,
        void (idaapi*edit)(void *obj,uint32 n),
        void (idaapi*enter)(void * obj,uint32 n),
        void (idaapi*destroy)(void *obj),
        const char * const *popup_names,
        int (idaapi*get_icon)(void *obj,uint32 n))
{
  return callui(ui_choose, chtype_generic2, flags, x0, y0, x1, y1, obj, ncol,
                widths, sizer, getl, title, icon, deflt, del, ins,
                update, edit, enter, destroy, popup_names, get_icon).i32;
}

inline uint32 choose3(const chooser_info_t *chi)
{
  return callui(ui_choose_info, chi).i32;
}

#endif // SWIG

// Add a command for a chooser window.
// Returns: success
inline bool add_chooser_command(
        const char *chooser_caption,
        const char *cmd_caption,
        chooser_cb_t *chooser_cb,
        int menu_index=-1,       // menu index of the item in the main menu (gui only)
        int icon=-1,             // icon number (gui only)
        int flags=0)             // combination CHOOSER_... constants
{
  return callui(ui_add_chooser_cmd, chooser_caption, cmd_caption, chooser_cb,
                menu_index, icon, flags).cnd;
}

inline bool add_chooser_command(
        const char *chooser_caption,
        const char *cmd_caption,
        chooser_cb_t *chooser_cb,
        const char *hotkey,
        int menu_index=-1,       // menu index of the item in the main menu (gui only)
        int icon=-1,             // icon number (gui only)
        int flags=0)             // combination CHOOSER_... constants
{
  return callui(ui_add_chooser_cmd, chooser_caption, cmd_caption, chooser_cb,
                menu_index, icon, flags|CHOOSER_HOTKEY, hotkey).cnd;
}


// Get the underlying object of the specified chooser
// Returns: the object that was used to create the chooser
// NB: for single-column choosers, a proxy object will be returned.

inline void *get_chooser_obj(const char *chooser_caption)
{
  return callui(ui_get_chooser_obj, chooser_caption).vptr;
}


// Enable item-specific attributes for chooser items
// (for example, color list items differently depending on a criterium)
// If enabled, the chooser will generate ui_get_chooser_item_attrs
// events that can be intercepted by a plugin to modify the item attributes.
// This event is generated only in the GUI version of IDA.
// Specifying CH_ATTRS bit at the chooser creation time has the same effect.
// Returns: success

inline bool idaapi enable_chooser_item_attrs(const char *chooser_caption, bool enable)
{
  return callui(ui_enable_chooser_item_attrs, chooser_caption, enable).cnd;
}


// Display a dialog box with "Please wait..."
// If the text message starts with "HIDECANCEL\n", the cancel button
// won't be displayed in the dialog box and you don't need to check
// for cancellations with wasBreak(). Plugins must call hide_wait_box()
// to close the dialog box, otherwise the user interface will be disabled.

AS_PRINTF(1, 0) inline void show_wait_box_v(const char *format, va_list va)
{
  callui(ui_mbox, mbox_wait, format, va);
}


AS_PRINTF(1, 2) inline void show_wait_box(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  show_wait_box_v(format, va);
  va_end(va);
}


// Hide the "Please wait dialog box"

inline void hide_wait_box(void)
{
  // stupid watcom requires va_list should not be NULL
  callui(ui_mbox, mbox_hide, NULL, &callui);
}


// Replace the label of "Please wait dialog box"

AS_PRINTF(1, 2) inline void replace_wait_box(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  callui(ui_mbox, mbox_replace, format, va);
  va_end(va);
}


// See AskUsingForm_c() function

AS_PRINTF(1, 0) inline int AskUsingForm_cv(const char *format, va_list va)
{
  return callui(ui_form, format, va).i;
}


// A helper function for the complex dialog box (form) callbacks:
//    close_normally - 1: form is closed normally as if the user pressed Enter
//                     0: form is closed abnormally as if the user pressed Esc

inline void close_form(const TView *const *fields, int close_normally)
{
  callui(ui_close_form, fields, close_normally);
}


// Issue a beeping sound.

inline void beep(beep_t beep_type=beep_default)
{
  callui(ui_beep, beep_type);
}


// See askbuttons_c() function

THREAD_SAFE AS_PRINTF(5, 0) inline int askbuttons_cv(
        const char *Yes,
        const char *No,
        const char *Cancel,
        int deflt,
        const char *format,
        va_list va)
{
  return callui(ui_askyn, Yes, No, Cancel, deflt, format, va).i;
}


// See askfile_c() function

AS_PRINTF(3, 0) inline char *askfile_cv(
        int savefile,
        const char *defval,
        const char *format,
        va_list va)
{
  return callui(ui_askfile, savefile, defval, format, va).cptr;
}

// Show a message box asking to send the input file to support@hex-rays.com
//      format - the reason why the input file is bad

THREAD_SAFE AS_PRINTF(1, 2) inline void ask_for_feedback(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  callui(ui_mbox, mbox_feedback, format, va);
  va_end(va);
}


// Display a dialog box and wait for the user to input an identifier
//      defval  - default value. will be displayed initially in the input line.
//                may be NULL.
//      format  - number of message from IDA.HLP to display as question
//                in printf() style format
// If the user enters a non-valid identifier, this function displays a warning
// and allows to correct it.
// returns: NULL-if the user pressed Esc.
//          otherwise returns pointer to identifier.

AS_PRINTF(2, 3) inline char *askident(const char *defval, const char *format, ...)
{
  va_list va;
  va_start(va, format);
  char *result = callui(ui_askident, defval, format, va).cptr;
  va_end(va);
  return result;
}


// Display a dialog box and wait for the user to input an address
//      addr    - in/out parameter. contains pointer to the address.
//      format  - printf() style format string with the question
// returns: 0-if the user pressed Esc.
//          1-ok, the user entered an address

AS_PRINTF(2, 3) inline int askaddr(ea_t *addr, const char *format, ...)
{
  va_list va;
  va_start(va, format);
  bool cnd = callui(ui_askaddr, addr, format, va).cnd;
  va_end(va);
  return cnd;
}


// Display a dialog box and wait for the user to input an segment name
//      sel     - in/out parameter. contains selector of the segment
//      format  - printf() style format string with the question
// this function allows to enter segment register names, segment base
// paragraphs, segment names to denote a segment.
// returns: 0-if the user pressed Esc.
//          1-ok, the user entered an segment name

AS_PRINTF(2, 3) inline int askseg(sel_t *sel, const char *format, ...)
{
  va_list va;
  va_start(va, format);
  bool code = callui(ui_askseg, sel, format, va).cnd;
  va_end(va);
  return code;
}


// Display a dialog box and wait for the user to input an number
//      value   - in/out parameter. contains pointer to the number
//      format  - printf() style format string with the question
// The number is represented in C-style.
// Actually this function allows to enter any IDC expression and
// properly calculates it.
// returns: 0-if the user pressed Esc.
//          1-ok, the user entered a valid number.

AS_PRINTF(2, 3) inline int asklong(sval_t *value, const char *format, ...)
{
  va_list va;
  va_start(va, format);
  bool code = callui(ui_asklong, value, format, va).cnd;
  va_end(va);
  return code;
}

AS_PRINTF(3, 0) inline char *vaskstr(
        int hist,
        const char *defval,
        const char *format,
        va_list va)
{
  return callui(ui_askstr, hist, defval, format, va).cptr;
}

AS_PRINTF(4, 0) inline char *vasktext(
        size_t size,
        char *answer,
        const char *defval,
        const char *format,
        va_list va)
{
  return callui(ui_asktext, size, answer, defval, format, va).cptr;
}

THREAD_SAFE AS_PRINTF(1, 0) inline void vwarning(const char *format, va_list va)
{
  callui(ui_mbox, mbox_warning, format, va);
}

THREAD_SAFE AS_PRINTF(1, 0) inline void vinfo(const char *format, va_list va)
{
  callui(ui_mbox, mbox_info, format, va);
}

THREAD_SAFE AS_PRINTF(1, 0) NORETURN inline void vnomem(const char *format, va_list va)
{
  callui(ui_mbox, mbox_nomem, format, va);
  // NOTREACHED
#ifndef UNDER_CE
  abort(); // to suppress compiler warning or error
#endif
}

THREAD_SAFE AS_PRINTF(1, 0) inline int vmsg(const char *format, va_list va)
{
  return callui(ui_msg, format, va).i;
}

inline bool display_copyright_warning(void)
{
  return callui(ui_copywarn).cnd;
}

#endif  // __UI__ END OF UI SERVICE FUNCTIONS

#ifdef __GUI__
bool idaapi set_xml(const char *path, const char *name, const char *value);
#endif
#if !defined(__UI__) || defined(__GUI__)
inline bool set_xml(const char *path, const char *name, int value)
{
  char buffer[12];
  ::qsnprintf(buffer, sizeof(buffer), "%d", value);
  return set_xml(path, name, buffer);
}
#endif

//---------------------------------------------------------------------------
//      E R R O R / W A R N I N G / I N F O   D I A L O G   B O X E S
//---------------------------------------------------------------------------

// If this variable is set, then dialog boxes will not appear on the screen.
// Warning/info messages are shown in the messages window.
// The default value of user input dialogs will be returned to the
// caller immediately.
// This variable is used to enable unattended work of ida.

idaman int ida_export_data batch;


idaman int ida_export_data errorexit;   // is 1 if we are exiting with from
                                        // error() function.
                                        // useful for atexit() functions.


// Display error dialog box and exit.
// If you just want to display an error message and let IDA continue,
// do NOT use this function! Use warning() instead.
//      format - printf() style message string.
//               It may have some prefixes, see 'Format of dialog box' for details.
// Err() function does the same but the format string is taken from IDA.HLP

THREAD_SAFE AS_PRINTF(1, 2) NORETURN inline void error(const char *format,...)
{
  va_list va;
  va_start(va, format);
  verror(format, va);
  // NOTREACHED
}

// Display warning dialog box and wait for the user to press Enter or Esc
//      format - printf() style format string.
//               It may have some prefixes, see 'Format of dialog box' for details.
// This messagebox will by default contain a "Don't display this message again"
// checkbox if the message is repetitively displayed. If checked, the message
// won't be displayed anymore during the current IDA session.
// Warn() function does the same but the format string is taken from IDA.HLP

THREAD_SAFE AS_PRINTF(1, 2) inline void warning(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  vwarning(format, va);
  va_end(va);
}

// Display info dialog box and wait for the user to press Enter or Esc
//      format - printf() style format string.
//               It may have some prefixes, see 'Format of dialog box' for details.
// This messagebox will by default contain a "Don't display this message again"
// checkbox. If checked, the message will never be displayed anymore (state saved
// in the Windows registry or the idareg.cfg file for a non-Windows version).
// Info() function does the same but the format string is taken from IDA.HLP

THREAD_SAFE AS_PRINTF(1, 2) inline void info(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  vinfo(format, va);
  va_end(va);
}

// Display "no memory for module ..." dialog box and exit
//      format  - printf() style message string.
//                name of module.

THREAD_SAFE AS_PRINTF(1, 2) NORETURN inline void nomem(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  vnomem(format, va);
  // NOTREACHED
}


// Output a formatted string to messages window [analog of printf()]
//      format - printf() style message string.
// Message() function does the same but the format string is taken from IDA.HLP
// Returns: number of bytes output
//
// Everything appearing on the messages window may be written
// to a text file. For this the user should define the following environment
// variable:
//         set IDALOG=idalog.txt
//

THREAD_SAFE AS_PRINTF(1, 2) inline int msg(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  int nbytes = vmsg(format, va);
  va_end(va);
  return nbytes;
}

#ifndef SWIG
//----------------------------------------------------------------------
//      F O R M S  -  C O M P L E X   D I A L O G   B O X E S
//----------------------------------------------------------------------
// Display a dialog box and wait for the user.
//      form     - dialog box as a string
//                 See its format below
// return: 0  - the user pressed Esc, no memory to display or form syntax error
//             a dialog box (a warning is displayed in this case).
//             all variables retain their original values.
//         1  - ok, all input fields are filled and validated.
// If the form contains the "BUTTON NO <title>" keyword, then the return values
// are the same as in the askyn() function (ASKBTN_XXX)

int AskUsingForm_cv(const char *form, va_list va);
inline int AskUsingForm_c(const char *form, ...)
{
  va_list va;
  va_start(va, form);
  int code = AskUsingForm_cv(form, va);
  va_end(va);
  return code;
}

// The following callback function is called when the user presses a
// form-specific button (defined with a field type B).
//      fields - array of input fields
//      code   - code of the pressed button
// Note: from this callback you may call close_form() function.
//       In this case the form will be closed as soon as you return from the callback.

typedef void (idaapi *formcb_t)(TView *fields[], int code); // callback for buttons


// From this callback you may call close_form() function.
// The form will be closed as soon as you return from the callback.
//      is_ok - 1: form is closed normally as if the user pressed Enter
//              0: form is closed abnormally as if the user pressed Esc

void close_form(const TView *const *fields, int is_ok);


// Functions available from formchgcb_t
struct form_actions_t
{
  // get value of an input field.
  // negative field ids can be used to denote labels that correspond
  // to the main edit or color button control.
  // returns false: no such field id or invalid field type (B)
  virtual bool idaapi get_field_value(int field_id, void *buf) = 0;

  // set value of an input field.
  // returns false: no such field id or invalid field type (B)
  virtual bool idaapi set_field_value(int field_id, const void *buf) = 0;

  // enable or disable an input field
  // returns false: no such field id
  virtual bool idaapi enable_field(int field_id, bool enable) = 0;

  // show or hide an input field
  // returns false: no such field id
  virtual bool idaapi show_field(int field_id, bool display) = 0;

  // move/resize an input field
  // parameters specified as -1 are not modified
  // returns false: no such field id
  virtual bool idaapi move_field(int field_id, int x, int y, int w, int h) = 0;

  // get currently focused input field. -1 - none
  virtual int idaapi get_focused_field(void) = 0;

  // set currently focused input field
  // returns false: no such field id
  virtual bool idaapi set_focused_field(int field_id) = 0;

  // refresh a field
  virtual void idaapi refresh_field(int field_id) = 0;

  // close the form (see close_form)
  virtual void idaapi close(int close_normally) = 0;

  // retrieve the user data specified through %*
  virtual void *idaapi get_ud() = 0;
};

// The following callback function is called when an input field is modified
// The callback will be also called before displaying the form and as soon
// as the user presses OK
//      field_id - id of the modified field
//                 -1: form is going to be displayed
//                 -2: form is going to be closed with OK.
//                     if formcghcb returns >0, then the form will be closed

typedef int (idaapi *formchgcb_t)(int field_id, form_actions_t &fa);


//------------------------------------------------------------------------
/* Format string for AskUsingForm_c()

  The following keywords might appear at the beginning of the form
  (case insensitive):

  STARTITEM number

    where number is a number of input field the cursor will stand on.
    By default the cursor is in the first field of the dialog box.
    The input fields are numbered from 0 (the first field is field 0).

  BUTTON name caption

    Alternative caption for a button. It may contain the character
    to highlight in this form:  ~Y~es
    Valid button names are: YES, NO, CANCEL
    For example:
        BUTTON YES Please do
        BUTTON NO Nope
        BUTTON CANCEL NONE

    By default the NO button is not displayed. If it is displayed, then
    the return value of the function will be different!
    (see the function description)

    Empty text means that there won't be any corresponding button.
    (you may also use NONE as the caption to hide it)

    A * after the button name means that this button will be the default:

      BUTTON CANCEL* Cancel

  Next, if the dialog box is kept in IDA.HLP, the following may appear:
  (this defines help context for the whole dialog box)

  @hlpMessageName[]

  If the form is not in IDA.HLP file, then it may have a built-in
  help message. In this case the help screen should be enclosed in the
  following keywords:

  HELP
  ....
  ....
  ....
  ENDHELP

  Each keyword should be alone on a line.

  Next there must be the title line and 2 empty lines.
  All text in the dialog box text string is copied to the dialog without
  any modifications. There are two special cases:

        - format parameters
        - input fields

  Format parameters are used to specify variant parts of dialog box.
  They are specified as "%x" combination, where x is format specifier.
  All input field types (except B and K) are valid format specifiers.
  List of input field types is given below. Parameter for "%x" combination
  is taken from the list function input arguments (va_list). The corresponding
  argument should contain pointer (sic, pointer) to the value to be converted
  and displayed. For example, dialog box:

  ------ format:
        Sample dialog box


        This is sample dialog box for %A
        using address %$

        <~E~nter value:N:32:16::>

  ------

  should be called as
                char *string = "something";
                ea_t addr = someaddr;
                uval_t answer = 0;
                int ok = AskUsingForm_c(format, string, &addr, &answer);

  The combination '%/' corresponds to a callback function that will be
  called when any of the fields is modified. The callback type is formchgcb_t.
  There can be only one such callback.

  The combination '%*' is used to store user data (void *) in the form.
  This data can be later retrieved from the formchgcb_t callback via the
  form action method get_ud().

  Input fields are represented by the following combination:

  <label:type:width:swidth:@hlp[]>

  where
        label - any text string serving as label for the input field
                the label may contain hotkey definition like this: "~O~pen"
                (O keystroke is hotkey here)
        type  - a character specifing type of input field.
                The form() function will perform initial validation of
                value specified by the user and convert it appropriately.
                See table of input field types below. The type can be followed
                by a decimal number, an input field id.
        width - decimal number specifying width of input field.
                this number may be omitted.
                For a field of type 'B' this attribute contains code generated
                when the user presses the button.
                For a field of type 'f' (path to file) this attribute specifies the dialog type:
                  0-'open file' dialog box
                  1-'save file' dialog box
                For a field of type 'b' (dropdown list) this attribute specifies the readonly attribute:
                  0   - read-only dropdown list
                  > 0 - editable dropdown list
        swidth -decimal number specifying width of visible part of input field.
                this number may be omitted.
        @hlp[]- help context for the input field. you may replace the
                help context with '::' (two colons) if you don't want to
                specify help context. The help context is a number of help
                screen from IDA.HLP file.


  Input field types                               va_list parameter
  -----------------                               -----------------

  A - ascii string                                char* at least MAXSTR size
  S - segment                                     sel_t*
  N - hex number, C notation                      uval_t*
  n - signed hex number, C notation               sval_t*
  L - default base (usually hex) number,          uint64*
      C notation
  l - default base (usually hex) number, signed,  int64*
      C notation
  M - hex number, no "0x" prefix                  uval_t*
  D - decimal number                              sval_t*
  O - octal number, C notation                    sval_t*
  Y - binary number, "0b" prefix                  sval_t*
  H - char value, C notation                      sval_t*
  $ - address                                     ea_t*
  I - ident                                       char* at least MAXNAMELEN size
  B - button                                      formcb_t
  K - color button                                bgcolor_t*
  F - path to folder                              char* at least QMAXPATH size
  f - path to file                                char* at least QMAXPATH size
  T - type declaration                            char* at least MAXSTR size
  E - chooser                                     chooser_info_t * - Embedded chooser
                                                  intvec_t * - in/out: selected lines
                                                    (NB: this field takes two args)
  t - multi line text control                     textctrl_info_t *
  b - dropdown list                               qstrvec_t * - the list of items
                                                  int/qstring - the preselected item
                                                    (a qstring when the combo is editable)

  The n, N, D, O, Y, H fields interpret the input as an IDC expression.
  M and $ fields fallback to IDC if the input can not be interpreted
  correctly.

  If the buffer for 'F' field contains filemasks and descriptions like this:
    *.exe|Executable files,*.dll|Dll files
  they will be used in the dialog box filter.

  The hint message can be specified before the label enclosed in '#':

  <#hint message#label:...>

  Radiobuttons and checkboxes are represented by:

  <label:type>
  <label:type>>         - end of block

  where valid types are C and R
  (you may use lowercase 'c' and 'r' if you need to create two radiobutton
  or checkbox groups on the same lines). The field id of the whole group
  can be specified between the brackets: <label:type>ID>

  field types           va_list parameter
  -----------           -----------------

  C - checkbox          ushort*                 bit mask of checkboxes
  R - radiobutton       ushort*                 number of radiobutton

  The box title and hint messages can be specified like this:

  <#item hint#title#box hint#label:type>

  The title and the box hint can be specified only in the first item of the box.
  If the hint doesn't exist, it should be specified as an empty hint (##title##)
  The subsequent items can have an item hint only:

  <#item hint#label:type>

  Initial values of input fields are specified in the corresponding
  input/output parameters (taken from va_list array).

  Ok, Cancel and (possibly) Help buttons are displayed at the bottom of
  the dialog box automatically. Their captions can be changed by the keywords
  described at the beginning of this page.

  Input field definition examples:

   <Kernel analyzer options ~1~:B:0:::>
   <~A~nalysis enabled:C>
   <~I~ndicator enabled:C>>
   <Names pre~f~ix  :A:15:15::>
   <~O~utput file:f:1:64::>
   <~O~utput directory:F:1:64::>

*/
#endif // SWIG

//---------------------------------------------------------------------------
//      Y E S / N O   D I A L O G  B O X
//---------------------------------------------------------------------------

// button IDs used in askyn() and askbuttons() functions

#define ASKBTN_YES     1  // Yes button
#define ASKBTN_NO      0  // No button
#define ASKBTN_CANCEL -1  // Cancel button
#define ASKBTN_BTN1    1  // First (Yes) button
#define ASKBTN_BTN2    0  // Second (No) button
#define ASKBTN_BTN3   -1  // Third (Cancel) button

// Display a dialog box and get choice from "Yes", "No", "Cancel"
//      deflt   - default choice: one of ASKBTN_XXX values
//      format  - The question in printf() style format
// returns: ASKBTN_XXX value - selected button (Esc key returns Cancel value)

AS_PRINTF(2, 0) inline int askyn_cv(int deflt, const char *format, va_list va)
{
  return askbuttons_cv(NULL, NULL, NULL, deflt, format, va);
}

AS_PRINTF(2, 3) inline int askyn_c(int deflt, const char *format, ...)
{
  va_list va;
  va_start(va, format);
  int code = askyn_cv(deflt, format, va);
  va_end(va);
  return code;
}

// Display a dialog box and get choice from maximum three possibilities
//      Yes             - text for the first button
//      No              - text for the second button
//      Cancel          - text for the third button
//                      for all buttons:
//                        "" or NULL - take the default name for the button
//                      use 'format' to hide the cancel button
//
//      deflt           - default choice: one of ASKBTN_XXX values
//      format          - printf-style format string for question.
//                        it may have some prefixes, see below
//      va              - parameters for the format string
// returns: ASKBTN_XXX value - selected button (Esc key returns Cancel/3rd button value)

AS_PRINTF(5, 6) inline int askbuttons_c(
        const char *Yes,
        const char *No,
        const char *Cancel,
        int deflt,
        const char *format,
        ...)
{
  va_list va;
  va_start(va, format);
  int code = askbuttons_cv(Yes, No, Cancel, deflt, format, va);
  va_end(va);
  return code;
}

//------------------------------------------------------------------------
/* Format of dialog box (actually they are mutliline strings
                         delimited by newline characters)

  The very first line of dialog box can specify a dialog box
  title if the following line appears:

  TITLE title string


  Then, the next line may contain an icon to display
  in the GUI version (ignored by the text version):

  ICON NONE          (no icon)
       INFO          (information icon)
       QUESTION      (question icon)
       WARNING       (warning icon)
       ERROR         (error icon)


  Then, the next line may contain a 'Don't display this message again'
  checkbox. If this checkbox is selected and the user didn't select cancel,
  the button he selected is saved and automatically returned.

  AUTOHIDE NONE      (no checkbox)
           DATABASE  (return value is saved to database)
           REGISTRY  (return value is saved to Windows registry or idareg.cfg
                      if non-Windows version)
           SESSION   (return value is saved for the current IDA session)
  It is possible to append "*" to the AUTOHIDE keywords to have this checkbox
  initially checked. For example: "AUTOHIDE REGISTRY*"

  To hide the cancel button the following keyword can be used:

  HIDECANCEL

  Please note that the user still can cancel the dialog box by pressing Esc
  or clicking on the 'close window' button.

  Finally, if the dialog box is kept in IDA.HLP, the following may appear
  to add a Help button (this defines help context for the whole dialog box):

  @hlpMessageName[]


  Each keyword should be alone on a line.

  Next, a format string must be specified.
  To center message lines in the text version, start them with '\3' character
  (currently ignored in the GUI version).
*/

//---------------------------------------------------------------------------
//      A S K   S T R I N G   O F   T E X T
//---------------------------------------------------------------------------

// Display a dialog box and wait for the user to input a text string
// Use this function to ask one-line text. For multiline input, use
// asktext() and asksmalltext() functions.
// This function will trim the trailing spaces.
//      hist    - category of history lines. an arbitrary number.
//                this number determines lines accessible in the history
//                of the user input (when he presses down arrow)
//                One of HIST_.. constants should be used here
//      defval  - default value. will be displayed initially in the input line.
//                may be NULL.
//      format  - printf() style format string with the question
// returns: NULL-if the user pressed Esc.
//          otherwise returns the entered value in a static storage.

AS_PRINTF(3, 4) inline char *askstr(int hist, const char *defval, const char *format, ...)
{
  va_list va;
  va_start(va, format);
  char *result = vaskstr(hist, defval, format, va);
  va_end(va);
  return result;
}

// Input line history categories used by the kernel:

#define HIST_SEG    1           // segment names
#define HIST_CMT    2           // comments
#define HIST_SRCH   3           // search substrings
#define HIST_ADDR   4           // addresses
#define HIST_IDENT  5           // names
#define HIST_NUM    6           // numbers
#define HIST_FILE   7           // file names
#define HIST_TYPE   8           // type declarations
#define HIST_CMD    9           // commands
#define HIST_DIR   10           // directory names


#ifndef SWIG
// Display a dialog box and wait for the user to input multiline text
//      size    - maximum size of text in bytes
//      answer  - output buffer. if you specify NULL then the answer
//                will be returned in a buffer allocated by
//                'new char' operator.
//      defval  - default value. will be displayed initially in the input line.
//                may be NULL.
//      format  - printf() style format string with the question
// returns: NULL-if the user pressed Esc.
//          otherwise returns pointer to text.

AS_PRINTF(4, 5) inline char *asktext(
        size_t size,
        char *answer,
        const char *defval,
        const char *format,
        ...)
{
  va_list va;
  va_start(va, format);
  char *result = vasktext(size, answer, defval, format, va);
  va_end(va);
  return result;
}
#endif // SWIG


//---------------------------------------------------------------------------
//      A S K   A D D R E S S E S ,   N A M E S ,   N U M B E R S ,   E T C .
//---------------------------------------------------------------------------

// Display a dialog box and wait for the user to input a file name
//      savefile- the entered file name will be used to save file
//      defval  - default value. will be displayed initially in the input line.
//                may be NULL. may be a wildcard file name.
//      format  - printf() style format string with the question
// This function displays a window with file names present in the directory
// pointed by 'defval'.
// returns: NULL-if the user pressed Esc.
//          otherwise the user entered a valid file name.

AS_PRINTF(3, 0) char *askfile_cv(
        int savefile,
        const char *defval,
        const char *format,
        va_list va);

AS_PRINTF(3, 4) inline char *askfile_c(
        int savefile,
        const char *defval,
        const char *format,
        ...)
{
  va_list va;
  va_start(va, format);
  char *answer = askfile_cv(savefile, defval, format, va);
  va_end(va);
  return answer;
}

//---------------------------------------------------------------------------
//      A D D - O N S
//---------------------------------------------------------------------------

// information about an installed add-on (e.g. a plugin)
struct addon_info_t
{
  size_t cb;                // size of this structure
  const char *id;           // product code, e.g. "com.hexrays.hexx86w". Must be unique
  const char *name;         // descriptive name, e.g. "Hex-Rays x86 Decompiler (Windows)"
  const char *producer;     // e.g. "Hex-Rays SA"
  const char *version;      // version string, e.g. 1.5.110408
  const char *url;          // URL of the product http://www.hex-rays.com/decompiler.shtml
  const char *freeform;     // any string, e.g. "Copyright (c) 2007-2011 Hex-Rays"
  const void *custom_data;  // custom data (license ID etc). Can be NULL. Not displayed in UI.
  size_t custom_size;

  addon_info_t() { memset(this, 0, sizeof(addon_info_t)); cb = sizeof(addon_info_t); };
};

#ifndef __UI__
// Register an add-on. Show its info in the About box.
// For plugins, should be called from init() function
// (repeated calls with the same product code overwrite previous entries)
// returns: index of the add-on in the list, or -1 on error
inline int register_addon(const addon_info_t *info)
{
  return callui(ui_addons, 0, info).i;
}

// returns: number of installed addons
inline int addon_count()
{
  return callui(ui_addons, 1).i;
}

// get info about a registered addon with a given product code
// info->cb must be valid!
// NB: all pointers are invalidated by next call to register_addon or get_addon_info
// returns false if not found
inline bool get_addon_info(const char *id, addon_info_t *info)
{
  return callui(ui_addons, 2, id, info).cnd;
}

// get info about a registered addon with specific index
// info->cb must be valid!
// NB: all pointers are invalidated by next call to register_addon or get_addon_info
// returns false if index is out of range
inline bool get_addon_info_idx(int index, addon_info_t *info)
{
  return callui(ui_addons, 3, index, info).cnd;
}
#endif

//---------------------------------------------------------------------------
//      S T R I N G   F U N C T I O N S
//---------------------------------------------------------------------------

// Add space characters to the string so that its length will be at least
// 'len' characters. Don't trim the string if it is longer than 'len'.
//      str - pointer to string to modify (may not be NULL)
//      len - wanted length of string
// This function may be applied to colored strings
// returns: pointer to the end of input string

idaman THREAD_SAFE char *ida_export addblanks(char *str,ssize_t len);


// Remove trailing space characters from a string
//      str - pointer to string to modify (may be NULL)
// returns: pointer to input string

idaman THREAD_SAFE char *ida_export trim(char *str);


// Skip whitespaces in the string

idaman THREAD_SAFE const char *ida_export skipSpaces(const char *ptr);
inline char *skipSpaces(char *ptr)
  { return CONST_CAST(char*)(skipSpaces((const char *)ptr)); }


// Find a line with the specified code in the strarray_t array
// If the last element of the array has code==0 then it is considered
// as the default entry
// If no default entry exists and the code is not found, strarray() returns ""

struct strarray_t
{
  int code;
  const char *text;
};

idaman THREAD_SAFE const char *ida_export strarray(const strarray_t *array, size_t array_size, int code);


#ifndef SWIG
// Convert whitespace to tabulations
// This function will stop the conversion as soon as a string or character constant
// is encountered

idaman THREAD_SAFE void ida_export entab(char *string);


//---------------------------------------------------------------------------
//      C O N V E R S I O N S
//---------------------------------------------------------------------------


// Linear address to ascii string and vice versa

idaman size_t ida_export ea2str(ea_t ea, char *buf, size_t bufsize);
idaman bool ida_export str2ea(const char *str, ea_t *ea_ptr, ea_t screenEA);


// Number in C-notation to an address

idaman bool ida_export atoea(const char *str, ea_t *pea);


// Segment selector to ascii string and vice versa

idaman size_t ida_export stoa(ea_t from, sel_t seg, char *buf, size_t bufsize);
idaman int ida_export atos(const char *str, sel_t *seg); //0-fail,1-ok(hex),2-ok(segment name or reg)


// a number to ascii using default radix with leading zeroes.
// used to output number in binary line prefixes

// get number of ascii characters required to represent
// a number with the specified number of bytes and radix
// radix==0: use default radix, usually 16
// nbytes==0: use default number of bytes, usually 4 or 8 depending on __EA64__
// return the answer length

#define MAX_NUMBUF (128+8) // 16-byte value in binary base (0b00101010...)
idaman size_t ida_export b2a_width(int nbytes, int radix);
idaman size_t ida_export b2a32(uint32 x, char *buf, size_t bufsize, int nbytes, int radix);
                                                        // nbytes: 1,2,3,4
idaman size_t ida_export b2a64(uint64 x, char *buf, size_t bufsize, int nbytes, int radix);
                                                        // nbytes: 1,2,3,4,8

// a number to ascii, the nicest representation of the number without leading zeroes
// can be used to output some numbers in the instructions
// return the answer length

idaman size_t ida_export btoa32(char *buf, size_t bufsize, uint32 x, int radix=0);
idaman size_t ida_export btoa64(char *buf, size_t bufsize, uint64 x, int radix=0);
idaman size_t ida_export btoa128(char *buf, size_t bufsize, uint128 x, int radix=0);
idaman size_t ida_export btoa_width(int nbytes, flags_t flag, int n); // get max width
#ifdef __EA64__
#define b2a b2a64
#define btoa btoa64
#define atob atob64
#else
#define b2a b2a32
#define btoa btoa32
#define atob atob32
#endif


// a instruction operand immediate number to ascii
// the main function to output numbers in the instruction operands
// it prints the number with or without the leading zeroes depending on the flags
// this function is called from OutValue(), please use OutValue() if you can

idaman size_t ida_export numop2str(char *buf,
                                   size_t bufsize,
                                   ea_t ea,
                                   int n,
                                   uint64 x,
                                   int nbytes,
                                   int radix=0);


// ascii to a number using the current assembler formats
// e.g. for ibmpc 12o is octal, 12h is hex etc.

idaman bool ida_export atob32(const char *str, uint32 *x);     // returns 1-ok
idaman bool ida_export atob64(const char *str, uint64 *x); // returns 1-ok


// auxillary function
// print displacement to a name (+disp or -disp) in the natural radix
//      buf  - pointer to the output buffer
//      end  - pointer to the end of the output buffer
//      disp - displacement to output. 0 leads to no modifications

idaman size_t ida_export print_disp(char *buf, char *end, adiff_t disp);


// String C-style conversions (convert \n to a newline and vice versa)

idaman THREAD_SAFE char *ida_export str2user(char *dst, const char *src, size_t dstsize); // make a user representation
idaman THREAD_SAFE char *ida_export user2str(char *dst, const char *src, size_t dstsize); // make an internal representation
idaman THREAD_SAFE char ida_export back_char(const char *&p);            // Translate char after '\\'
idaman THREAD_SAFE void ida_export qstr2user(qstring *dst, const qstring &src);
idaman THREAD_SAFE void ida_export user2qstr(qstring *dst, const qstring &src);


// ASCII <-> RADIX50 conversions
//      r - pointer to radix50 string
//      p - pointer to ascii string
//      k - number of elements in the input string
//            (element of radix50 string is a word)
//            (element of ascii   string is a character)
// return: number of elements left unprocessed in the input string
//         because the input string contains unconvertible elements.
//         0-ok, all elements are converted

idaman THREAD_SAFE int ida_export r50_to_asc(const ushort *r, char *p, int k);
int    THREAD_SAFE                asc_to_r50(const char *p, ushort *r, int k);


// the following characters are allowed in ASCII strings, i.e.
// in order to find end of a string IDA looks for a character
// which doesn't belong to this array:

idaman char ida_export_data AsciiStringChars[256+1];


// Pack/unpack 2, 4, and 8 byte numbers into character string
// These functions encode numbers using an encoding similar to UTF.
// The smaller is the number, the better is packing.

THREAD_SAFE inline uchar *idaapi pack_db(uchar *ptr, uchar *end, uchar x)
{
  if ( ptr < end )
    *ptr++ = x;
  return ptr;
}
THREAD_SAFE inline uchar idaapi unpack_db(const uchar **pptr, const uchar *end)
{
  const uchar *ptr = *pptr;
  uchar x = 0;
  if ( ptr < end )
    x = *ptr++;
  *pptr = ptr;
  return x;
}

idaman THREAD_SAFE uchar *ida_export pack_dw(uchar *ptr, uchar *end, uint16 x);
idaman THREAD_SAFE uchar *ida_export pack_dd(uchar *ptr, uchar *end, uint32 x);
idaman THREAD_SAFE uchar *ida_export pack_dq(uchar *ptr, uchar *end, uint64 x);
idaman THREAD_SAFE ushort ida_export unpack_dw(const uchar **pptr, const uchar *end);
idaman THREAD_SAFE uint32 ida_export unpack_dd(const uchar **pptr, const uchar *end);
idaman THREAD_SAFE uint64 ida_export unpack_dq(const uchar **pptr, const uchar *end);

THREAD_SAFE inline uchar *pack_ea(uchar *ptr, uchar *end, ea_t ea)
{
#ifdef __EA64__
  return pack_dq(ptr, end, ea);
#else
  return pack_dd(ptr, end, ea);
#endif
}
THREAD_SAFE inline ea_t unpack_ea(const uchar **ptr, const uchar *end)
{
#ifdef __EA64__
  return unpack_dq(ptr, end);
#else
  return unpack_dd(ptr, end);
#endif
}

// pack/unpack a string
// unpack_ds will allocate the output string in the dynamic memory. The caller
// should use qfree() to deallocate it.
//   empty_null - if true, then return NULL for empty strings
//                otherwise return an empty string (not NULL)

idaman THREAD_SAFE uchar *ida_export pack_ds(uchar *ptr, uchar *end, const char *x, size_t len=0);
idaman THREAD_SAFE char  *ida_export unpack_ds(const uchar **pptr, const uchar *end, bool empty_null);


// Unpack an object of a known size.
// Returns pointer to the destination buffer
// If any error, returns NULL.

THREAD_SAFE inline void *idaapi unpack_obj(const uchar **pptr, const uchar *end, void *destbuf, size_t destsize)
{
  const uchar *src = *pptr;
  if ( src+destsize > end )
    return NULL;
  *pptr = src + destsize;
  return memcpy(destbuf, src, destsize);
}


// Unpack an object of an unknown size (packed with append_buf)
// Returns pointer to the destination buffer, which is allocated in the dynamic memory.
// The caller should use qfree() to deallocate it.
// If any error, returns NULL.
// NB: zero size objects will return NULL too.

THREAD_SAFE inline void *idaapi unpack_buf(const uchar **pptr, const uchar *end, size_t *sz)
{
  size_t size = *sz = unpack_dd(pptr, end);
  if ( size == 0 )
    return NULL;
  void *dst = qalloc(size);
  if ( dst != NULL )
  {
    const uchar *src = *pptr;
    memcpy(dst, src, size);
    *pptr += size;
  }
  return dst;
}


// In-place versions of the above functions.
// They do not copy any data but just return a pointer to the object in the packed
// string. If any error, they may return NULL.

THREAD_SAFE inline const void *idaapi unpack_obj_inplace(const uchar **pptr, const uchar *end, size_t objsize)
{
  const uchar *ret = *pptr;
  if ( ret+objsize > end )
    return NULL;
  *pptr = ret + objsize;
  return ret;
}

THREAD_SAFE inline const void *idaapi unpack_buf_inplace(const uchar **pptr, const uchar *end, size_t *sz)
{
  size_t objsize = unpack_dd(pptr, end);
  const uchar *ret = *pptr;
  if ( ret+objsize > end )
    return NULL;
  *pptr = ret + objsize;
  *sz   = objsize;
  return ret;
}

THREAD_SAFE inline void unpack_eavec(ea_t ea, eavec_t &insns, const uchar **ptr, const uchar *end)
{
  ea_t old = ea;
  int n = unpack_dw(ptr, end);
  insns.resize(n);
  for ( int i=0; i < n; i++ )
  {
    old += unpack_ea(ptr, end);
    insns[i] = old;
  }
}

// unpack an LEB128 encoded (DWARF-3 style) unsigned value
THREAD_SAFE inline uint64 unpack_uleb128(const uchar **pptr, const uchar* end)
{
  uint64 result = 0;
  int  bit = 0;
  const uchar *ptr = *pptr;
  uchar byte;
  do
  {
    if ( ptr >= end )
    {
      result = uint64(-1);
      break;
    }

    byte = *ptr++;
    uint64 slice = byte & 0x7f;

    if ( bit >= 64 || ((slice << bit) >> bit) != slice )
    {
      result = uint64(-1);
      break;
    }
    else
    {
      result |= (slice << bit);
      bit += 7;
    }
  }
  while ( byte & 0x80 );
  *pptr = ptr;
  return result;
}

// unpack an LEB128 encoded (DWARF-3 style) signed value
THREAD_SAFE inline int64 unpack_sleb128(const uchar **pptr, const uchar *end)
{
  int64 result = 0;
  int bit = 0;
  const uchar *ptr = *pptr;
  uchar byte;
  do
  {
    if ( ptr >= end )
    {
      byte = 0;
      result = -1;
      break;
    }

    byte = *ptr++;
    uint64 slice = byte & 0x7f;

    if ( bit >= 64 || ((slice << bit) >> bit) != slice )
    {
      byte = 0;
      result = -1;
      break;
    }
    else
    {
      result |= (slice << bit);
      bit += 7;
    }
  }
  while ( byte & 0x80 );
  // sign extend negative numbers
  if ( (byte & 0x40) != 0 )
    result |= uint64(-1) << bit;
  *pptr = ptr;
  return result;
}

// packed sizes
static const int ea_packed_size = sizeof(ea_t) + sizeof(ea_t)/4; // 5 or 10 bytes
static const int dq_packed_size = 10;
static const int dd_packed_size = 5;
static const int dw_packed_size = 3;
inline int ds_packed_size(const char *s) { return s ? int(strlen(s)+dd_packed_size) : 1; }

//----------------------------------------------------------------------------
// Convenience functions to pack data into byte vectors
THREAD_SAFE inline void append_db(bytevec_t &v, uchar x)
{
  v.push_back(x);
}

THREAD_SAFE inline void append_obj(bytevec_t &v, const void *obj, size_t size)
{
  v.append(obj, size);
}

THREAD_SAFE inline void append_dw(bytevec_t &v, uint16 x)
{
  uchar packed[3];
  size_t len = pack_dw(packed, packed+sizeof(packed), x) - packed;
  append_obj(v, packed, len);
}

THREAD_SAFE inline void append_dd(bytevec_t &v, uint32 x)
{
  uchar packed[5];
  size_t len = pack_dd(packed, packed+sizeof(packed), x) - packed;
  append_obj(v, packed, len);
}

THREAD_SAFE inline void append_dq(bytevec_t &v, uint64 x)
{
  uchar packed[10];
  size_t len = pack_dq(packed, packed+sizeof(packed), x) - packed;
  append_obj(v, packed, len);
}

THREAD_SAFE inline void append_ea(bytevec_t &v, ea_t x)
{
  uchar packed[10];
  size_t len = pack_ea(packed, packed+sizeof(packed), x) - packed;
  append_obj(v, packed, len);
}

THREAD_SAFE inline void append_ds(bytevec_t &v, const char *x)
{
  size_t len = strlen(x);
#ifdef __X64__
  QASSERT(4, len <= 0xFFFFFFFF);
#endif
  append_dd(v, uint32(len));
  append_obj(v, x, len);
}

THREAD_SAFE inline void append_buf(bytevec_t &v, const void *buf, size_t len)
{
#ifdef __X64__
  QASSERT(5, len <= 0xFFFFFFFF);
#endif
  append_dd(v, uint32(len));
  append_obj(v, buf, len);
}

THREAD_SAFE inline void append_eavec(bytevec_t &v, ea_t ea, const eavec_t &insns)
{
  int n = (int)insns.size();
  append_dw(v, (ushort)n);
  ea_t old = ea;
  for ( int i=0; i < n; i++ )
  {
    ea_t nea = insns[i];
    append_ea(v, nea-old);
    old = nea;
  }
}

THREAD_SAFE inline char *unpack_str(const uchar **ptr, const uchar *end)
{
  char *str = (char *)*ptr;
  *ptr = (const uchar *)strchr(str, '\0') + 1;
  if ( *ptr > end )
    *ptr = end;
  return str;
}


//----------------------------------------------------------------------------
// Calculate CRC32 (polynom 0xEDB88320, zlib compatible).
// Note: in IDA versions before 6.0 a different, incompatible algorithm was used
idaman THREAD_SAFE uint32 ida_export calc_crc32(uint32 crc, const void *buf, size_t len);

// calculate an input source CRC32
idaman THREAD_SAFE uint32 ida_export calc_file_crc32(linput_t *fp);

// match a string with a regular expression
// returns: 0-no match, 1-match, -1-error
idaman int ida_export regex_match(const char *str, const char *pattern, bool sense_case);
#endif // SWIG

#ifndef NO_OBSOLETE_FUNCS
typedef idc_value_t value_t;
#endif

//----------------------------------------------------------------------------
// compatibility windows virtual keys to use in plugins which are not Qt aware (check the QT_AWARE flag)
// these keys are provided for compilation of older plugins that use windows virtual keys on all platforms.
// those constants are currently passed to cli_t->keydown and customview/CVH_KEYDOWN handlers.
#define IK_CANCEL              0x03
#define IK_BACK                0x08
#define IK_TAB                 0x09
#define IK_CLEAR               0x0C
#define IK_RETURN              0x0D
#define IK_SHIFT               0x10
#define IK_CONTROL             0x11
#define IK_MENU                0x12
#define IK_PAUSE               0x13
#define IK_CAPITAL             0x14
#define IK_KANA                0x15
#define IK_ESCAPE              0x1B
#define IK_MODECHANGE          0x1F
#define IK_SPACE               0x20
#define IK_PRIOR               0x21
#define IK_NEXT                0x22
#define IK_END                 0x23
#define IK_HOME                0x24
#define IK_LEFT                0x25
#define IK_UP                  0x26
#define IK_RIGHT               0x27
#define IK_DOWN                0x28
#define IK_SELECT              0x29
#define IK_PRINT               0x2A
#define IK_EXECUTE             0x2B
#define IK_SNAPSHOT            0x2C
#define IK_INSERT              0x2D
#define IK_DELETE              0x2E
#define IK_HELP                0x2F
#define IK_LWIN                0x5B
#define IK_RWIN                0x5C
#define IK_APPS                0x5D
#define IK_SLEEP               0x5F
#define IK_NUMPAD0             0x60
#define IK_NUMPAD1             0x61
#define IK_NUMPAD2             0x62
#define IK_NUMPAD3             0x63
#define IK_NUMPAD4             0x64
#define IK_NUMPAD5             0x65
#define IK_NUMPAD6             0x66
#define IK_NUMPAD7             0x67
#define IK_NUMPAD8             0x68
#define IK_NUMPAD9             0x69
#define IK_MULTIPLY            0x6A
#define IK_ADD                 0x6B
#define IK_SEPARATOR           0x6C
#define IK_SUBTRACT            0x6D
#define IK_DECIMAL             0x6E
#define IK_DIVIDE              0x6F
#define IK_F1                  0x70
#define IK_F2                  0x71
#define IK_F3                  0x72
#define IK_F4                  0x73
#define IK_F5                  0x74
#define IK_F6                  0x75
#define IK_F7                  0x76
#define IK_F8                  0x77
#define IK_F9                  0x78
#define IK_F10                 0x79
#define IK_F11                 0x7A
#define IK_F12                 0x7B
#define IK_F13                 0x7C
#define IK_F14                 0x7D
#define IK_F15                 0x7E
#define IK_F16                 0x7F
#define IK_F17                 0x80
#define IK_F18                 0x81
#define IK_F19                 0x82
#define IK_F20                 0x83
#define IK_F21                 0x84
#define IK_F22                 0x85
#define IK_F23                 0x86
#define IK_F24                 0x87
#define IK_NUMLOCK             0x90
#define IK_SCROLL              0x91
#define IK_OEM_FJ_MASSHOU      0x93
#define IK_OEM_FJ_TOUROKU      0x94
#define IK_LSHIFT              0xA0
#define IK_RSHIFT              0xA1
#define IK_LCONTROL            0xA2
#define IK_RCONTROL            0xA3
#define IK_LMENU               0xA4
#define IK_RMENU               0xA5
#define IK_BROWSER_BACK        0xA6
#define IK_BROWSER_FORWARD     0xA7
#define IK_BROWSER_REFRESH     0xA8
#define IK_BROWSER_STOP        0xA9
#define IK_BROWSER_SEARCH      0xAA
#define IK_BROWSER_FAVORITES   0xAB
#define IK_BROWSER_HOME        0xAC
#define IK_VOLUME_MUTE         0xAD
#define IK_VOLUME_DOWN         0xAE
#define IK_VOLUME_UP           0xAF
#define IK_MEDIA_NEXT_TRACK    0xB0
#define IK_MEDIA_PREV_TRACK    0xB1
#define IK_MEDIA_STOP          0xB2
#define IK_MEDIA_PLAY_PAUSE    0xB3
#define IK_LAUNCH_MAIL         0xB4
#define IK_LAUNCH_MEDIA_SELECT 0xB5
#define IK_LAUNCH_APP1         0xB6
#define IK_LAUNCH_APP2         0xB7
#define IK_OEM_1               0xBA
#define IK_OEM_PLUS            0xBB
#define IK_OEM_COMMA           0xBC
#define IK_OEM_MINUS           0xBD
#define IK_OEM_PERIOD          0xBE
#define IK_OEM_2               0xBF
#define IK_OEM_3               0xC0
#define IK_OEM_4               0xDB
#define IK_OEM_5               0xDC
#define IK_OEM_6               0xDD
#define IK_OEM_7               0xDE
#define IK_OEM_102             0xE2
#define IK_PLAY                0xFA
#define IK_ZOOM                0xFB
#define IK_OEM_CLEAR           0xFE

#pragma pack(pop)
#endif // __KERNWIN_HPP
