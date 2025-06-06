/*
 * Copyright (c) 2003-2025 Rony Shapiro <ronys@pwsafe.org>.
 * All rights reserved. Use of the code is allowed under the
 * Artistic License 2.0 terms, as specified in the LICENSE file
 * distributed with this code, or available from
 * http://www.opensource.org/licenses/artistic-license-2.0.php
 */

/** \file ToolbarButtons.h
*
*/

#ifndef _TOOLBARBUTTONS_H_
#define _TOOLBARBUTTONS_H_

#include "./graphics/toolbar/new/new.xpm"
#include "./graphics/toolbar/new/new_disabled.xpm"
#include "./graphics/toolbar/new/open.xpm"
#include "./graphics/toolbar/new/open_disabled.xpm"
#include "./graphics/toolbar/new/close.xpm"
#include "./graphics/toolbar/new/close_disabled.xpm"
#include "./graphics/toolbar/new/lock.xpm"
#include "./graphics/toolbar/new/lock_disabled.xpm"
#include "./graphics/toolbar/new/unlock.xpm"
#include "./graphics/toolbar/new/unlock_disabled.xpm"
#include "./graphics/toolbar/new/save.xpm"
#include "./graphics/toolbar/new/save_disabled.xpm"
#include "./graphics/toolbar/new/copypassword.xpm"
#include "./graphics/toolbar/new/copypassword_disabled.xpm"
#include "./graphics/toolbar/new/copyuser.xpm"
#include "./graphics/toolbar/new/copyuser_disabled.xpm"
#include "./graphics/toolbar/new/copyauthcode.xpm"
#include "./graphics/toolbar/new/copyauthcode_disabled.xpm"
#include "./graphics/toolbar/new/displayauthcode.xpm"
#include "./graphics/toolbar/new/displayauthcode_disabled.xpm"
#include "./graphics/toolbar/new/copynotes.xpm"
#include "./graphics/toolbar/new/copynotes_disabled.xpm"
#include "./graphics/toolbar/new/clearclipboard.xpm"
#include "./graphics/toolbar/new/clearclipboard_disabled.xpm"
#include "./graphics/toolbar/new/autotype.xpm"
#include "./graphics/toolbar/new/autotype_disabled.xpm"
#include "./graphics/toolbar/new/browseurl.xpm"
#include "./graphics/toolbar/new/browseurl_disabled.xpm"
#include "./graphics/toolbar/new/sendemail.xpm"
#include "./graphics/toolbar/new/sendemail_disabled.xpm"
#include "./graphics/toolbar/new/add.xpm"
#include "./graphics/toolbar/new/add_disabled.xpm"
#include "./graphics/toolbar/new/viewedit.xpm"
#include "./graphics/toolbar/new/viewedit_disabled.xpm"
#include "./graphics/toolbar/new/delete.xpm"
#include "./graphics/toolbar/new/delete_disabled.xpm"
#include "./graphics/toolbar/new/expandall.xpm"
#include "./graphics/toolbar/new/expandall_disabled.xpm"
#include "./graphics/toolbar/new/collapseall.xpm"
#include "./graphics/toolbar/new/collapseall_disabled.xpm"
#include "./graphics/toolbar/new/options.xpm"
#include "./graphics/toolbar/new/options_disabled.xpm"
#include "./graphics/toolbar/new/help.xpm"
#include "./graphics/toolbar/new/help_disabled.xpm"

// Unreferenced bitmaps are commented
//#include "./graphics/toolbar/new/addgroup.xpm"
//#include "./graphics/toolbar/new/addgroup_disabled.xpm"
//#include "./graphics/toolbar/new/applyfilter.xpm"
//#include "./graphics/toolbar/new/applyfilter_disabled.xpm"
//#include "./graphics/toolbar/new/compare.xpm"
//#include "./graphics/toolbar/new/compare_disabled.xpm"
//#include "./graphics/toolbar/new/exporttext.xpm"
//#include "./graphics/toolbar/new/exporttext_disabled.xpm"
//#include "./graphics/toolbar/new/exportXML.xpm"
//#include "./graphics/toolbar/new/exportXML_disabled.xpm"
//#include "./graphics/toolbar/new/importtext.xpm"
//#include "./graphics/toolbar/new/importtext_disabled.xpm"
//#include "./graphics/toolbar/new/importXML.xpm"
//#include "./graphics/toolbar/new/importXML_disabled.xpm"
//#include "./graphics/toolbar/new/listtree.xpm"
//#include "./graphics/toolbar/new/listtree_disabled.xpm"
//#include "./graphics/toolbar/new/managefilters.xpm"
//#include "./graphics/toolbar/new/managefilters_disabled.xpm"
//#include "./graphics/toolbar/new/merge.xpm"
//#include "./graphics/toolbar/new/merge_disabled.xpm"
//#include "./graphics/toolbar/new/passwordchars.xpm"
//#include "./graphics/toolbar/new/passwordchars_disabled.xpm"
//#include "./graphics/toolbar/new/redo.xpm"
//#include "./graphics/toolbar/new/redo_disabled.xpm"
//#include "./graphics/toolbar/new/runcmd.xpm"
//#include "./graphics/toolbar/new/runcmd_disabled.xpm"
//#include "./graphics/toolbar/new/saveas.xpm"
//#include "./graphics/toolbar/new/saveas_disabled.xpm"
//#include "./graphics/toolbar/new/setfilter.xpm"
//#include "./graphics/toolbar/new/setfilter_disabled.xpm"
//#include "./graphics/toolbar/new/synchronize.xpm"
//#include "./graphics/toolbar/new/synchronize_disabled.xpm"
//#include "./graphics/toolbar/new/undo.xpm"
//#include "./graphics/toolbar/new/undo_disabled.xpm"
//#include "./graphics/toolbar/new/viewreports.xpm"
//#include "./graphics/toolbar/new/viewreports_disabled.xpm"

//-- classic bitmaps...
#include "./graphics/toolbar/classic/new.xpm"
#include "./graphics/toolbar/classic/new_disabled.xpm"
#include "./graphics/toolbar/classic/open.xpm"
#include "./graphics/toolbar/classic/open_disabled.xpm"
#include "./graphics/toolbar/classic/close.xpm"
#include "./graphics/toolbar/classic/close_disabled.xpm"
#include "./graphics/toolbar/classic/lock.xpm"
#include "./graphics/toolbar/classic/lock_disabled.xpm"
#include "./graphics/toolbar/classic/unlock.xpm"
#include "./graphics/toolbar/classic/unlock_disabled.xpm"
#include "./graphics/toolbar/classic/save.xpm"
#include "./graphics/toolbar/classic/save_disabled.xpm"
#include "./graphics/toolbar/classic/copypassword.xpm"
#include "./graphics/toolbar/classic/copypassword_disabled.xpm"
#include "./graphics/toolbar/classic/copyuser.xpm"
#include "./graphics/toolbar/classic/copyuser_disabled.xpm"
#include "./graphics/toolbar/classic/copyauthcode.xpm"
#include "./graphics/toolbar/classic/copyauthcode_disabled.xpm"
#include "./graphics/toolbar/classic/displayauthcode.xpm"
#include "./graphics/toolbar/classic/displayauthcode_disabled.xpm"
#include "./graphics/toolbar/classic/copynotes.xpm"
#include "./graphics/toolbar/classic/copynotes_disabled.xpm"
#include "./graphics/toolbar/classic/clearclipboard.xpm"
#include "./graphics/toolbar/classic/clearclipboard_disabled.xpm"
#include "./graphics/toolbar/classic/autotype.xpm"
#include "./graphics/toolbar/classic/autotype_disabled.xpm"
#include "./graphics/toolbar/classic/browseurl.xpm"
#include "./graphics/toolbar/classic/browseurl_disabled.xpm"
#include "./graphics/toolbar/classic/sendemail.xpm"
#include "./graphics/toolbar/classic/sendemail_disabled.xpm"
#include "./graphics/toolbar/classic/add.xpm"
#include "./graphics/toolbar/classic/add_disabled.xpm"
#include "./graphics/toolbar/classic/viewedit.xpm"
#include "./graphics/toolbar/classic/viewedit_disabled.xpm"
#include "./graphics/toolbar/classic/delete.xpm"
#include "./graphics/toolbar/classic/delete_disabled.xpm"
#include "./graphics/toolbar/classic/expandall.xpm"
#include "./graphics/toolbar/classic/expandall_disabled.xpm"
#include "./graphics/toolbar/classic/collapseall.xpm"
#include "./graphics/toolbar/classic/collapseall_disabled.xpm"
#include "./graphics/toolbar/classic/options.xpm"
#include "./graphics/toolbar/classic/options_disabled.xpm"
#include "./graphics/toolbar/classic/help.xpm"
#include "./graphics/toolbar/classic/help_disabled.xpm"

// Unreferenced bitmaps are commented
//#include "./graphics/toolbar/classic/addgroup.xpm"
//#include "./graphics/toolbar/classic/addgroup_disabled.xpm"
//#include "./graphics/toolbar/classic/applyfilter.xpm"
//#include "./graphics/toolbar/classic/applyfilter_disabled.xpm"
//#include "./graphics/toolbar/classic/compare.xpm"
//#include "./graphics/toolbar/classic/compare_disabled.xpm"
//#include "./graphics/toolbar/classic/exporttext.xpm"
//#include "./graphics/toolbar/classic/exporttext_disabled.xpm"
//#include "./graphics/toolbar/classic/exportXML.xpm"
//#include "./graphics/toolbar/classic/exportXML_disabled.xpm"
//#include "./graphics/toolbar/classic/importtext.xpm"
//#include "./graphics/toolbar/classic/importtext_disabled.xpm"
//#include "./graphics/toolbar/classic/importXML.xpm"
//#include "./graphics/toolbar/classic/importXML_disabled.xpm"
//#include "./graphics/toolbar/classic/listtree.xpm"
//#include "./graphics/toolbar/classic/listtree_disabled.xpm"
//#include "./graphics/toolbar/classic/managefilters.xpm"
//#include "./graphics/toolbar/classic/managefilters_disabled.xpm"
//#include "./graphics/toolbar/classic/merge.xpm"
//#include "./graphics/toolbar/classic/merge_disabled.xpm"
//#include "./graphics/toolbar/classic/passwordchars.xpm"
//#include "./graphics/toolbar/classic/passwordchars_disabled.xpm"
//#include "./graphics/toolbar/classic/redo.xpm"
//#include "./graphics/toolbar/classic/redo_disabled.xpm"
//#include "./graphics/toolbar/classic/runcmd.xpm"
//#include "./graphics/toolbar/classic/runcmd_disabled.xpm"
//#include "./graphics/toolbar/classic/saveas.xpm"
//#include "./graphics/toolbar/classic/saveas_disabled.xpm"
//#include "./graphics/toolbar/classic/setfilter.xpm"
//#include "./graphics/toolbar/classic/setfilter_disabled.xpm"
//#include "./graphics/toolbar/classic/synchronize.xpm"
//#include "./graphics/toolbar/classic/synchronize_disabled.xpm"
//#include "./graphics/toolbar/classic/undo.xpm"
//#include "./graphics/toolbar/classic/undo_disabled.xpm"
//#include "./graphics/toolbar/classic/viewreports.xpm"
//#include "./graphics/toolbar/classic/viewreports_disabled.xpm"

enum {ID_SEPARATOR = -1};

#define PWS_TOOLBAR_BITMAPS(n)  wxCONCAT(n, _xpm),                              \
                                wxCONCAT(wxCONCAT(n, _disabled), _xpm),         \
                                wxCONCAT(wxCONCAT(classic_, n), _xpm),          \
                                wxCONCAT(wxCONCAT(classic_, n), _disabled_xpm)
#define SEPARATOR {ID_SEPARATOR, wxEmptyString, wxEmptyString, nullptr, nullptr, nullptr, nullptr}

struct _PwsToolbarInfo {
  int id;
  const wxString toollabel;
  const wxString tooltip;
  const char* const* const bitmap_normal;
  const char* const* const bitmap_disabled;
  const char* const* const bitmap_classic;
  const char* const* const bitmap_classic_disabled;

  bool IsSeparator() const
  {
    return (id == ID_SEPARATOR);
  }

  bool UseNewToolbarStyle() const
  {
    return PWSprefs::GetInstance()->GetPref(PWSprefs::UseNewToolbar);
  }

  /**
   * Provides the bitmap that represents an enabled toolbar item in the new or classic style, depending on user preferences.
   * @return toolbar item bitmap
   */
  wxBitmap GetBitmapForEnabledButton() const
  {
    return UseNewToolbarStyle() ? bitmap_normal : bitmap_classic;
  }

  /**
   * Provides the bitmap that represents an disabled toolbar item in the new or classic style, depending on user preferences.
   * @return toolbar item bitmap
   */
  wxBitmap GetBitmapForDisabledButton() const
  {
    return UseNewToolbarStyle() ? bitmap_disabled : bitmap_classic_disabled;
  }

  // Following ctor's required to shut up some compiler warnings
_PwsToolbarInfo() : id(0), toollabel(wxEmptyString), tooltip(wxEmptyString), bitmap_normal(nullptr), bitmap_disabled(nullptr),
    bitmap_classic(nullptr), bitmap_classic_disabled(nullptr) {}
_PwsToolbarInfo(int aid, const wxString &atoollabel, const wxString &atooltip, const char* const* abitmap_normal,
                const char* const* abitmap_disabled, const char* const* abitmap_classic, const char* const* abitmap_classic_disabled) :
  id(aid), toollabel(atoollabel), tooltip(atooltip), bitmap_normal(abitmap_normal), bitmap_disabled(abitmap_disabled),
    bitmap_classic(abitmap_classic), bitmap_classic_disabled(abitmap_classic_disabled) {}
} PwsToolbarButtons[] =

{
          { wxID_NEW,          _("New"),             _("Make New Database"),            PWS_TOOLBAR_BITMAPS(new)            },
          { wxID_OPEN,         _("Open"),            _("Open Another Database"),        PWS_TOOLBAR_BITMAPS(open)           },
          { wxID_CLOSE,        _("Close"),           _("Close Database"),               PWS_TOOLBAR_BITMAPS(close)          },
          { ID_LOCK_SAFE,      _("Lock"),            _("Lock Database"),                PWS_TOOLBAR_BITMAPS(lock)           },
          { ID_UNLOCK_SAFE,    _("Unlock"),          _("Unlock Database"),              PWS_TOOLBAR_BITMAPS(unlock)         },
          { wxID_SAVE,         _("Save"),            _("Save Database"),                PWS_TOOLBAR_BITMAPS(save)           },
          SEPARATOR,
          { ID_COPYPASSWORD,   _("Password"),        _("Copy Password to Clipboard"),   PWS_TOOLBAR_BITMAPS(copypassword)   },
          { ID_COPYUSERNAME,   _("Username"),        _("Copy Username to Clipboard"),   PWS_TOOLBAR_BITMAPS(copyuser)       },
          { ID_COPYAUTHCODE,   _("Auth Code"),       _("Copy Auth Code to Clipboard"),  PWS_TOOLBAR_BITMAPS(copyauthcode)   },
          { ID_SHOWAUTHCODE,   _("Display Auth"),    _("Display Auth Code"),            PWS_TOOLBAR_BITMAPS(displayauthcode)},
          { ID_COPYNOTESFLD,   _("Notes"),           _("Copy Notes to Clipboard"),      PWS_TOOLBAR_BITMAPS(copynotes)      },
          { ID_CLEARCLIPBOARD, _("Clr Clipboard"),   _("Clear the clipboard contents"), PWS_TOOLBAR_BITMAPS(clearclipboard) },
          SEPARATOR,
          { ID_AUTOTYPE,       _("Autotype"),        _("Perform Autotype"),             PWS_TOOLBAR_BITMAPS(autotype)       },
          { ID_BROWSEURL,      _("Browse URL"),      _("Browse to URL"),                PWS_TOOLBAR_BITMAPS(browseurl)      },
          { ID_SENDEMAIL,      _("Send Email"),      _("Send Email"),                   PWS_TOOLBAR_BITMAPS(sendemail)      },
          SEPARATOR,
          { wxID_ADD,          _("Add"),             _("Add New Entry"),                PWS_TOOLBAR_BITMAPS(add)            },
          { ID_EDIT,           _("Edit"),            _("Edit an Entry"),                PWS_TOOLBAR_BITMAPS(viewedit)       },
          SEPARATOR,
          { wxID_DELETE,       _("Delete"),          _("Delete an Entry"),              PWS_TOOLBAR_BITMAPS(delete)         },
          SEPARATOR,
          { ID_EXPANDALL,      _("Expand"),          _("Expand All"),                   PWS_TOOLBAR_BITMAPS(expandall)      },
          { ID_COLLAPSEALL,    _("Collapse"),        _("Collapse All"),                 PWS_TOOLBAR_BITMAPS(collapseall)    },
          SEPARATOR,
          { wxID_PREFERENCES,  _("Options"),         _("Options"),                      PWS_TOOLBAR_BITMAPS(options)        },
          SEPARATOR,
          { wxID_HELP,         _("Help"),            _("Help"),                         PWS_TOOLBAR_BITMAPS(help)           }
};

#undef SEPARATOR

#endif // _TOOLBARBUTTONS_H_
