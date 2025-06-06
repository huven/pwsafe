/*
 * Copyright (c) 2003-2025 Rony Shapiro <ronys@pwsafe.org>.
 * All rights reserved. Use of the code is allowed under the
 * Artistic License 2.0 terms, as specified in the LICENSE file
 * distributed with this code, or available from
 * http://www.opensource.org/licenses/artistic-license-2.0.php
 */

/** \file SafeCombinationSetupDlg.cpp
*
*/

// Generated by DialogBlocks, Wed 21 Jan 2009 09:07:57 PM IST

// For compilers that support precompilation, includes "wx/wx.h".
#include "wx/wxprec.h"

#ifndef WX_PRECOMP
#include "wx/wx.h"
#endif

#ifdef __WXMSW__
#include <wx/msw/msvcrt.h>
#endif

////@begin includes
////@end includes
#include "core/PWCharPool.h"
#include "ExternalKeyboardButton.h"
#include "SafeCombinationSetupDlg.h"
#include "wxUtilities.h"          // for ApplyPasswordFont()

#ifndef NO_YUBI
////@begin XPM images
#include "graphics/Yubikey-button.xpm"
////@end XPM images
#endif

/*!
 * SafeCombinationSetupDlg type definition
 */

IMPLEMENT_DYNAMIC_CLASS( SafeCombinationSetupDlg, wxDialog )

/*!
 * SafeCombinationSetupDlg event table definition
 */

BEGIN_EVENT_TABLE( SafeCombinationSetupDlg, wxDialog )

////@begin SafeCombinationSetupDlg event table entries
#ifndef NO_YUBI
  EVT_BUTTON( ID_YUBIBTN, SafeCombinationSetupDlg::OnYubibtnClick )

EVT_TIMER(POLLING_TIMER_ID, SafeCombinationSetupDlg::OnPollingTimer)
#endif

  EVT_BUTTON( wxID_OK, SafeCombinationSetupDlg::OnOkClick )

  EVT_BUTTON( wxID_CANCEL, SafeCombinationSetupDlg::OnCancelClick )

////@end SafeCombinationSetupDlg event table entries
END_EVENT_TABLE()

/*!
 * SafeCombinationSetupDlg constructors
 */
SafeCombinationSetupDlg::SafeCombinationSetupDlg(wxWindow *parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
  wxASSERT(!parent || parent->IsTopLevel());
////@begin SafeCombinationSetupDlg creation
  SetExtraStyle(wxWS_EX_BLOCK_EVENTS);
  wxDialog::Create( parent, id, caption, pos, size, style );

  CreateControls();
  if (GetSizer())
  {
    GetSizer()->SetSizeHints(this);
  }
  Centre();
////@end SafeCombinationSetupDlg creation
#ifndef NO_YUBI
  SetupMixin(this, FindWindow(ID_YUBIBTN), FindWindow(ID_YUBISTATUS));
#endif
}

SafeCombinationSetupDlg* SafeCombinationSetupDlg::Create(wxWindow *parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
  return new SafeCombinationSetupDlg(parent, id, caption, pos, size, style);
}

/*!
 * SafeCombinationSetupDlg destructor
 */

SafeCombinationSetupDlg::~SafeCombinationSetupDlg()
{
////@begin SafeCombinationSetupDlg destruction
////@end SafeCombinationSetupDlg destruction
}

/*!
 * Control creation for SafeCombinationSetupDlg
 */

void SafeCombinationSetupDlg::CreateControls()
{
////@begin SafeCombinationSetupDlg content construction
  auto* mainSizer = new wxBoxSizer(wxVERTICAL);
  SetSizer(mainSizer);

  auto* itemStaticText3 = new wxStaticText(this, wxID_STATIC,
    _("The Master Password will be used to protect the new password database file."),
    wxDefaultPosition, wxDefaultSize, 0
  );
  mainSizer->Add(itemStaticText3, 0, wxALL|wxEXPAND, 12);

  m_PasswordEntryCtrl = wxUtilities::CreateLabeledSafeCombinationCtrl(this, ID_PASSWORD, _("Master Password"), &m_password, true);
  auto *hBoxSizer = new wxBoxSizer(wxHORIZONTAL);
  m_strengthMeter = new StrengthMeter(this);
  m_PasswordEntryCtrl->SetTextChangedHandler(
    [&](const StringX& password) {
      m_strengthMeter->SetStrength(
        CPasswordCharPool::CalculatePasswordStrength(password)
      );
    }
  );
  hBoxSizer->Add(m_strengthMeter, 1, wxALIGN_LEFT|wxEXPAND, 0);
  hBoxSizer->AddSpacer(
    29 /*eye icon width*/ + 11 /*margin*/
#ifdef __WXOSX__
    + 9 /*extra margin*/
#endif
  );
  mainSizer->Add(hBoxSizer, 0, wxALIGN_LEFT|wxLEFT|wxBOTTOM|wxRIGHT|wxEXPAND, 12);
  m_VerifyEntryCtrl = wxUtilities::CreateLabeledSafeCombinationCtrl(this, ID_VERIFY, _("Confirmation"), &m_verify, false);

#ifndef NO_YUBI
  auto yubiControls = wxUtilities::CreateYubiKeyControls(this, ID_YUBIBTN, ID_YUBISTATUS);
  m_YubiBtn = wxUtilities::GetYubiKeyButtonControl(yubiControls);
  m_yubiStatusCtrl = wxUtilities::GetYubiKeyStatusControl(yubiControls);
#endif

  mainSizer->AddStretchSpacer();

  auto* horizontalBoxSizer = new wxBoxSizer(wxHORIZONTAL);
  mainSizer->Add(horizontalBoxSizer, 0, wxEXPAND|wxLEFT|wxBOTTOM|wxRIGHT, 12);

  auto* itemStdDialogButtonSizer11 = new wxStdDialogButtonSizer;
  horizontalBoxSizer->Add(itemStdDialogButtonSizer11, 1, wxEXPAND|wxALL, 5);

  auto* itemButton12 = new wxButton(this, wxID_OK, _("&OK"), wxDefaultPosition, wxDefaultSize, 0 );
  itemButton12->SetDefault();
  itemStdDialogButtonSizer11->AddButton(itemButton12);

  auto* itemButton13 = new wxButton(this, wxID_CANCEL, _("&Cancel"), wxDefaultPosition, wxDefaultSize, 0 );
  itemStdDialogButtonSizer11->AddButton(itemButton13);

  auto* itemButton14 = new wxButton(this, wxID_HELP, _("&Help"), wxDefaultPosition, wxDefaultSize, 0 );
  itemStdDialogButtonSizer11->AddButton(itemButton14);

  itemStdDialogButtonSizer11->Realize();

  if (wxUtilities::IsVirtualKeyboardSupported()) {
    auto *keyboardButton = new ExternalKeyboardButton(this);
    keyboardButton->SetFocusOnSafeCombinationCtrl(m_PasswordEntryCtrl);
    horizontalBoxSizer->Add(keyboardButton, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5);
  }

  // Set validators
  m_PasswordEntryCtrl->SetValidatorTarget(&m_password);
  m_VerifyEntryCtrl->SetValidatorTarget(&m_verify);
////@end SafeCombinationSetupDlg content construction
}

/*!
 * Should we show tooltips?
 */

bool SafeCombinationSetupDlg::ShowToolTips()
{
  return true;
}

/*!
 * Get bitmap resources
 */

#ifndef NO_YUBI
wxBitmap SafeCombinationSetupDlg::GetBitmapResource( const wxString& name )
{
  // Bitmap retrieval
////@begin SafeCombinationSetupDlg bitmap retrieval
  if (name == _T("graphics/Yubikey-button.xpm"))
  {
    wxBitmap bitmap(Yubikey_button_xpm);
    return bitmap;
  }
  return wxNullBitmap;
////@end SafeCombinationSetupDlg bitmap retrieval
}
#endif

/*!
 * Get icon resources
 */

wxIcon SafeCombinationSetupDlg::GetIconResource( const wxString& WXUNUSED(name) )
{
  // Icon retrieval
////@begin SafeCombinationSetupDlg icon retrieval
  return wxNullIcon;
////@end SafeCombinationSetupDlg icon retrieval
}

/*!
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK
 */

void SafeCombinationSetupDlg::OnOkClick(wxCommandEvent& WXUNUSED(evt))
{
  if (Validate() && TransferDataFromWindow()) {
    if (m_password != m_verify) {
      wxMessageDialog err(this, _("The two entries do not match."),
                          _("Mismatching Master Password"), wxOK | wxICON_EXCLAMATION);
      err.ShowModal();
      return;
    }
    if (m_password.empty()) {
      wxMessageDialog err(this, _("Enter the key and verify it."),
                          _("Empty Master Password"), wxOK | wxICON_EXCLAMATION);
      err.ShowModal();
      return;
    }
    if (CheckPasswordStrengthAndWarn(this, m_password)) {
      EndModal(wxID_OK);
    }
  }
}

/*!
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL
 */

void SafeCombinationSetupDlg::OnCancelClick( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL in SafeCombinationSetupDlg.
  // Before editing this code, remove the block markers.
  event.Skip();
////@end wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL in SafeCombinationSetupDlg.
}

#ifndef NO_YUBI
void SafeCombinationSetupDlg::OnPollingTimer(wxTimerEvent &evt)
{
  if (evt.GetId() == POLLING_TIMER_ID) {
    HandlePollingTimer(); // in YubiMixin
  }
}

/*!
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_YUBIBTN
 */

void SafeCombinationSetupDlg::OnYubibtnClick(wxCommandEvent& WXUNUSED(event))
{
  m_PasswordEntryCtrl->AllowEmptyCombinationOnce();
  m_VerifyEntryCtrl->AllowEmptyCombinationOnce();
  if (Validate() && TransferDataFromWindow()) {
    if (m_password != m_verify) {
      wxMessageDialog err(this, _("The two entries do not match."),
                          _("Mismatching entries"), wxOK | wxICON_EXCLAMATION);
      err.ShowModal();
      return;
    }
    // A blank password with a Yubikey is a common use case
    if (!m_password.empty() && !CheckPasswordStrengthAndWarn(this, m_password)) {
      return;
    }

    StringX response;
    bool oldYubiChallenge = ::wxGetKeyState(WXK_SHIFT); // for pre-0.94 databases
    if (PerformChallengeResponse(this, m_password, response, oldYubiChallenge)) {
      m_password = response.c_str();
      EndModal(wxID_OK);
    }
  }
}
#endif
