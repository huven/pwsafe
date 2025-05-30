/*
* Copyright (c) 2003-2025 Rony Shapiro <ronys@pwsafe.org>.
* All rights reserved. Use of the code is allowed under the
* Artistic License 2.0 terms, as specified in the LICENSE file
* distributed with this code, or available from
* http://www.opensource.org/licenses/artistic-license-2.0.php
*/
/// \file Fonts.cpp
//-----------------------------------------------------------------------------

#include "stdafx.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#include "Fonts.h"
#include "winutils.h"

#include "os/env.h"

#include <usp10.h>    // for support of Unicode character (Uniscribe)
#include <vector>

Fonts *Fonts::self = nullptr;

// 12pt Consolas Regular
static LOGFONT dfltPasswordLogfont = {
  -16, 0, 0, 0, FW_NORMAL, 0, 0, 0, 0, 0, 0, 0, FF_MODERN | FIXED_PITCH,
  L'C', L'o', L'n', L's', L'o', L'l', L'a', L's', L'\0'};

// 10pt Segoe UI Regular
static LOGFONT dfltTreeListFont = {
  -13, 0, 0, 0, FW_NORMAL, 0, 0, 0, 0, 0, 0, 0, FF_MODERN | FF_SWISS,
  L'S', L'e', L'g', L'o', L'e', L' ', L'U', L'I', L'\0'};

// 10pt Segoe UI Regular
static LOGFONT dfltAddEditLogfont = {
  -13, 0, 0, 0, FW_NORMAL, 0, 0, 0, 0, 0, 0, 0, FF_MODERN | FF_SWISS,
  L'S', L'e', L'g', L'o', L'e', L' ', L'U', L'I', L'\0'};

// 10pt Segoe UI Regular
static LOGFONT dfltNotesLogfont = {
  -13, 0, 0, 0, FW_NORMAL, 0, 0, 0, 0, 0, 0, 0, FF_MODERN | FF_SWISS,
  L'S', L'e', L'g', L'o', L'e', L' ', L'U', L'I', L'\0'};

// Bug in MS TreeCtrl and CreateDragImage. During Drag, it doesn't show
// the entry's text as well as the drag image if the font is not MS Sans Serif !!!!
static LOGFONT DragFixLogfont = {
  -16, 0, 0, 0, FW_NORMAL, 0, 0, 0, 0, 0, 0, 0, DEFAULT_PITCH | FF_SWISS,
  L'M', L'S', L' ', L'S', L'a', L'n', L's', L' ', L'S', L'e', L'r', L'i', L'f', L'\0'};

static void tweakFontSizes()
{
  const UINT defDPI = WinUtil::defDPI;
  const UINT curDPI = WinUtil::GetDPI();

  auto adjust = [&defDPI, &curDPI](LONG& height)
  {
    height = (height * static_cast<LONG>(curDPI)) / static_cast<LONG>(defDPI);
  };

  adjust(dfltPasswordLogfont.lfHeight);
  adjust(dfltTreeListFont.lfHeight);
  adjust(dfltAddEditLogfont.lfHeight);
  adjust(dfltNotesLogfont.lfHeight);
  adjust(DragFixLogfont.lfHeight);
}

Fonts *Fonts::GetInstance()
{
  tweakFontSizes();
  if (self == nullptr) {
    self = new Fonts();
  }
  return self;
}

void Fonts::DeleteInstance()
{
  if (m_pTreeListFont != nullptr) {
    m_pTreeListFont->DeleteObject();
    delete m_pTreeListFont;
    m_pTreeListFont = nullptr;
  }
  if (m_pAddEditFont != nullptr) {
    m_pAddEditFont->DeleteObject();
    delete m_pAddEditFont;
    m_pAddEditFont = nullptr;
  }
  if (m_pItalicTreeListFont != nullptr) {
    m_pItalicTreeListFont->DeleteObject();
    delete m_pItalicTreeListFont;
    m_pItalicTreeListFont = nullptr;
  }
  if (m_pItalicAddEditFont != nullptr) {
    m_pItalicAddEditFont->DeleteObject();
    delete m_pItalicAddEditFont;
    m_pItalicAddEditFont = nullptr;
  }
  if (m_pDragFixFont != nullptr) {
    m_pDragFixFont->DeleteObject();
    delete m_pDragFixFont;
    m_pDragFixFont = nullptr;
  }
  if (m_pPasswordFont != nullptr) {
    m_pPasswordFont->DeleteObject();
    delete m_pPasswordFont;
    m_pPasswordFont = nullptr;
  }
  if (m_pNotesFont != nullptr) {
    m_pNotesFont->DeleteObject();
    delete m_pNotesFont;
    m_pNotesFont = nullptr;
  }
  delete self;
  self = nullptr;
}

std::wstring Utf32ToUtf16(uint32_t codepoint)
{
  wchar_t wc[3];
  if (codepoint < 0x10000) {
    // Length 1
    wc[0] = static_cast<wchar_t>(codepoint);
    wc[1] = wc[2] = 0;
  } else {
    if (codepoint <= 0x10FFFF) {
      codepoint -= 0x10000;
      // Length 2
      wc[0] = static_cast<unsigned short>(codepoint >> 10) + static_cast<unsigned short>(0xD800);
      wc[1] = static_cast<unsigned short>(codepoint & 0x3FF) + static_cast<unsigned short>(0xDC00);
      wc[2] = 0;
    } else {
      // Length 1
      wc[0] = 0xFFFD;
      wc[1] = wc[2] = 0;
    }
  }
  std::wstring s = wc;
  return s;
}

Fonts::Fonts() : MODIFIED_COLOR(RGB(0, 0, 128)),
  m_bProtectSymbolSupportedTreeList(true), m_bProtectSymbolSupportedAddEdit(true),
  m_bAttachmentSymbolSupportedTreeList(true), m_bAttachmentSymbolSupportedAddEdit(true)
{
  m_pTreeListFont = new CFont;
  m_pAddEditFont = new CFont;
  m_pDragFixFont = new CFont;
  m_pPasswordFont = new CFont;
  m_pNotesFont = new CFont;

  m_pItalicTreeListFont = new CFont;
  m_pItalicAddEditFont = new CFont;

  // Protected entry symbol
  const uint32_t newprotectedsymbol = 0x1f512;  // Padlock

  // Convert UTF-32 to UTF-16 or a surrogate pair of UTF-16
  m_sProtect = Utf32ToUtf16(newprotectedsymbol);

  // Entry has Attachment symbol
  const uint32_t newattachmentsymbol = 0x1F4CE;  // Paper-clip

  // Convert UTF-32 to UTF-16 or a surrogate pair of UTF-16
  m_sAttachment = Utf32ToUtf16(newattachmentsymbol);
}

void Fonts::GetTreeListFont(LOGFONT *pLF)
{
  ASSERT(pLF != nullptr && m_pTreeListFont != nullptr);
  if (pLF == nullptr || m_pTreeListFont == nullptr)
    return;

  m_pTreeListFont->GetLogFont(pLF);
}

void Fonts::SetTreeListFont(LOGFONT *pLF, const int iPtSz)
{
  ASSERT(pLF != nullptr);
  if (pLF == nullptr)
    return;

  if (m_pTreeListFont == nullptr) {
    m_pTreeListFont = new CFont;
  } else {
    m_pTreeListFont->DeleteObject();
  }

  if (iPtSz == 0) {
    // Create a new LOGFONT structure based on provided font
    LOGFONT lf(*pLF);
    
    // Use WinUtil::GetDPI() for DPI scaling
    UINT dpi = WinUtil::GetDPI();
    
    // Scale the font height based on DPI
    lf.lfHeight = MulDiv(lf.lfHeight, dpi, WinUtil::defDPI);
    
    m_pTreeListFont->CreateFontIndirect(&lf);
  } else {
    LOGFONT lf(*pLF);
    
    // Use WinUtil::GetDPI() for DPI scaling
    UINT dpi = WinUtil::GetDPI();
    
    // Scale the point size based on DPI
    int scaledPtSize = MulDiv(iPtSz, dpi, WinUtil::defDPI);
    lf.lfHeight = scaledPtSize;
    m_pTreeListFont->CreatePointFontIndirect(&lf);
  }
}

void Fonts::GetAddEditFont(LOGFONT *pLF)
{
  ASSERT(pLF != nullptr && m_pAddEditFont != nullptr);
  if (pLF == nullptr || m_pAddEditFont == nullptr)
    return;

  m_pAddEditFont->GetLogFont(pLF);
}

void Fonts::SetAddEditFont(LOGFONT *pLF, const int iPtSz)
{
  ASSERT(pLF != nullptr);
  if (pLF == nullptr)
    return;

  if (m_pAddEditFont == nullptr) {
    m_pAddEditFont = new CFont;
  } else {
    m_pAddEditFont->DeleteObject();
  }

  if (iPtSz == 0) {
    // Create a new LOGFONT structure based on provided font
    LOGFONT lf(*pLF);
    
    // Use WinUtil::GetDPI() for DPI scaling
    UINT dpi = WinUtil::GetDPI();
    
    // Scale the font height based on DPI
    lf.lfHeight = MulDiv(lf.lfHeight, dpi, WinUtil::defDPI);
    
    m_pAddEditFont->CreateFontIndirect(&lf);
  } else {
    LOGFONT lf(*pLF);
    
    // Use WinUtil::GetDPI() for DPI scaling
    UINT dpi = WinUtil::GetDPI();
    
    // Scale the point size based on DPI
    int scaledPtSize = MulDiv(iPtSz, dpi, WinUtil::defDPI);
    lf.lfHeight = scaledPtSize;
    m_pAddEditFont->CreatePointFontIndirect(&lf);
  }

  // Set up Add/Edit italic font
  if (m_pItalicAddEditFont == nullptr) {
    m_pItalicAddEditFont = new CFont;
  } else {
    m_pItalicAddEditFont->DeleteObject();
  }

  // Get current font - values depend on actions above
  LOGFONT lf_italic;
  m_pAddEditFont->GetLogFont(&lf_italic);

  // Make it italic and create "modified" font
  lf_italic.lfItalic = TRUE;
  m_pItalicAddEditFont->CreateFontIndirect(&lf_italic);
}

void Fonts::GetPasswordFont(LOGFONT *pLF)
{
  ASSERT(pLF != nullptr && m_pPasswordFont != nullptr);
  if (pLF == nullptr || m_pPasswordFont == nullptr)
    return;

  m_pPasswordFont->GetLogFont(pLF);
}

void Fonts::GetDefaultPasswordFont(LOGFONT &lf)
{
  memcpy(&lf, &dfltPasswordLogfont, sizeof(LOGFONT));
}

void Fonts::GetDefaultTreeListFont(LOGFONT &lf)
{
  memcpy(&lf, &dfltTreeListFont, sizeof(LOGFONT));
}

void Fonts::GetDefaultAddEditFont(LOGFONT &lf)
{
  memcpy(&lf, &dfltAddEditLogfont, sizeof(LOGFONT));
}

void Fonts::GetDefaultNotesFont(LOGFONT &lf)
{
  memcpy(&lf, &dfltNotesLogfont, sizeof(LOGFONT));
}

void Fonts::SetPasswordFont(LOGFONT *pLF, const int iPtSz)
{
  if (m_pPasswordFont == nullptr) {
    m_pPasswordFont = new CFont;
  } else {
    m_pPasswordFont->DeleteObject();
  }

  if (iPtSz == 0 || pLF == nullptr) {
    // Create a new LOGFONT structure based on default or provided font
    LOGFONT lf = (pLF == nullptr ? dfltPasswordLogfont : *pLF);
    
    UINT dpi = WinUtil::GetDPI();
    
    lf.lfHeight = MulDiv(lf.lfHeight, dpi, WinUtil::defDPI);
    
    m_pPasswordFont->CreateFontIndirect(&lf);
  } else {
    LOGFONT lf(*pLF);
    
    UINT dpi = WinUtil::GetDPI();
    
    int scaledPtSize = MulDiv(iPtSz, dpi, WinUtil::defDPI);
    lf.lfHeight = scaledPtSize;
    m_pPasswordFont->CreatePointFontIndirect(&lf);
  }
}

void Fonts::ApplyPasswordFont(CWnd *pDlgItem)
{
  ASSERT(pDlgItem != nullptr);
  if (pDlgItem == nullptr)
    return;

  if (m_pPasswordFont == nullptr) {
    m_pPasswordFont = new CFont;
    
    // Use WinUtil::GetDPI() with the window handle for per-window DPI
    UINT dpi = WinUtil::GetDPI(pDlgItem->GetSafeHwnd());
    
    // Create a scaled LOGFONT
    LOGFONT lf = dfltPasswordLogfont;
    lf.lfHeight = MulDiv(lf.lfHeight, dpi, WinUtil::defDPI);
    
    // Initialize a CFont object with the DPI-aware characteristics
    m_pPasswordFont->CreateFontIndirect(&lf);
  }

  pDlgItem->SetFont(m_pPasswordFont);
}

void Fonts::GetNotesFont(LOGFONT *pLF)
{
  ASSERT(pLF != nullptr && m_pNotesFont != nullptr);
  if (pLF == nullptr || m_pNotesFont == nullptr)
    return;

  m_pNotesFont->GetLogFont(pLF);
}

void Fonts::SetNotesFont(LOGFONT *pLF, const int iPtSz)
{
  ASSERT(pLF != nullptr);
  if (pLF == nullptr)
    return;

  if (m_pNotesFont == nullptr) {
    m_pNotesFont = new CFont;
  } else {
    m_pNotesFont->DeleteObject();
  }

  LOGFONT lf(*pLF);
  UINT dpi = WinUtil::GetDPI();

  if (iPtSz == 0) {
    // Scale the font height based on DPI
    lf.lfHeight = MulDiv(lf.lfHeight, dpi, WinUtil::defDPI);
    
    m_pNotesFont->CreateFontIndirect(&lf);
  } else {
    
    // Scale the point size based on DPI
    int scaledPtSize = MulDiv(iPtSz, dpi, WinUtil::defDPI);
    lf.lfHeight = scaledPtSize;
    m_pNotesFont->CreatePointFontIndirect(&lf);
  }
}

#ifdef DEBUG
void FixFontPreference(std::wstring &sFont)
{
  // Need to cope with differences between wxWidgets wxFont GetNativeFontInfoDesc
  // and our MFC implementation if they share the same config file, which will
  // only be during testing until wxWdigets replaces MFC version on Windows!

  // GetNativeFontInfoDesc adds an extra version parameter at the start of this string
  // and uses semi-colons to delimit values

  // MFC font preference is missing the first 'version' value at the start of this string
  // and uses commas to delimit values

#ifdef __WX__
  // wxWidgets fails safely if given a MFC created font preference - just doesn't set font
  // This will NEVER be used as in the  MFC source but consider putting this routine in
  // the wx build wherever it uses a font preference string.
  if (sFont.find(L',') != -1) {
    // First replace commas with semi-colons
    std::replace(sFont.begin(), sFont.end(), L',', L';');

    // Count the number of delimiters
    size_t count = std::count(sFont.begin(), sFont.end(), L';');

    // Add first value, which is a version, if only 13 (MFC Windows)
    if (count == 13)
      sFont = L"0;" + sxFont;
  }
#else
  // MFC does NOT fail safely if given a wxWdigets created font preference
  if (sFont.find(L';') != -1) {
    // First replace semi-colons with commas
    std::replace(sFont.begin(), sFont.end(), L';', L',');

    // Count the number of delimiters
    size_t count = std::count(sFont.begin(), sFont.end(), L',');

    // Skip first value, which is a version, if more than 13 (wxWidgets)
    if (count > 13) {
      size_t pos = sFont.find(L",");
      sFont.erase(0, pos + 1);
    }
  }
#endif
}
#endif

bool Fonts::ExtractFont(const std::wstring &str, LOGFONT &lf)
{
  std::wstring sFont = str;
#ifdef DEBUG
  FixFontPreference(sFont);
#endif

  // Tokenize
  std::vector<std::wstring> vtokens;
  size_t pos = 0;
  std::wstring token;
  while ((pos = sFont.find(L',')) != std::wstring::npos) {
    token = sFont.substr(0, pos);
    vtokens.push_back(token);
    sFont.erase(0, pos + 1);
  }
  vtokens.push_back(sFont);

  if (vtokens.size() != 14)
    return false;

  SecureZeroMemory(&lf, sizeof(lf));
  lf.lfHeight         = _wtol(vtokens[0].c_str());
  lf.lfWidth          = _wtol(vtokens[1].c_str());
  lf.lfEscapement     = _wtol(vtokens[2].c_str());
  lf.lfOrientation    = _wtol(vtokens[3].c_str());
  lf.lfWeight         = _wtol(vtokens[4].c_str());
  lf.lfItalic         = static_cast<BYTE>(_wtoi(vtokens[5].c_str()));
  lf.lfUnderline      = static_cast<BYTE>(_wtoi(vtokens[6].c_str()));
  lf.lfStrikeOut      = static_cast<BYTE>(_wtoi(vtokens[7].c_str()));
  lf.lfCharSet        = static_cast<BYTE>(_wtoi(vtokens[8].c_str()));
  lf.lfOutPrecision   = static_cast<BYTE>(_wtoi(vtokens[9].c_str()));
  lf.lfClipPrecision  = static_cast<BYTE>(_wtoi(vtokens[10].c_str()));
  lf.lfQuality        = static_cast<BYTE>(_wtoi(vtokens[11].c_str()));
  lf.lfPitchAndFamily = static_cast<BYTE>(_wtoi(vtokens[12].c_str()));

  wcscpy_s(lf.lfFaceName, LF_FACESIZE, vtokens[13].c_str());
  return true;
}

void Fonts::SetUpFont(CWnd *pWnd, CFont *pfont)
{
  // Set main font
  m_pTreeListFont = pfont;
  pWnd->SetFont(pfont);

  // Set up special fonts
  // Remove old fonts
  m_pItalicTreeListFont->DeleteObject();
  m_pDragFixFont->DeleteObject();
  
  // Get current font
  LOGFONT lf;
  pfont->GetLogFont(&lf);

  // Make it italic and create "modified" font
  lf.lfItalic = TRUE;
  m_pItalicTreeListFont->CreateFontIndirect(&lf);
  
  // Make DragFix font same height as user selected font
  DragFixLogfont.lfHeight = lf.lfHeight;
  // Create DragFix font
  m_pDragFixFont->CreateFontIndirect(&DragFixLogfont);
}

LONG Fonts::CalcHeight(const bool bIncludeNotesFont) const
{
  //Get max height from current/modified/password font
  TEXTMETRIC tm;
  HDC hDC = ::GetDC(nullptr);

  HFONT hFontOld = static_cast<HFONT>(SelectObject(hDC, m_pTreeListFont->GetSafeHandle()));

  // Current
  GetTextMetrics(hDC, &tm);
  LONG height = tm.tmHeight + tm.tmExternalLeading;

  // Modified
  SelectObject(hDC, m_pItalicTreeListFont->GetSafeHandle());
  GetTextMetrics(hDC, &tm);
  if (height < tm.tmHeight + tm.tmExternalLeading)
    height = tm.tmHeight + tm.tmExternalLeading;

  // Password
  SelectObject(hDC, m_pPasswordFont->GetSafeHandle());
  GetTextMetrics(hDC, &tm);
  if (height < tm.tmHeight + tm.tmExternalLeading)
    height = tm.tmHeight + tm.tmExternalLeading;

  if (bIncludeNotesFont) {
    // Notes - only for List View if Notes column present
    SelectObject(hDC, m_pNotesFont->GetSafeHandle());
    GetTextMetrics(hDC, &tm);
    if (height < tm.tmHeight + tm.tmExternalLeading)
      height = tm.tmHeight + tm.tmExternalLeading;
  }

  // Tidy up
  SelectObject(hDC, hFontOld);
  ::ReleaseDC(nullptr, hDC);

  return height;
}

bool Fonts::CalculateCaptionWidth(CWnd* pWnd, const CString& csCaption, int& cxWidth) const
{
  NONCLIENTMETRICS ncm;
  ncm.cbSize = sizeof(ncm);
  CFont fontCap;
  if (!SystemParametersInfo(SPI_GETNONCLIENTMETRICS, sizeof(NONCLIENTMETRICS), &ncm, 0) ||
      !fontCap.CreateFontIndirectW(&ncm.lfCaptionFont))
    return false;

  CDC* pDC = pWnd->GetWindowDC();
  if (!pDC)
    return false;

  CFont* ofont = pDC->SelectObject(&fontCap);
  cxWidth = pDC->GetTextExtent(csCaption).cx;
  pDC->SelectObject(ofont);
  pWnd->ReleaseDC(pDC);
  return true;
}

std::wstring Fonts::GetProtectedSymbol(const PWSFont font)
{
  if (font == TREELIST) {
    return m_bProtectSymbolSupportedTreeList ? m_sProtect : L"#";
  } else {
    return m_bProtectSymbolSupportedAddEdit ? m_sProtect : L"#";
  }
}

std::wstring Fonts::GetAttachmentSymbol(const PWSFont font)
{
  if (font == TREELIST) {
    return m_bProtectSymbolSupportedTreeList ? m_sAttachment : L"+";
  } else {
    return m_bProtectSymbolSupportedAddEdit ? m_sAttachment : L"+";
  }
}

bool Fonts::IsSymbolSuported(const Symbol symbol, const PWSFont font)
{
  if (symbol == PROTECT) {
    if (font == TREELIST) {
      return m_bProtectSymbolSupportedTreeList;
    } else {
      return m_bProtectSymbolSupportedAddEdit;
    }
  } else {
    if (font == TREELIST) {
      return m_bAttachmentSymbolSupportedTreeList;
    } else {
      return m_bAttachmentSymbolSupportedAddEdit;
    }
  }
}

void Fonts::VerifySymbolsSupported()
{
  bool bWindows10 = pws_os::IsWindows10OrGreater();

  // If supported - fine - use it
  // If not, use it if running under Windows 10 which seems to handle this nicely
  m_bProtectSymbolSupportedTreeList = IsCharacterSupported(m_sProtect) ? true : bWindows10;
  m_bProtectSymbolSupportedAddEdit = IsCharacterSupported(m_sProtect, false) ? true : bWindows10;

  // If supported - fine - use it
  // If not, use it if running under Windows 10 which seems to handle this nicely
  m_bAttachmentSymbolSupportedTreeList = IsCharacterSupported(m_sAttachment) ? true : bWindows10;
  m_bAttachmentSymbolSupportedAddEdit = IsCharacterSupported(m_sAttachment, false) ? true : bWindows10;
}

bool Fonts::IsCharacterSupported(std::wstring &sSymbol, const bool bTreeListFont)
{
  int cItems, cMaxItems = 2;
  bool bSupported(false);
  SCRIPT_ITEM items[3];  // Number should be (cMaxItems + 1)

  ASSERT(sSymbol.length() < 3);

  // Itemize - Uniscribe function
  HRESULT hr = ScriptItemize(sSymbol.c_str(), static_cast<int>(sSymbol.length()), cMaxItems, nullptr, nullptr, items,
                             &cItems);

  if (SUCCEEDED(hr) == FALSE)
    return bSupported;

  ASSERT(cItems == 1);

  SCRIPT_CACHE sc = nullptr;

  CDC ScreenDC;
  ScreenDC.CreateCompatibleDC(nullptr);
  CFont *pFont;

  if (bTreeListFont) {
    pFont = m_pTreeListFont;
  } else {
    pFont = m_pAddEditFont;
  }

  HFONT hOldFont = static_cast<HFONT>(ScreenDC.SelectObject(pFont->GetSafeHandle()));

  for (int i = 0; i < cItems; i++) {
    int idx = items[i].iCharPos;
    int len = items[i + 1].iCharPos - idx;
    int cMaxGlyphs = len * 2 + 16;  // As recommended by Uniscribe documentation
    int cGlyphs = 0;

    WORD *pwLogClust = static_cast<WORD*>(malloc(sizeof(WORD) * cMaxGlyphs));
    WORD *pwOutGlyphs = static_cast<WORD*>(malloc(sizeof(WORD) * cMaxGlyphs));
    SCRIPT_VISATTR *psva = static_cast<SCRIPT_VISATTR*>(malloc(sizeof(SCRIPT_VISATTR) * cMaxGlyphs));

    // Shape - Uniscribe function
    hr = ScriptShape(ScreenDC.GetSafeHdc(), &sc, sSymbol.substr(idx).c_str(), len, cMaxGlyphs,
      &items[i].a, pwOutGlyphs, pwLogClust, psva, &cGlyphs);

    if (SUCCEEDED(hr) == FALSE)
      goto clean;

    if (pwOutGlyphs[0] != 0)
      bSupported = true;

  clean:
    // Free up storage
    free(pwOutGlyphs);
    free(pwLogClust);
    free(psva);

    if (SUCCEEDED(hr) == FALSE)
      break;
  }

  // Free cache - Uniscribe function
  ScriptFreeCache(&sc);

  ScreenDC.SelectObject(hOldFont);

  return bSupported;
}

bool Fonts::CreateFontMatchingWindowHeight(CWnd& wnd, CFont& font, int cMaxCharWidth)
{
  ASSERT(::IsWindow(wnd.m_hWnd));
  if (!::IsWindow(wnd.m_hWnd))
    return false;
  CRect rcClient;
  wnd.GetClientRect(&rcClient);
  CFont* fontWnd = wnd.GetFont();
  if (!fontWnd)
    return false;
  LOGFONT lf;
  if (!fontWnd->GetLogFont(&lf))
    return false;
  lf.lfHeight = rcClient.Height();
  if (cMaxCharWidth > 0) {
    lf.lfWidth = rcClient.Width() / cMaxCharWidth;
  }
  font.DeleteObject();
  return font.CreateFontIndirect(&lf);
}
