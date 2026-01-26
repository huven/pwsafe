/*
* Copyright (c) 2003-2026 Rony Shapiro <ronys@pwsafe.org>.
* All rights reserved. Use of the code is allowed under the
* Artistic License 2.0 terms, as specified in the LICENSE file
* distributed with this code, or available from
* http://www.opensource.org/licenses/artistic-license-2.0.php
*/
// CustomFields.cpp
//-----------------------------------------------------------------------------

#include "CustomFields.h"
#include "UTF8Conv.h"
#include "StringXStream.h"

#include <iomanip>

static bool ReadHexValue(const unsigned char *data, size_t len, unsigned int &value)
{
  StringX hexstr;
  hexstr.reserve(len);
  for (size_t i = 0; i < len; i++)
    hexstr += static_cast<wchar_t>(data[i]);

  iStringXStream iss(hexstr);
  iss >> std::hex >> value;
  return !iss.fail() && iss.eof();
}

static bool IsSeparator(const unsigned char *data, size_t remaining)
{
  return remaining >= 6 &&
         data[0] == '0' && data[1] == '0' &&
         data[2] == '0' && data[3] == '0' &&
         data[4] == '0' && data[5] == '0';
}

StringX CustomField::GetName() const
{
  for (const auto &prop : m_props) {
    if (prop.id == PROP_NAME)
      return prop.value;
  }
  return _T("");
}

StringX CustomField::GetValue() const
{
  for (const auto &prop : m_props) {
    if (prop.id == PROP_VALUE)
      return prop.value;
  }
  return _T("");
}

bool CustomField::GetSensitive(bool &sensitive) const
{
  for (const auto &prop : m_props) {
    if (prop.id == PROP_SENSITIVE) {
      if (prop.value.length() == 1)
        sensitive = (prop.value[0] != _T('0'));
      else
        sensitive = false;
      return true;
    }
  }
  sensitive = false;
  return false;
}

bool CustomField::IsSensitive() const
{
  bool sensitive = false;
  GetSensitive(sensitive);
  return sensitive;
}

bool CustomField::HasProperty(unsigned char id) const
{
  for (const auto &prop : m_props) {
    if (prop.id == id)
      return true;
  }
  return false;
}

void CustomField::SetName(const StringX &name)
{
  SetProperty(PROP_NAME, name);
}

void CustomField::SetValue(const StringX &value)
{
  SetProperty(PROP_VALUE, value);
}

void CustomField::SetSensitive(bool sensitive)
{
  StringX value;
  value += sensitive ? _T('1') : _T('0');
  SetProperty(PROP_SENSITIVE, value);
}

void CustomField::SetProperty(unsigned char id, const StringX &value)
{
  for (auto &prop : m_props) {
    if (prop.id == id) {
      prop.value = value;
      return;
    }
  }
  m_props.push_back(CustomFieldProperty(id, value));
}

CustomFieldList::CustomFieldList(const StringX &data) : m_numErr(0)
{
  if (data.empty())
    return;

  CUTF8Conv utf8conv;
  const unsigned char *utf8 = nullptr;
  size_t utf8Len = 0;
  if (!utf8conv.ToUTF8(data, utf8, utf8Len)) {
    m_numErr = 1;
    return;
  }

  size_t pos = 0;
  CustomField current;
  while (pos < utf8Len) {
    if (IsSeparator(utf8 + pos, utf8Len - pos)) {
      if (!current.Empty()) {
        if (!current.HasProperty(CustomField::PROP_NAME) ||
            !current.HasProperty(CustomField::PROP_VALUE))
          m_numErr++;
        if (current.HasProperty(CustomField::PROP_NAME) && current.GetName().empty())
          m_numErr++;
        push_back(current);
        current = CustomField();
      }
      pos += 6;
      continue;
    }

    if (utf8Len - pos < 6) {
      m_numErr++;
      break;
    }

    unsigned int prop_id = 0;
    unsigned int value_len = 0;
    if (!ReadHexValue(utf8 + pos, 2, prop_id) ||
        !ReadHexValue(utf8 + pos + 2, 4, value_len)) {
      m_numErr++;
      break;
    }
    if (prop_id == 0 || prop_id > 0xff) {
      m_numErr++;
      break;
    }
    pos += 6;

    size_t value_len_sz = static_cast<size_t>(value_len);
    if (pos + value_len_sz > utf8Len) {
      m_numErr++;
      break;
    }

    StringX value;
    VectorX<unsigned char> buf(utf8 + pos, utf8 + pos + value_len_sz);
    buf.push_back(0); // null terminate for FromUTF8.
    if (!utf8conv.FromUTF8(&buf[0], value_len_sz, value)) {
      m_numErr++;
      break;
    }
    pos += value_len_sz;

    if (current.HasProperty(static_cast<unsigned char>(prop_id))) {
      m_numErr++;
      continue;
    }
    if (prop_id == CustomField::PROP_SENSITIVE) {
      if (value_len_sz != 1)
        m_numErr++;
    }
    current.SetProperty(static_cast<unsigned char>(prop_id), value);
  }

  if (!current.Empty()) {
    if (!current.HasProperty(CustomField::PROP_NAME) ||
        !current.HasProperty(CustomField::PROP_VALUE))
      m_numErr++;
    if (current.HasProperty(CustomField::PROP_NAME) && current.GetName().empty())
      m_numErr++;
    push_back(current);
  }
}

CustomFieldList::operator StringX() const
{
  if (empty())
    return _T("");

  CUTF8Conv utf8conv;
  StringX out;
  bool wrote_field = false;

  for (auto field_iter = begin(); field_iter != end(); ++field_iter) {
    const CustomField &field = *field_iter;
    if (field.Empty())
      continue;

    if (wrote_field)
      out += _T("000000");

    const auto &props = field.GetProperties();
    for (const auto &prop : props) {
      if (prop.id == 0) {
        ASSERT(0);
        continue;
      }

      const unsigned char *utf8 = nullptr;
      size_t utf8Len = 0;
      if (!utf8conv.ToUTF8(prop.value, utf8, utf8Len)) {
        ASSERT(0);
        continue;
      }
      if (utf8Len > 0xffff) {
        ASSERT(0);
        continue;
      }

      oStringXStream oss;
      oss.fill(charT('0'));
      oss << std::hex << std::setw(2) << static_cast<int>(prop.id)
          << std::setw(4) << static_cast<unsigned int>(utf8Len);
      out += oss.str().c_str();
      out += prop.value;
    }
    wrote_field = true;
  }

  return out;
}
