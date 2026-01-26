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

#include <string>

static int HexValue(unsigned char ch)
{
  if (ch >= '0' && ch <= '9')
    return ch - '0';
  if (ch >= 'a' && ch <= 'f')
    return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F')
    return ch - 'A' + 10;
  return -1;
}

static bool ReadHexByte(const unsigned char *data, unsigned char &value)
{
  int hi = HexValue(data[0]);
  int lo = HexValue(data[1]);
  if (hi < 0 || lo < 0)
    return false;
  value = static_cast<unsigned char>((hi << 4) | lo);
  return true;
}

static bool ReadHexWord(const unsigned char *data, size_t &value)
{
  unsigned char hi = 0;
  unsigned char lo = 0;
  if (!ReadHexByte(data, hi) || !ReadHexByte(data + 2, lo))
    return false;
  value = (static_cast<size_t>(hi) << 8) | lo;
  return true;
}

static bool IsSeparator(const unsigned char *data, size_t remaining)
{
  return remaining >= 6 &&
         data[0] == '0' && data[1] == '0' &&
         data[2] == '0' && data[3] == '0' &&
         data[4] == '0' && data[5] == '0';
}

static void AppendHexByte(std::string &out, unsigned char value)
{
  static const char hex_digits[] = "0123456789abcdef";
  out.push_back(hex_digits[(value >> 4) & 0x0f]);
  out.push_back(hex_digits[value & 0x0f]);
}

static void AppendHexWord(std::string &out, size_t value)
{
  static const char hex_digits[] = "0123456789abcdef";
  out.push_back(hex_digits[(value >> 12) & 0x0f]);
  out.push_back(hex_digits[(value >> 8) & 0x0f]);
  out.push_back(hex_digits[(value >> 4) & 0x0f]);
  out.push_back(hex_digits[value & 0x0f]);
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
      if (prop.value.length() == 1 && (prop.value[0] == _T('0') || prop.value[0] == _T('1')))
        sensitive = (prop.value[0] == _T('1'));
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

    unsigned char prop_id = 0;
    size_t value_len = 0;
    if (!ReadHexByte(utf8 + pos, prop_id) ||
        !ReadHexWord(utf8 + pos + 2, value_len)) {
      m_numErr++;
      break;
    }
    if (prop_id == 0) {
      m_numErr++;
      break;
    }
    pos += 6;

    if (pos + value_len > utf8Len) {
      m_numErr++;
      break;
    }

    StringX value;
    if (!utf8conv.FromUTF8(utf8 + pos, value_len, value)) {
      m_numErr++;
      break;
    }
    pos += value_len;

    if (current.HasProperty(prop_id)) {
      m_numErr++;
      continue;
    }
    if (prop_id == CustomField::PROP_SENSITIVE) {
      if (value.length() != 1 || (value[0] != _T('0') && value[0] != _T('1')))
        m_numErr++;
    }
    current.SetProperty(prop_id, value);
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
  std::string out;
  bool wrote_field = false;

  for (auto field_iter = begin(); field_iter != end(); ++field_iter) {
    const CustomField &field = *field_iter;
    if (field.Empty())
      continue;

    if (wrote_field)
      out.append("000000");

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

      AppendHexByte(out, prop.id);
      AppendHexWord(out, utf8Len);
      out.append(reinterpret_cast<const char *>(utf8), utf8Len);
    }
    wrote_field = true;
  }

  StringX result;
  if (!out.empty()) {
    if (!utf8conv.FromUTF8(reinterpret_cast<const unsigned char *>(out.data()), out.size(), result)) {
      ASSERT(0);
      result.clear();
    }
  }
  return result;
}
