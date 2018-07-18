// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2000-2018 ANSSI. All Rights Reserved.
/**
 * @file
 * @author Frederic Gauche <clipos@ssi.gouv.fr>
 * @author Olivier Levillain <clipos@ssi.gouv.fr>
 *
 * @section DESCRIPTION
 *
 * The String class aims at offering a simple type to manipulate character
 * strings, binary byte strings and big nums in particular.
 */


#include "anssipki-common.h"



/**********
 * String *
 **********/


/* Constructors and destructors */
/********************************/


String::String (const char* const src, const size_t sz)
  : _newUsed (false), _size (0), _str (NULL), _index (0)
{
  pr_init (sz);
  pr_assign (src);
}


String::String (const char* src /* = NULL (default value) */)
  : _newUsed (false), _size (0), _str (NULL), _index (0)
{
  size_t sz = pr_len (src);

  pr_init (sz);
  pr_assign (src);
}


String::String (const String& src)
  : _newUsed (false), _size (0), _str (NULL), _index (0)
{
  pr_init (src._size);
  pr_assign (src._str);
}


String::String (const uint val, const size_t min)
  : _newUsed (false), _size (0), _str (NULL), _index (0)
{
  uint v;
  size_t i, sz = 0;

  for (v=val; v!=0; v/=10)
    sz++;

  // Adds as many 0s as necessary
  if (sz < min) sz = min;

  pr_init (sz);

  // Finally, we extract the integer decimal digits
  for (i=0, v=val; i<sz; i++, v/=10) {
    char digit = (char) (0x30 + v % 10);
    _str[sz-1-i] = digit;
  }
}


String::String (const mpz_t n, encode_t encoding)
  : _newUsed (false), _size (0), _str (NULL), _index (0)
{
  if (mpz_sgn (n) < 0)
    throw ANSSIPKIException (E_NEGATIVE_BIGNUM);

  pr_init (mpz_sizeinbase(n, 16));
  mpz_get_str (_str, 16, n);

  switch (encoding) {
  case ENC_BINARY:
    asciiHexaToBignum ();
    break;
  case ENC_DISPLAY:
    break;
  default:
    throw UnexpectedError ("Valeur d'encodage inconnue (ni BINARY, ni DISPLAY)");
  }
}


String::~String () {
  clear();
}




/* Simple operations */
/*********************/


void String::clear() {
  if (_newUsed) {
    shred (_str, _size);
    delete[] _str;
    _newUsed = false;
  }
  _str = 0;
  _size=0;
  _index=0;
}


void String::resize(const size_t sz) {
  clear ();
  pr_init (sz);
}


const String& String::operator=(const String& src) {
  clear ();
  pr_init (src._size);
  pr_assign (src._str);
  return *this;
}


const String& String::operator+=(const String& src) {
  char *str_tmp;
  size_t size_tmp;

  // Temporary use of str_tmp to host the result
  size_tmp = pr_add (&str_tmp, src._str, src._size);

  // Then, we wipe the current content and replace it by str_tmp
  clear ();
  _newUsed = (size_tmp > 0);
  _size = size_tmp;
  _str = str_tmp;

  return *this;
}


const String& String::operator+=(const char src) {
  char *str_tmp;
  size_t size_tmp;

  // Temporary use of str_tmp to host the result
  size_tmp = pr_add (&str_tmp, &src, 1);

  // Then, we wipe the current content and replace it by str_tmp
  clear ();
  _newUsed = (size_tmp > 0);
  _size = size_tmp;
  _str = str_tmp;

  return *this;
}


String String::operator+(const String& src) const {
  String res (*this);
  res += src;
  return res;
}


String String::operator+(const char src) const {
  String res (*this);
  res += src;
  return res;
}


bool String::operator==(const String& src) const {
  if (_size != src._size)
    return false;

  // Both Strings have the same length. Let's compare their content.
  for (size_t i=0; i<_size; i++) {
    if (_str[i] != src._str[i]) {
      return false;
    }
  }

  // We have checked every byte: the Strings are equal.
  return true;
}


bool String::operator!=(const String& src) const {
  return ! (*this == src);
}


String String::substring (size_t start, size_t len) const {
  if (start + len > _size) throw OutOfBoundsStringOperation ();
  if (len == 0) return String ();
  if (!_newUsed)
    throw UnexpectedError ("Une chaîne de caractère de longueur non nulle n'a pas de données.");

  return String (_str+start, len);
}




/* String exploration */
/**********************/

void String::initIndex (size_t start /* = 0 (defaut value) */) const {
  if (start > _size) throw OutOfBoundsStringOperation ();
  _index = start;
}


char String::getChar () const {
  if (_index > _size) throw OutOfBoundsStringOperation ();
  return _str[_index];
}

char String::popChar () const {
  if (_index >= _size) throw OutOfBoundsStringOperation ();
  return _str[_index++];
}


String String::popSubstring (size_t len) const {
  String res = substring (_index, len);
  _index += len;
  return res;
}


String String::popLine () const {
  size_t start = _index;
  size_t len = 0;

  // If index is out of bounds, we throw an exception.
  if (eof()) throw OutOfBoundsStringOperation ();

  // Otherwise, we count the characters until we find a new line.
  while (!eof()) {
    char c = popChar();

    if (c == '\n') {
      // The loop must end when we reach a '\n' character...
      return substring (start, len);
    }
    else
      len ++; 
  }

  // ... or when we reach the end of the String.
  return substring (start, len);
}


void String::pushChar (char c) {
  if (_index >= _size) throw OutOfBoundsStringOperation ();
  _str[_index++] = c;
}


void String::pushString (const String& s) {
  s.initIndex ();
  while (! s.eof()) {
    pushChar (s.popChar());
  }
}




/* Filename and extensions handling */
/************************************/

String String::basename () const {
  try {
    size_t slash_pos = pr_get_last_slash ();
    return substring (slash_pos + 1, _size - (slash_pos + 1));
  } catch (NoSlashFound& e) {
    return String (_str, _size);
  }
}


String String::dirname () const {
  try {
    size_t slash_pos = pr_get_last_slash ();
    return substring (0, slash_pos + 1);
  } catch (NoSlashFound& e) {
    return String ("./");
  }
}


bool String::checkExtension (const String oldExt) const {
  return (_size >= oldExt._size)
    && (substring (_size - oldExt._size, oldExt._size) == oldExt);
}


String String::changeExtension (const String oldExt, const String newExt) const {
  if (checkExtension (oldExt))
    return substring (0, _size - oldExt._size) + newExt;
  else
    throw ANSSIPKIException (E_BAD_EXTENSION);
}




/* Bignum handling */
/*******************/


// Useful array/function to convert between binary and hexadecimal
// ASCII representations

static char hexa[16] = {
  '0', '1', '2', '3', '4', '5', '6', '7',
  '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};

static inline int fromHexa (char c) {
  if (c >= '0' && c <= '9')
    return (c - '0');
  if (c >= 'A' && c <= 'F')
    return (c + 10 - 'A');
  if (c >= 'a' && c <= 'f')
    return (c + 10 - 'a');
  throw ANSSIPKIException (E_INVALID_HEXA_STRING);
}



void String::bignumToAsciiHexa (char delimiter/* = 0 (defaut value) */) {
  size_t new_size;

  if (delimiter == 0)
    new_size = _size * 2;
  else
    new_size = _size * 3 - 1;

  char* new_str = new char[new_size + 1];
  size_t dst_i = 0;

  // Each character is transformed into two hexadecimal chars.
  for (size_t i=0; i<_size; i++) {
    new_str[dst_i++] = hexa [(_str[i] >> 4) & 0xf];
    new_str[dst_i++] = hexa [_str[i] & 0xf];
    if (delimiter != 0 && dst_i < new_size)
      new_str[dst_i++] = delimiter;
  }
  new_str[new_size] = 0;

  // Once the work is done, we replace the value by the new representation.
  clear();
  _size = new_size;
  _str = new_str;
  _newUsed = true;
}


String String::toAsciiHexa (char delimiter) const {
  String res (*this);
  res.bignumToAsciiHexa(delimiter);
  return res;
}


void String::asciiHexaToBignum () {
  size_t new_size = (_size / 2) + (_size % 2);
  char* new_str = new char[new_size + 1];
  size_t i = 0, dst_i = 0;

  // We have to treat the case where the first character is left alone.
  if (_size % 2 == 1)
    new_str[dst_i++] = (char) fromHexa (_str[i++]);

  // Then, we work with two chars at a time to form a byte.
  while (dst_i<new_size) {
    new_str[dst_i] = (char) ((fromHexa (_str[i]) << 4) | fromHexa (_str[i+1]));
    dst_i++;
    i+=2;
  }
  new_str[new_size] = 0;

  // Once the work is done, we replace the value by the new representation.
  clear();
  _size = new_size;
  _str = new_str;
  _newUsed = true;
}



/* Private useful functions */
/****************************/

void String::pr_init (const size_t sz) {
  size_t i;

  _size = sz;
  _index = 0;
  _newUsed = false;
  _str = 0;
  if (_size > 0) {
    _str = new char[_size + 1];
    _newUsed = true;
    for (i = 0; i < _size+1; i++) {
      _str[i] = 0;
    }
  }
}


size_t String::pr_len (const char* const src) const {
  size_t sz;

  if (src == NULL) {
    sz = 0;
  } else {
    for (sz = 0; src[sz] != 0; sz++) ;
  }

  return sz;
}


size_t String::pr_add (char** const dest, const char* const src, const size_t sz) const {
  size_t new_size, i;

  new_size = _size + sz;
  if (new_size > 0) {
    // Le résultat n'est pas vide
    // On va copier self.str puis src dans un nouveau tampon alloué pour dest
    *dest = new char[new_size + 1];
    for (i=0; i<_size; i++)
      (*dest)[i] = _str[i];

    for (i=0; i<sz; i++)
      (*dest)[_size + i] = src[i];

    (*dest)[_size + sz]= 0;
  } else {
    // La chaîne à retourner est vide
    *dest = 0;
  }

  return new_size;
}



void String::pr_assign (const char* const src) {
  size_t i;

  if (_size > 0) {
    for (i = 0; i < _size; i++) {
      _str[i] = src[i];
    }
  }
}


size_t String::pr_get_last_slash () const {
  if (_size > 0) {
    size_t i = _size-1;   

    while (1) {
      if (_str[i] == '/') return i;
      if (i == 0) break;
      i--;
    }
  }

  throw NoSlashFound ();
}
