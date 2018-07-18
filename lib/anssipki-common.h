// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2000-2018 ANSSI. All Rights Reserved.
/**
 * @file
 * @author Frederic Gauche <clipos@ssi.gouv.fr>
 * @author Olivier Levillain <clipos@ssi.gouv.fr>
 *
 * @section DESCRIPTION
 *
 * This file defines all the basic classes used by the cryptographic
 * library.
 */

#ifndef ANSSIPKI_COMMON_H
#define ANSSIPKI_COMMON_H


#include <stdint.h>
#include <sys/types.h>
#include <gmp.h>
#include <exception>


/// Enumeration of all the exception thrown by the library
typedef enum {
  /* String errors */
  E_OUT_OF_BOUNDS_STRING_OPERATION, /**< Out of bound error while handling strings */
  E_INVALID_HEXA_STRING,            /**< Hexadecimal string conversion is impossible due to an incorrect character */
  E_NEGATIVE_BIGNUM,                /**< The bignum given is negarive */
  E_NO_SLASH_FOUND,                 /**< The string contains no '/' character */
  E_BAD_EXTENSION,                  /**< The string doesn't end with the expected extension */

  /* DER Format errors */
  E_DER_INVALID_FILE,               /**< The data are not compliant with the Distinguished Encoding Rules (DER) of ASN.1 */
  E_DER_SEQUENCE_EXPECTED,          /**< ASN.1 Sequence object expected */
  E_DER_SET_EXPECTED,               /**< ASN.1 Set object expected */
  E_DER_OID_EXPECTED,               /**< ASN.1 OID object expected */
  E_INVALID_CERTIFICATE,            /**< Parsing error in a certificate */

  /* Cryptographic errors */
  E_CRYPTO_BAD_PARAMETER,           /**< Invalid cryptographic parameters */
  E_CRYPTO_PRNG_STATE_ERROR,        /**< Error while accessing the PRNG state file */
  E_CRYPTO_INTERNAL_MAYHEM,         /**< Critical bug detected during a cryptographic operation */

  /* Unexpected errors */
  E_NOT_IMPLEMENTED,                /**< Function not implemented */
  E_UNEXPECTED_ERROR,               /**< Unexpected error */
  E_UNKNOWN_ERROR,                  /**< Unknown error thrown */

  E_NB_ERRORS                       /**< Number of errors described by this enum type */
} exception_t;



/// Class describing byte/char strings
/**
 * This class aims at offering a simple type to manipulate character
 * strings, binary byte strings and big nums in particular.
 *
 * Upon destruction, a String object wipes the memory used.
 */
class String {
 public:

  /// Enumeration used to tell how to encode a mpz_t into a string.
  typedef enum {ENC_BINARY,      /**< Binary byte string */
		ENC_DISPLAY      /**< Hexadecimal ASCII representation  */
  } encode_t;



  /* Constructors and destructors */
  /********************************/

  /**
   * Constructor using a char array of given length as the source of
   * the string. This constructor should be used on binary data (where
   * null characters occur).
   *
   * @param src the source character array.
   * @param sz the number of chars to take into account.
   */
  String (const char* src, const size_t sz);
                
  /**
   * Constructor using a standard null-terminated C string. This
   * constructor should only be used on character string destined to
   * be displayed and must not be used on binary data. It is also the
   * default constructor.
   *
   * @param src a null-terminated C char string.
   */
  String (const char* src = NULL);

  /**
   * Constructor by copy.
   *
   * @param src a String object.
   */
  String (const String& src);

  /**
   * Constructor using an unsigned int. The resulting string is a
   * decimal representation on at least min characters.
   *
   * @param val an unsigned integer to convert.
   * @param min the minimum length of the resulting String.
   */
  String (const uint val, const size_t min); 

  /**
   * Constructor using a mpz_t GMP integer.
   *
   * @param n a GMP integer.
   * @param encoding the format used to create the String (binary or printable).
   * @exception E_NEGATIVE_BIGNUM if n is negative.
   */
  String (const mpz_t n, encode_t encoding); 

  /**
   * String destructor. This method calls clear to wipe the memory
   * used by the String.
   */
  virtual ~String();



  /* Simple operations */
  /*********************/

  /**
   * Returns the character string represented by the String
   * object. Applied to a String of size n, the result is guaranteed
   * to have a null character at position n+1.
   *
   * @result a const character pointer to the content of the String.
   */
  const char* toChar () const throw () {
    return _newUsed ? _str : "";
  }

  /**
   * Returns the size of the String object. It can be different from
   * the value returned by strlen on the this->toChar().
   *
   * @result the size of the byte string represented.
   */
  size_t size () const throw () {
    return _newUsed ? _size : 0;
  }

  /**
   * Wipes the memory used by the String and frees the corresponding
   * memory.
   */
  void clear ();

  /**
   * Changes the size of the String. The old value is first wiped and
   * freed, then the new buffer is allocated and filled with zeroes.
   *
   * @param sz the new size of the String.
   */
  void resize (const size_t sz);

  /**
   * Assignment operator.
   *
   * @param src a String object.
   */
  const String& operator=(const String& src);

  /**
   * Adds the content of another String to the current object. This
   * method modifies the object it is called upon.
   *
   * @param src the String to add to the current String.
   * @return a reference on the modified String.
   */
  const String& operator+=(const String& src);

  /**
   * Adds a character to the current object. This method modifies the
   * object it is called upon.
   *
   * @param src the character to add to the current String.
   * @return a reference on the modified String.
   */
  const String& operator+=(const char src);

  /**
   * Adds the content of another String to the current object to
   * create a new String. This method leaves unchanged the it is
   * called upon.
   *
   * @param src the String to add to the current String.
   * @return a new String formed by the concatenation of this and src.
   */
  String operator+(const String& src) const;

  /**
   * Adds a character to the current object to create a new
   * String. This method leaves unchanged the it is called upon.
   *
   * @param src the character to add to the current String.
   * @return a new String formed by the concatenation of this and src.
   */
  String operator+(const char src) const;


  /**
   * Equality test between Strings. Two Strings are declared equal if
   * they have the same length and the exact same binary content. It
   * essentially behaves like a memcmp, and not like a strcmp.
   *
   * This function is not safe against timing attacks.
   * 
   * @param src the String to compare to this.
   * @return true if this and src have the same content, false otherwise.
   */
  bool operator==(const String& src) const;

  /**
   * Inequality test between Strings. It simply consists of the
   * negation of the == operator.
   */
  bool operator!=(const String& src) const;

  /**
   * Returns a substring of the current String. In terms of the
   * original byte array str, the result corresponds to
   * str[start:start+len[
   *
   * @param start the first character to extract.
   * @param len the number of characters to extract.
   * @return a new String object containing the substring.
   * @exception E_OUT_OF_BOUNDS_STRING_OPERATION if the indices given are out of bounds.
   */
  String substring (size_t start, size_t len) const;



  /* String exploration */
  /**********************/

  /**
   * Initializes the exploration index. The default value is zero,
   * i.e. the beginning of the String. The exploration can be used to
   * read a String character by character or to modify it character by
   * character. In both cases, the size of the String cannot be
   * modified.
   *
   * @param start the value to initialize the index with.
   * @exception E_OUT_OF_BOUNDS_STRING_OPERATION if the index is out of bounds.
   */
  void initIndex (size_t start = 0) const;

  /**
   * Returns the current value of the exploration index.
   *
   * @return the current value of the exploration index.
   */
  size_t index () const throw () {
    return _index;
  }


  /**
   * Returns the character pointed by the current exploration index
   * without changing the index value.
   * 
   * @return the current character.
   * @exception E_OUT_OF_BOUNDS_STRING_OPERATION if the index is out of bounds.
   */
  char getChar () const;

  /**
   * Returns the character pointed by the current exploration index
   * which is incremented.
   * 
   * @return the current character.
   * @exception E_OUT_OF_BOUNDS_STRING_OPERATION if the index is out of bounds.
   */
  char popChar () const;

  /**
   * Returns a new String corresponding to the len next characters in
   * the String from the exploration index. The index is updated after
   * the extraction.
   * 
   * @param len the length of the String to extract.
   * @return the String extracted.
   * @exception E_OUT_OF_BOUNDS_STRING_OPERATION if the index is out of bounds during the operation.
   */
  String popSubstring (size_t len) const;

  /**
   * Returns a new String corresponding to the content of the current
   * String from its exploration index to the next end of the
   * line. The '\n' character is not part of the returned String.
   * 
   * @return the String extracted.
   * @exception E_OUT_OF_BOUNDS_STRING_OPERATION if the initial index is out of bounds.
   */
  String popLine () const;

  /**
   * Modifies the current character and updates the exploration index.
   *
   * @param c the new character
   * @exception E_OUT_OF_BOUNDS_STRING_OPERATION if the index is out of bounds.
   */
  void pushChar (char c);

  /**
   * Replaces the current String from the exploration index by the
   * content of s using pushChar. The index is updated
   * accordingly. The index of the String s will be altered.
   *
   * @param c the new character
   * @exception E_OUT_OF_BOUNDS_STRING_OPERATION if the index is out of bounds during the operation.
   */
  void pushString (const String& s);


  /**
   * Indicates whether the end of the String is reached.
   *
   * @return true if the exploration index is at the end of the String, false otherwise.
   */
  bool eof () const throw () {
    return (_index >= _size);
  }


  /* Filename and extensions handling */
  /************************************/

  /**
   * Extracts the base name of a filename. If the file contains a /,
   * it corresponds to the part after the last /; otherwise, a copy of
   * the String unmodified is returned.
   * 
   * @return a new String containing the base name.
   */
  String basename () const;

  /**
   * Extracts the dir name of a filename. If the file contains a /, it
   * corresponds to the part after the last /; otherwise, "./" is
   * returned. The String returned always contains a final "/".
   * 
   * @return a new String containing the dir name.
   */
  String dirname () const;

  /**
   * Checks whether a filename ends with a given suffix.
   * 
   * @param oldExt the suffix to check.
   * @return true if the current String ends with oldExt, false otherwise.
   */
  bool checkExtension (const String oldExt) const;

  /**
   * Returns a new String where the suffix given as oldExt is replaced
   * by newExt.
   * 
   * @param oldExt the suffix to delete.
   * @param newExt the suffix to add.
   * @return a new String where the suffix has been changed.
   * @exception E_BAD_EXTENSION if the String does not end with oldExt.
   */
  String changeExtension (const String oldExt, const String newExt) const;



  /* Bignum handling */
  /*******************/

  /**
   * Transforms in place the current String seen as a binary bignum
   * into a printable hexadecimal ASCII version. For example,
   * "\x12\x34" would be transformed into "1234" or "12:34", depending
   * on the delimiter given.
   *
   * @param delimiter if non null, the character to insert between the representation of each byte.
   */
  void bignumToAsciiHexa (const char delimiter = 0);

  /**
   * Returns a printable hexadecimal ASCII version of the current
   * String seen as a binary bignum. The current String is left
   * unchanged.
   *
   * @param delimiter if non null, the character to insert between the representation of each byte.
   * @return a new String containing the printable representation.
   */
  String toAsciiHexa (const char delimiter) const;

  /**
   * Transforms in place the current String seen as a printable
   * hexadecimal ASCII chain into a binary bignum. For example, "1234"
   * would be transformed into "\x12\x34".
   *
   * @exception E_INVALID_HEXA_STRING if the current String contains invalid hexadecimal chars.
   */
  void asciiHexaToBignum ();


 private:
  bool _newUsed;          /**< Indicates whether _str corresponds to a malloc'ed buffer or not. */
  size_t _size;           /**< Size of the String contained in _str. */
  char *_str;             /**< Buffer containing the value of the object. Its value is NULL when _newUsed is false. */

  mutable size_t _index;  /**< Exploration index */



  /* Private useful functions */
  /****************************/


  /**
   * Allocates the _str buffer and initializes it with zeroes.
   * Furthermore, _size, _index and _newUsed are correctly updated. If
   * sz equals zero, no buffer is actually created. Actually, the
   * buffer allocated contains one more character to add a safe ending
   * null character.
   *
   * WARNING: this function assumes the _str buffer is currently
   * unallocated.
   *
   * @param sz the size to allocate for the _str buffer.
   */
  void pr_init (const size_t sz);   

  /**
   * Returns the length of a null-terminated char string.
   *
   * @param src the null-terminated string.
   * @return the index of the first null character in src, or zero if src is NULL.
   */
  size_t pr_len (const char* const src) const;

  /**
   * Allocates a buffer *dest of size _size + sz and concatenates the
   * current buffer _str and src in the new buffer.
   *
   * WARNING: this function assumes that _str has been correctly
   * allocated and contains at least _size characters.
   *
   * @param dest a pointer to a char* to allocate and fill in with the concatenation.
   * @param src a pointer to the bytes to concatenate to the current value.
   * @param sz the size of the bytes to consider in src.
   * @return the size of the created value (size + sz).
   *
   */
  size_t pr_add (char** const dest, const char* const src, const size_t sz) const;

  /**
   * Copies _size characters from src to _str.
   *
   * WARNING: this functions assumes _size is null or _str contains at
   * least _size characters.
   *
   * @param src the char string to copy to _str.
   */
  void pr_assign (const char* const src);

  /**
   * Returns the position of the last slash of the current String.
   *
   * @return the position of the last slash.
   * @exception E_NO_SLASH_FOUND if the String does not contain any slashes.
  */
  size_t pr_get_last_slash () const;
};



/// Class describing the exceptions thrown by the ANSSIPKI libraries/programs.
/**
 * This class allows for a unified way of signaling errors inside the
 * ANSSIPKI code. It uses a variable of type exception_t to describe the
 * type of error and possibly a textual description.
 */
class ANSSIPKIException : public std::exception {
 public:

  /**
   * Simple exception constructor.
   *
   * @param e the type describing the exception.
   */
  ANSSIPKIException (const exception_t e);

  /**
   * Exception constructor allowing for a detailled message.
   *
   * @param e the type describing the exception.
   * @param details String containing details about the error encountered.
   */
  ANSSIPKIException (const exception_t e, const String& details);

  /**
   * Constructor by copy.
   *
   * @param e an existing ANSSIPKIException.
   */
  ANSSIPKIException (const ANSSIPKIException& e) : _errNo (e._errNo), _details (e._details) {}

  /**
   * Standard function to produce a printable message when the
   * exception is caught.
   *
   * @return the message to be printed.
   */
  virtual const char* what () const throw ();

  /**
   * Simple accessor for the error type.
   */
  exception_t errNo () const { return _errNo; }

  /**
   * Simple accessor for the detailed message if available.
   */
  const String& details () const { return _details; }

  /**
   * Simple destructor
   */
  virtual ~ANSSIPKIException() throw () {};

 private:
  exception_t _errNo;  /**< Error type */
  String _details;     /**< Detailed message. If empty, a default message corresponding to the error type is returned. */

  ANSSIPKIException () {}
  const ANSSIPKIException& operator= (const ANSSIPKIException& e);
};


/***********************
 * Specific Exceptions *
 ***********************/

/* String errors */

/// Specific exception class for OutOfBounds String errors (E_OUT_OF_BOUNDS_STRING_OPERATION).
class OutOfBoundsStringOperation : public ANSSIPKIException {
 public:
  /// Constructor
  OutOfBoundsStringOperation () : ANSSIPKIException (E_OUT_OF_BOUNDS_STRING_OPERATION) {}
};

/// Specific exception class to signal the absence of a '/' character (E_NO_SLASH_FOUND).
class NoSlashFound : public ANSSIPKIException {
 public:
  NoSlashFound () : ANSSIPKIException (E_NO_SLASH_FOUND) {}
};


/* DER Format errors */

/// Specific exception indicating an unexpected ASN.1 object type (E_DER_SEQUENCE_EXPECTED).
class DERSequenceExpected : public ANSSIPKIException {
 public:
  DERSequenceExpected () : ANSSIPKIException (E_DER_SEQUENCE_EXPECTED) {}
};

/// Specific exception indicating an unexpected ASN.1 object type (E_DER_SET_EXPECTED).
class DERSetExpected : public ANSSIPKIException {
 public:
  DERSetExpected () : ANSSIPKIException (E_DER_SET_EXPECTED) {}
};

/// Specific exception indicating an unexpected ASN.1 object type (E_DER_OID_EXPECTED).
class DEROIDExpected : public ANSSIPKIException {
 public:
  DEROIDExpected () : ANSSIPKIException (E_DER_OID_EXPECTED) {}
};

/// Specific exception indicating a problem while parsing a certificate (E_INVALID_CERTIFICATE).
class DERUnknownCertFormat : public ANSSIPKIException {
 public:
  DERUnknownCertFormat (const String& details) : ANSSIPKIException (E_INVALID_CERTIFICATE, details) {}
};


/* Crypto errors */

/// Specific excpetion thrown when a crypto invariant has been violated (E_CRYPTO_INTERNAL_MAYHEM).
/**
 * When this exception arises, something very nasty has happened
 * cryptographically speaking, and the program must stop immediatly.
 */
class CryptoInternalMayhem : public ANSSIPKIException {
 public:
  CryptoInternalMayhem (const String& details) : ANSSIPKIException (E_CRYPTO_INTERNAL_MAYHEM, details) {}
};


/* Unexpected errors */

/// Specific exception thrown when a functionnality has not (yet) been implemented (E_NOT_IMPLEMENTED).
/**
 * Such an exception arise on not handled cases. It is mandatory to
 * give details about the function that is not implemented.
 */
class NotImplemented : public ANSSIPKIException {
 public:
  NotImplemented (const String& details) : ANSSIPKIException (E_NOT_IMPLEMENTED, details) {}
};

/// Specific exception for unexpected cases (E_UNEXPECTED_ERROR).
/**
 * This exception should never arise and corresponds to defensive
 * checks in the code. That is why it should always be thrown with
 * the details needed to identify the underlying bug.
 */
class UnexpectedError : public ANSSIPKIException {
 public:
  UnexpectedError (const String& details) : ANSSIPKIException (E_UNEXPECTED_ERROR, details) {}
};





/********************
 * Useful Functions *
 ********************/

/// Simple function checking that a pointer is not null
static inline void abortIfNull (void* ptr) {
  if (ptr == 0) throw UnexpectedError ("Pointeur non nul attendu");
}

/// Simple function checking that a pointer is null
static inline void abortIfNotNull (void* ptr) {
  if (ptr != 0) throw UnexpectedError ("Pointeur nul attendu");
}

/**
 * Wrapper around write syscalls to insure that all the data given is
 * written before returning
 *
 * @param fd the file descriptor where the data should be written.
 * @param data a pointer towards the data to be written.
 * @param len the length in bytes of data to be written.
 * @return the number of characters really written (which will be len) or -1 if an error occurred.
 */
ssize_t reallyWrite (int fd, const char* data, size_t len);

/**
 * Wrapper around read syscalls to insure that the correct amount of
 * data is really read.
 *
 * @param fd the file descriptor the data should be read from.
 * @param data a pointer where the data should be read.
 * @param len the length in bytes of data to be read.
 * @return the number of characters really read (it can be 0..len since we might have hit the end of file) or -1 if an error occurred.
 */
ssize_t reallyRead (int fd, char* data, size_t len);

/**
 * Overwrites a GMP integer to clear its value from memory. 
 *
 * @param n the integer to erase.
 */
void mpz_shred (mpz_t n);

/**
 * Overwrites a memory area with 0s and 1s to clear its value.
 *
 * @param state the buffer to erase.
 * @param len the length of the buffer.
 */
void shred (char* state, size_t len);

/**
 * This function computes a naive value of the entropy of a given
 * String. The idea is just to compress it with the zlib and return
 * the length of the result.
 *
 * @param s the String we want to compute the entropy of.
 * @return the size of the String compressed.
 * @exception E_UNEXPECTED_ERROR if the compression failed.
 */
size_t naive_entropy (const String& s);



#endif  // ifndef ANSSIPKI_COMMON_H
