// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2000-2018 ANSSI. All Rights Reserved.
/**
 * @file
 * @author Frederic Gauche <clipos@ssi.gouv.fr>
 * @author Olivier Levillain <clipos@ssi.gouv.fr>
 *
 * @section DESCRIPTION
 *
 * This file contains the error messages used when exceptions arise.
 */


#include "anssipki-common.h"



static const char* errorMessages[E_NB_ERRORS] = {
  /* String errors */
  // E_INVALID_STRING_OPERATION,
  "Opération invalide sur une chaîne de caractère",
  // E_INVALID_HEXA_STRING,
  "La chaîne de caractère n'est pas une chaîne valide de caractères hexadécimaux",
  // E_INVALID_BIGNUM,
  "La chaîne de caractère n'est pas une chaîne valide codant un grand entier",
  // E_NO_SLASH_FOUND,
  "La chaîne de caractère ne contient pas de caractère '/'",
  // E_BAD_EXTENSION,
  "La chaîne de caractère ne se termine pas par l'extension attendue",

  /* DER Format errors */
  // E_DER_INVALID_FILE,
  "Format du fichier DER invalide",
  // E_DER_SEQUENCE_EXPECTED,
  "Champ de type séquence attendu",
  // E_DER_SET_EXPECTED,
  "Champ de type ensemble (\"set\") attendu",
  // E_DER_OID_EXPECTED,
  "Identifiant d'objet (\"OID\") attendu",
  // E_INVALID_CERTIFICATE,
  "Format de certificat ou de liste de révocation inconnu",

  /* Cryptographic errors */
  // E_CRYPTO_BAD_PARAMETER,
  "Paramètres cryptographique incorrect",
  // E_CRYPTO_PRNG_STATE_ERROR,
  "Erreur lors de l'accès au fichier contenant l'état du générateur d'aléa",
  // E_CRYPTO_INTERNAL_MAYHEM,
  "Une erreur de cohérence interne du moteur cryptographique a été détectée",
  

  /* Erreur inattendue */
  // E_NOT_IMPLEMENTED,
  "Fonctionalité non implantée",
  // E_UNEXPECTED_ERROR,
  "Erreur inattendue",
  // E_UNKNOWN_ERROR
  "Erreur inconnue",
};




ANSSIPKIException::ANSSIPKIException (const exception_t e) : _errNo (e) {
  if (_errNo < 0 || _errNo >= E_NB_ERRORS)
    _errNo = E_UNKNOWN_ERROR;
}
  
ANSSIPKIException::ANSSIPKIException (const exception_t e, const String& details) : _errNo (e) {
  if (_errNo < 0 || _errNo >= E_NB_ERRORS)
    _errNo = E_UNKNOWN_ERROR;

  if (details.size() > 0) {
    _details = String (errorMessages[_errNo]) + " : " + details;
  }
}
  

const char* ANSSIPKIException::what () const throw () {
  if (_details.size() > 0)
    return _details.toChar();
  else {
    return errorMessages[_errNo];
  }
}
