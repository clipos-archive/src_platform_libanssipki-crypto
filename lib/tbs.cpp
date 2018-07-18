// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2000-2018 ANSSI. All Rights Reserved.
/************************************************************************

   tbs.cpp

   La classe abstraite TBS définit l'interface nécessaire pour une
   classe gérant un bloc de données à signer (haché, affichage,
   algorithme de signature).

   Frédéric Gauche
   DCSSI/SDS/LTI
   2000 - 2001

   Olivier Levillain
   DCSSI/SDS/LTI
   2008

************************************************************************/


#include "anssipki-asn1.h"
using namespace ANSSIPKI_ASN1;



////////////////
// Classe TBS //
////////////////


const String TBS::appendSignatureToDER (const String& signature) const {
  String padding;
  padding.resize(1);
  ANSSIPKI_ASN1::ASN1_BASIC sign_bstr (C_UNIV, M_PRIM, T_BSTR, (padding + signature));

  return (encapsulate(toDER() + encapsulate (ASN1_SIGN_ALGO(get_sign_algo()).toDER(), T_SEQU) + sign_bstr.toDER(), T_SEQU));
}



/** get_serial_no : renvoie le numéro de série */
const ANSSIPKI_ASN1::ASN1_BASIC TBS::get_serial_no () const {
  throw UnexpectedError ("Appel de get_serial_no sur un bloc de données à signer invalide.");
}
