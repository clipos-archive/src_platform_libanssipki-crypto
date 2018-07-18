// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2000-2018 ANSSI. All Rights Reserved.
/************************************************************************

   asn1.cpp

   Ce fichier contient un ensemble de classes permettant
   l'interprétation de fichiers au format ASN.1 (encodés en DER).

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
// Constantes //
////////////////


// Constantes pour l'affichage
//----------------------------

// T_NULL
const char str_null[] = "<Element vide>";

// T_SEQU
const char str_sequ[] = "Séquence";

// T_SET
const char str_sets[] = "Ensemble";

// T_BSTR
const char str_bstr[] = "Chaîne de bits";

// T_OIDR
const char str_oid_unknown[] = "Identifiant d'objet (OID) inconnu";




//////////////////////
// Fonctions utiles //
//////////////////////



hash_algo hashAlgo (const sign_algo sa) {
  switch (sa) {
  case S_ALGO_SHA1RSA:
    return H_ALGO_SHA1;
  case S_ALGO_SHA256RSA:
    return H_ALGO_SHA256;
  case S_ALGO_SHA512RSA:
    return H_ALGO_SHA512;
  default:
    throw NotImplemented ("Unknown signature algorithm");
  }
}

pubkey_algo pubkeyAlgo (const sign_algo sa) {
  switch (sa) {
  case S_ALGO_SHA1RSA:
  case S_ALGO_SHA256RSA:
  case S_ALGO_SHA512RSA:
    return PK_ALGO_RSA;
  default:
    throw NotImplemented ("Unknown signature algorithm");
  }
}

sign_algo sigAlgo (const hash_algo ha, const pubkey_algo pka) {
  switch (pka) {

  case PK_ALGO_RSA:
    switch (ha) {
    case H_ALGO_SHA1:
      return S_ALGO_SHA1RSA;
    case H_ALGO_SHA256:
      return S_ALGO_SHA256RSA;
    case H_ALGO_SHA512:
      return S_ALGO_SHA512RSA;
    default:
      throw NotImplemented ("Invalid combination of a public key algorithm and a hash function");
    }

  default:
    throw NotImplemented ("Unknown public key algorithm");
  }
}



const String
INTtoASN1_BSTR(unsigned int flags, size_t length) {
  unsigned int ibstr = 0;
  size_t newLength = length;
  unsigned char paddingLength = 0;
  size_t resLength;
  String res;

  if (length > 32)
    throw UnexpectedError("INTtoASN1_BSTR length should not be > 32");


  while ((newLength > 0) && ! (flags & (0x01 << (newLength - 1))))
    --newLength;

  paddingLength = (8 - (newLength % 8)) % 8;

  for (size_t i = newLength; i > 0; --i)
  {
    unsigned int bit = flags & (0x01 << (i - 1));
    if (bit)
      ibstr = ibstr | (0x01 << (paddingLength + newLength - i));
  }


  resLength = 1 + (newLength + paddingLength) / 8;
  res.resize(resLength);
  res.pushChar(paddingLength);
  for (size_t i = resLength - 1; i > 0; --i)
    res.pushChar(((unsigned char*)(&ibstr))[i - 1]);
  return res;
}


unsigned int
ASN1_BSTRtoINT(const String bstr, size_t& bfLength) {
  unsigned int ibstr = 0;
  const char* c_bstr;
  unsigned char paddingLength = 0;

  c_bstr = bstr.toChar();
  paddingLength = c_bstr[0];
  c_bstr++;
  bfLength = (bstr.size() - 1) * 8 - paddingLength;

  if (bfLength > 32)
    throw UnexpectedError("INTtoASN1_BSTR bfLength should not be > 32");

  for (size_t i = bfLength; i > 0; --i)
  {
    unsigned int bit = c_bstr[(i - 1) / 8] & (0x01 << ( (8 - (i % 8)) % 8));
    if (bit)
      ibstr = ibstr | (0x01 << (i - 1));
  }

  return ibstr;
}



/** getTagNumber (uchar) : renvoie le "tag number" contenu dans un
    octet donné
 */
static inline asn1_tagnumber getTagNumber (const asn1_class c, const char idOctet) {
  // On ne prend pas en compte les tag numbers supérieurs à 30
  if ((idOctet & 0x1F) == 0x1F)
    throw NotImplemented ("Unknown object type");

  asn1_tagnumber tmp = (asn1_tagnumber) (idOctet & 0x1F);
  if (c == C_UNIV) {
  switch (tmp) {
  case T_BOOL:
  case T_INTG:
  case T_BSTR:
  case T_OSTR:
  case T_NULL:
  case T_OIDR:
  case T_UTF8:
  case T_SEQU:
  case T_SETS:
  case T_PRTS:
  case T_T61S:
  case T_IA5S:
  case T_UTCT:
  case T_GENT:
    return tmp;
  default:
    throw NotImplemented ("Unknown object type");
  }
}
  else
    return tmp;
}


/** dateToString (String&) renvoie une version lisible d'un champ date
    ASN.1 au format T_TIME (YYMMDDHHMMZ) */
static inline String dateToString (const String& date) {

  // TODO: Corriger ça !

  try {
    date.initIndex();
    const String year = date.popSubstring (2);
    const String month = date.popSubstring (2);
    const String day = date.popSubstring (2);
    const String hour = date.popSubstring (2);
    const String minute = date.popSubstring (2);
    String second ("00");

    // Si le format contient les secondes, on continue, on renvoie la version originale
    if (date.getChar() != 'Z' && (! date.eof())) { 
      second = date.popSubstring (2);
    }
     
    // Si le format est mauvais, on renvoie la version originale
    if (date.popChar() != 'Z' || (! date.eof())) {
      return date;
    }

    // Sinon, on renvoie la date sous une forme plus lisible
    return (String ("le ") + day + "/" + month + "/20" + year + " à " + hour + ":" + minute + ":" + second);
  } catch (ANSSIPKIException& e) {
    // Si le format est mauvais, on renvoie la version originale
    return date;
  }
}


/** getSize : renvoie la taille d'un objet pointé dans une chaîne DER
    et avance l'index de la chaîne sur l'objet proprement dit (qui
    suit le champ de taille)

    Paramètres
       DERstring : chaîne au format DER dont l'index pointe sur la taille d'un objet
    Valeur de retour
       la taille de l'objet pointé
    Exception possible
       E_DER_INVALID_FILE en cas de sous-chaîne invalide
       E_DER_SIZE_TOO_LONG si la taille ne tient pas sur 32 bits
*/
static inline size_t getSize (const String& DERString) {
  try {
    char sizeCode = DERString.getChar ();
    if (sizeCode & 0x80) {
      sizeCode &= 0x7f;
      DERString.popChar();
    } else {
      sizeCode = 1;
    }
    
    size_t size = 0;
    if (sizeCode >= 5) {    // Nous n'utiliserons que la forme courte
                            // ici (longueur sur au plus 32 bits)
      throw NotImplemented ("ASN1 object is too big");
    }
    
    while (sizeCode)
      size |= (DERString.popChar() & 0xff) << (8 * (--sizeCode));
    
    return size;
  } catch (ANSSIPKIException& e) {
    if (e.errNo() == E_OUT_OF_BOUNDS_STRING_OPERATION)
      throw ANSSIPKIException (E_DER_INVALID_FILE, "Reached end of file too early");
    else
      throw UnexpectedError (e.what());
  }
}


/** decapsulate ouvre le conteneur DER pointé par l'index de DERString
    et en renvoie le contenu dans une nouvelle chaîne de
    caractères. L'indice de la chaîne initiale est avancé à l'objet
    suivant le conteneur.

    Paramètres
       DERstring : chaîne au format DER pointant sur un conteneur
       t : TagNumber du conteneur (par ex.: T_SETS ou T_SEQU)
    Valeur de retour
       une chaîne de caractères représentant le contenu
    Exception possible
       E_DER_INVALID_FILE en cas de sous-chaîne invalide
       E_DER_SIZE_TOO_LONG si la taille du champ ne tient pas sur 32 bits
       E_DER_SET_EXPECTED ou E_DER_SEQUENCE_EXPECTED si l'objet à décapsuler est incorrect
*/
const String decapsulate (const String& DERString, const asn1_tagnumber t) {
  try {
    // TODO: Should this also extract the class?
    if (getTagNumber (C_UNIV, DERString.popChar()) != t) {
      switch (t) {
      case T_SETS: throw DERSetExpected ();
      case T_SEQU: throw DERSequenceExpected ();
      default: throw NotImplemented ("asn1.decapsulate expects T_SETS or T_SEQU.");
      }
    }

    const size_t sz = getSize (DERString);
    return (DERString.popSubstring (sz));
  } catch (ANSSIPKIException& e) {
    if (e.errNo() == E_OUT_OF_BOUNDS_STRING_OPERATION)
      throw ANSSIPKIException (E_DER_INVALID_FILE, "Reached end of file too early");
    else
      throw UnexpectedError (e.what());
  }
}


/** encapsulate crée l'ASN1_BASIC adéquat autour d'une chaîne
    DERString et renvoie la chaîne au format DER correspondante.

    Paramètres
       DERstring : chaîne au format DER pointant sur un contenu à encapsuler
       t : TagNumber du conteneur (par ex.: T_SETS ou T_SEQU)
    Valeur de retour
       une chaîne de caractères représentant le contenant avec le contenu
*/
const String encapsulate (const String& DERString, const asn1_tagnumber t, const asn1_class c /* = C_UNIV (par defaut) */) {
  ASN1_BASIC res (c, M_CONS, t, DERString);
  return res.toDER();
}


/** compareOIDs (String&, asn1_oid&) compare la valeur de la chaîne de
    caractère avec l'OID donné. */
inline bool compareOIDs (const String& val, const asn1_oid& oid) {
  const String strOID = String (oid.hoid, oid.len);
  return (val == strOID);
}


/** getOID (String&, asn1_oid&) renvoie vrai si l'objet asn1_oid est
    connu ; dans ce cas, l'objet asn1_oid correspondant est renseigné
    dans le paramètre.
*/
inline bool getOID (const String& value, asn1_oid& oid) {
  int i;
  for (i=0; i<nDNOIDs; i++) {
    if (compareOIDs (value, DNOIDs[i])) {
      oid = DNOIDs[i];
      return true;
    }
  }

  for (i=0; i<nSignAlgos; i++) {
    if (compareOIDs (value, signAlgoOIDs[i])) {
      oid = signAlgoOIDs[i];
      return true;
    }
  }
  for (i=0; i<nHashAlgos; i++) {
    if (compareOIDs (value, hashAlgoOIDs[i])) {
      oid = hashAlgoOIDs[i];
      return true;
    }
  }
  for (i=0; i<nPubKeyAlgos; i++) {
    if (compareOIDs (value, pubKeyAlgoOIDs[i])) {
      oid = pubKeyAlgoOIDs[i];
      return true;
    }
  }

  for (i=0; i<nExtensionIds; i++) {
    if (compareOIDs (value, extensionOIDs[i])) {
      oid = extensionOIDs[i];
      return true;
    }
  }

  return false;
}




///////////////////////
// Classe ASN1_BASIC //
///////////////////////


/** ASN1_BASIC (asn1_class, asn1_method, asn1_tagnumber, String&) : constructeur trivial */
ASN1_BASIC::ASN1_BASIC (const asn1_class c, const asn1_method m,
			const asn1_tagnumber n, const String& v /* = String() (par defaut) */)
  : classe (c), method (m), tagNumber (n) {

  // On traite à part le cas des entiers.
  if (c == C_UNIV && m == M_PRIM && n == T_INTG) {
    size_t sz = v.size();
    v.initIndex();

    // On commence par supprimer tous les zéros inutiles
    while (sz > 0 && v.getChar() == 0) {
      sz--;
      v.popChar();
    }

    // Comme nous ne manipulons QUE des entiers positifs, il faut
    // prendre garde que le bit de poids fort ne soit pas pris pour un
    // bit de signe : si le caractère de poids fort à son bit de poids
    // fort à 1, il nous faut donc ajouter un octet nul avant.
    String padding;
    if ((sz > 0) && (v.getChar() & 0x80) != 0)
      padding.resize(1);

    value = padding + v.popSubstring (sz);

  } else
    // Dans les autres cas, une simple copie de la valeur suffit.
    value = v;
}


/** ASN1_BASIC (asn1_oid) : constructeur d'object identifier */
ASN1_BASIC::ASN1_BASIC (const asn1_oid& oid)
  : classe (C_UNIV), method (M_PRIM), tagNumber (T_OIDR), value (oid.hoid, oid.len) {}



/** ASN1_BASIC : construit un élément ASN.1 à partir d'une chaîne au
    format DER. L'index de la chaîne est mis à jour.

    Paramètres
       DERstring : chaîne au format DER pointant sur un élément ASN.1
    Exception possible
       E_DER_INVALID_FILE en cas de sous-chaîne invalide
       E_DER_SIZE_TOO_LONG si la taille ne tient pas sur 32 bits
*/
ASN1_BASIC::ASN1_BASIC (const String& DERString) {
  try {
    const char idOctet = DERString.popChar();
    classe = (asn1_class) ((idOctet & 0xC0) >> 6);
    method = (asn1_method) ((idOctet & 0x20) >> 5);
    tagNumber = getTagNumber (classe, idOctet);

    size_t sz = getSize (DERString);
    value = DERString.popSubstring (sz);
  } catch (ANSSIPKIException& e) {
    if (e.errNo() == E_OUT_OF_BOUNDS_STRING_OPERATION)
      throw ANSSIPKIException (E_DER_INVALID_FILE, "Reached end of file too early");
    else
      throw UnexpectedError (e.what());
  }
}


/** makeAndCheckBasic : construit et renvoie un élément ASN.1 à partir
    d'une chaîne au format DER, après avoir vérifier que la classe, la
    méthode et le tag number étaient bien ceux attendus. L'index de la
    chaîne est mis à jour.

    Paramètres
       c, m, n : paramètres à vérifier
       DERstring : chaîne au format DER pointant sur un élément ASN.1
       value : valeure attendue (fonction makeAndCheckBasic surchargée)
    Exception possible
       E_DER_INVALID_FILE en cas de sous-chaîne invalide
       E_DER_SIZE_TOO_LONG si la taille ne tient pas sur 32 bits
*/
ASN1_BASIC ASN1_BASIC::makeAndCheckBasic (const asn1_class c, const asn1_method m,
					  const asn1_tagnumber n, const String& DERString,
					  const ANSSIPKIException& e) {
  ASN1_BASIC res (DERString);
  if (res.classe != c || res.method != m || res.tagNumber != n)
    throw e;
  return res;
}

ASN1_BASIC ASN1_BASIC::makeAndCheckBasic (const asn1_class c, const asn1_method m,
					  const asn1_tagnumber n, const String& DERString,
					  const String& v, const ANSSIPKIException& e) {
  ASN1_BASIC res (DERString);
  if (res.classe != c || res.method != m || res.tagNumber != n || (! (res.value == v)))
    throw e;
  return res;
}



/** toDER : produit une chaîne de caractères au format DER représentant
    l'élément. */
const String ASN1_BASIC::toDER() const {
  size_t sizeLen = 0;
  size_t valLen = value.size();

  if (valLen < 128) {
    sizeLen = 1;
  } else {
    size_t tmp = valLen;
    sizeLen = 1;
    while (tmp) {
      sizeLen++;
      tmp >>=8;
    }
  }


  String res;
  res.resize (1 + sizeLen + valLen);
  res.initIndex();

  // On construit l'octet identifiant (1 octet)
  res.pushChar ((char) (((classe & 0x03) << 6) | ((method & 0x01) << 5) | (tagNumber & 0x1F)));

  // On écrit la taille (sizeLen octets)
  if (valLen < 128) {
    res.pushChar ((char) valLen);
  } else {
    sizeLen--;
    res.pushChar ((char) (0x80 | sizeLen));
    while (sizeLen) {
      sizeLen--;
      res.pushChar ((char) ((valLen >> (8 * sizeLen)) & 0xFF) );
    }
  }

  // Enfin, on écrit la valeur (valLen octets)
  res.pushString (value);
  res.initIndex();

  return res;
}



/** toString : produit une chaîne de caractères lisible destinée à un
    affichage. */
const String ASN1_BASIC::toString() const {
  String res;
  char c;
  long n;
  asn1_oid oid;

  switch (tagNumber) {
  case T_NULL:
    return String (str_null);

  case T_OSTR:
  case T_INTG: {
    res = String (value);
    res.bignumToAsciiHexa(':');
    return res;
  }

  case T_SEQU:
    return String (str_sequ);

  case T_SETS:
    return String (str_sets);

  case T_BSTR:
    return String (str_bstr);

  case T_OIDR:
    if (getOID (value, oid))
      return oid.desc;

    // Cas du déchiffrement de l'OID
    if (value.size() < 2)
      throw UnexpectedError ("ASN1_BASIC::toString reached an invalid OID.");
    value.initIndex();
    res = String ( (c = value.popChar()) / 40, 1) + ".";
    res += String (c % 40, 1);
    try {
      while (!value.eof()) {
	n = 0;
	while (((c = value.popChar()) & 0x80) != 0) {
	  n += c & 0x7f;
	  n *= 0x80;
	}
	n += c & 0x7f;
	res += String (".") + String ((uint)n, 1);
      }
    } catch (ANSSIPKIException e) {
      throw UnexpectedError ("ASN1_BASIC::toString reached an invalid OID.");
    }
    return res;

  case T_PRTS:
  case T_IA5S:
  case T_T61S:
  case T_UTF8:
    return value;

  case T_UTCT:
  case T_GENT:
    return dateToString (value);

  case T_BOOL:
  default:
    throw NotImplemented ("ASN1_BASIC::toString on some tagNumbers.");
  }
}






/////////////////////////
// Classe ASN1_VERSION //
/////////////////////////


/* Un élément codant la version a la structure suivante :

   | CONTEXT SPE (conteneur)
   | | INTEGER (1 octet) : numéro de version
*/



/** ASN1_VERSION (uchar) : construit un élément version à partir d'un entier entre 1 et 3 */
ASN1_VERSION::ASN1_VERSION (const int v)
  : ASN1_BASIC (C_CSPE, M_CONS, (asn1_tagnumber) 0), version (v) {
  if (v == 0 || v > 3)
    throw DERUnknownCertFormat ("Only X.509 versions 1 to 3 are accepted.");

  char tmp = (char) (v - 1);
  value = ASN1_BASIC (C_UNIV, M_PRIM, T_INTG, String (&tmp, 1)).toDER();
}


/** ASN1_VERSION (String&,) : extrait un élément ASN.1 codant la
    version X509 utilisée d'une chaîne au format DER. L'index de la
    chaîne est mis à jour.

    Paramètres
       DERstring : chaîne au format DER pointant sur l'élément codant la version
    Exception possible
       E_DER_INVALID_FILE en cas de sous-chaîne invalide
       E_DER_SIZE_TOO_LONG si la taille ne tient pas sur 32 bits
       E_UNKNOWN_CERT_FORMAT si le champ version est absent ou incorrect
*/
ASN1_VERSION::ASN1_VERSION (const String& DERString)
  // Dans le cadre d'un élément composé ASN1 Context Specific, le
  // tagNumber sert d'indice pour numéroter ces sections spécifiques
  // (0 : version, 3 : extensions par ex.:) dans le cas d'un certificat.
  : ASN1_BASIC (makeAndCheckBasic (C_CSPE, M_CONS, (asn1_tagnumber) 0, DERString,
				   DERUnknownCertFormat ("Le champ version est absent."))) {

  const ASN1_BASIC vers = makeAndCheckBasic (C_UNIV, M_PRIM, T_INTG, value,
					     DERUnknownCertFormat ("Le champ version est incorrect."));

  if (vers.value.size() != 1)
    throw DERUnknownCertFormat ("Incorrect version field.");

  version = vers.value.getChar() + 1;
  if (version == 0 || version > 3)
    throw DERUnknownCertFormat ("Only X.509 versions 1 to 3 are accepted.");
}
 
 
/** toString : produit une chaîne de caractères lisible. */
const String ASN1_VERSION::toString () const {
  String res ("Version : ");
  res += String (version, 1);
  res += "\n";
  return res;
}




 
/////////////////////////
// Classe ASN1_INTEGER //
/////////////////////////


/** ASN1_INTEGER (mpz_t) : construit un élément codant un entier à
    partir d'un entier GMP */

ASN1_INTEGER::ASN1_INTEGER (const mpz_t n)
  : ASN1_BASIC (C_UNIV, M_PRIM, T_INTG) {

  value = String (n, String::ENC_BINARY);

  // Eventuellement, on ajoute un octet nul au début
  value.initIndex();
  if (value.getChar() & 0x80) {
    char padding = 0;
    value = String (&padding, 1) + value;
  }
}

/** ASN1_INTEGER (const char* raw, size_t size) : construit un élément codant un entier à
    partir d'un grand entier */

ASN1_INTEGER::ASN1_INTEGER (String raw)
  : ASN1_BASIC (C_UNIV, M_PRIM, T_INTG) {

  value = raw;
}

////////////////////////
// Classe ASN1_OBJECT //
////////////////////////


/* Un objet ASN.1 a la structure suivante :

   | OBJECT IDENTIFIER
   | <valeur de l'objet>
*/



/** ASN1_OBJECT : construit un objet ASN.1 à partir d'un Object
    Identifier, d'une valeur et d'un tagnumber.

    Paramètres
       oid : identifiant de l'objet
       value : valeur (vide par défaut)
       tag : tagNumber à associer à la valeur (T_CHAR par défaut)
*/
ASN1_OBJECT::ASN1_OBJECT (const asn1_oid& oid, const String& value, const asn1_tagnumber tag /* = T_CHAR (par defaut) */)
  : objectType (oid), object (C_UNIV, M_PRIM, tag, value) {}



/** ASN1_OBJECT : construit un objet ASN.1 à partir d'une chaîne au
    format DER. L'index de la chaîne est mis à jour.

    Paramètres
       DERstring : chaîne au format DER pointant sur un élément ASN.1
    Exception possible
       E_DER_INVALID_FILE en cas de sous-chaîne invalide
       E_DER_SIZE_TOO_LONG si la taille ne tient pas sur 32 bits
       E_OID_EXPECTED si le premier élément rencontré n'est pas un Object Identifier
*/
ASN1_OBJECT::ASN1_OBJECT (const String& DERString)
  : objectType (ASN1_BASIC::makeAndCheckBasic (C_UNIV, M_PRIM, T_OIDR, DERString,
					       DEROIDExpected ())),
    object (DERString) {

  asn1_oid oid;
  if (getOID (objectType.value, oid)) {
    switch (oid.tag_expected) {
    case TE_NULL:
      if (object.classe != C_UNIV || object.method != M_PRIM || object.tagNumber != T_NULL)
	throw ANSSIPKIException (E_DER_INVALID_FILE, "Null object expected.");
      break;
    case TE_STRING:
      if (object.classe != C_UNIV || object.method != M_PRIM || 
	  (object.tagNumber != T_PRTS && object.tagNumber != T_IA5S &&
	   object.tagNumber != T_T61S && object.tagNumber != T_UTF8))
	throw ANSSIPKIException (E_DER_INVALID_FILE, "Character string object expected.");
      break;
    case TE_OCTETSTRING:
      throw NotImplemented ("ASN1_Object constructor (DERString) with TE_OCTETSTRING");
    default:
      throw UnexpectedError ("The expected type of the object was not correctly specified.");
    }
  }
}


/** toDER : produit une chaîne de caractères au format DER représentant
    l'objet. */
const String ASN1_OBJECT::toDER () const {
  return (objectType.toDER() + object.toDER());
}


/** toString : produit une chaîne de caractères lisible destinée à un
    affichage. */
const String ASN1_OBJECT::toString () const {
  return (objectType.toString() + " : " + object.toString() + "\n");
}







///////////////////////////
// Classe ASN1_SIGN_ALGO //
///////////////////////////


/* Un objet décrivant un algorithme de signature a la structure
   suivante :

   | OBJECT IDENTIFIER : <identifiant de l'algorithme>
   | NULL
*/



/** ASN1_SIGN_ALGO : construit un objet ASN.1 codant un algorithme de
    signature à partir de la numérotation interne (voir asn1.h) */
ASN1_SIGN_ALGO::ASN1_SIGN_ALGO (const sign_algo sign_algo)
  : ASN1_OBJECT (signAlgoOIDs[sign_algo], String(), T_NULL), sa (sign_algo) {}


/** ASN1_SIGN_ALGO : construit un objet ASN.1 codant un algorithme de
    signature à partir d'une chaîne au format DER. L'index de la
    chaîne est mis à jour.

    Paramètres
       DERstring : chaîne au format DER pointant sur un élément ASN.1
    Exception possible
       E_DER_INVALID_FILE en cas de sous-chaîne invalide
       E_DER_SIZE_TOO_LONG si la taille ne tient pas sur 32 bits
       E_OID_EXPECTED si le premier élément rencontré n'est pas un Object Identifier
*/
ASN1_SIGN_ALGO::ASN1_SIGN_ALGO (const String& DERString)
  : ASN1_OBJECT (DERString)
{
  for (int i=0; i<nSignAlgos; i++)
    if (compareOIDs (objectType.value, signAlgoOIDs[i])) {
      sa = (sign_algo) i;
      return;
    }

  throw NotImplemented ("Unknown signature algorithm");
}


/** toString : produit une chaîne de caractères lisible destinée à un
    affichage. */
const String ASN1_SIGN_ALGO::toString () const {
  return (String ("Algorithme de signature : ") + objectType.toString() + "\n");
}






//////////////////////////////
// Classe ASN1_HASH_ALGO //
//////////////////////////////


/* Un objet décrivant un algorithme de hachage a la structure suivante :

   | OBJECT IDENTIFIER : <identifiant de l'algorithme>
   | NULL
*/



/** ASN1_HASH_ALGO : construit un objet ASN.1 codant un algorithme de
    signature à partir de la numérotation interne (voir asn1.h) */
ASN1_HASH_ALGO::ASN1_HASH_ALGO (const hash_algo hash_algo)
  : ASN1_OBJECT (hashAlgoOIDs[hash_algo], String(), T_NULL), ha (hash_algo) {}


/** toString : produit une chaîne de caractères lisible destinée à un
    affichage. */
const String ASN1_HASH_ALGO::toString () const {
  return (String ("Algorithme de chiffrement asymétrique : ") + objectType.toString() + "\n");
}


/** ASN1_HASH_ALGO : construit un objet ASN.1 codant une fonction de
    hashage à partir d'une chaîne au format DER. L'index de la
    chaîne est mis à jour.

    Paramètres
       DERstring : chaîne au format DER pointant sur un élément ASN.1
    Exception possible
       E_DER_INVALID_FILE en cas de sous-chaîne invalide
       E_DER_SIZE_TOO_LONG si la taille ne tient pas sur 32 bits
       E_OID_EXPECTED si le premier élément rencontré n'est pas un Object Identifier
*/
ASN1_HASH_ALGO::ASN1_HASH_ALGO (const String& DERString)
  : ASN1_OBJECT (DERString)
{
  for (int i=0; i<nHashAlgos; i++)
    if (compareOIDs (objectType.value, hashAlgoOIDs[i])) {
      ha = (hash_algo) i;
      return;
    }

  throw NotImplemented ("Unknown encryption algorithm");
}





//////////////////////////////
// Classe ASN1_ENCRYPT_ALGO //
//////////////////////////////


/* Un objet décrivant un algorithme de chiffrement asymétrique a la
   structure suivante :

   | OBJECT IDENTIFIER : <identifiant de l'algorithme>
   | NULL
*/



/** ASN1_ENCRYPT_ALGO : construit un objet ASN.1 codant un algorithme de
    signature à partir de la numérotation interne (voir asn1.h) */
ASN1_ENCRYPT_ALGO::ASN1_ENCRYPT_ALGO (const pubkey_algo pubkey_algo)
  : ASN1_OBJECT (pubKeyAlgoOIDs[pubkey_algo], String(), T_NULL), pka (pubkey_algo) {}


/** toString : produit une chaîne de caractères lisible destinée à un
    affichage. */
const String ASN1_ENCRYPT_ALGO::toString () const {
  return (String ("Algorithme de chiffrement asymétrique : ") + objectType.toString() + "\n");
}

/** ASN1_ENCRYPT_ALGO : construit un objet ASN.1 codant un algorithme de
    chiffrement à partir d'une chaîne au format DER. L'index de la
    chaîne est mis à jour.

    Paramètres
       DERstring : chaîne au format DER pointant sur un élément ASN.1
    Exception possible
       E_DER_INVALID_FILE en cas de sous-chaîne invalide
       E_DER_SIZE_TOO_LONG si la taille ne tient pas sur 32 bits
       E_OID_EXPECTED si le premier élément rencontré n'est pas un Object Identifier
*/
ASN1_ENCRYPT_ALGO::ASN1_ENCRYPT_ALGO (const String& DERString)
  : ASN1_OBJECT (DERString)
{
  for (int i=0; i<nPubKeyAlgos; i++)
    if (compareOIDs (objectType.value, pubKeyAlgoOIDs[i])) {
      pka = (pubkey_algo) i;
      return;
    }

  throw NotImplemented ("Unknown encryption algorithm");
}




////////////////////
// Classe ASN1_DN //
////////////////////


/* Un Distinguished Name ASN.1 a la structure suivante (certains
   champs sont optionnels et certains peuvent être définis de façon
   multiple :

   SEQUENCE
   | SET
   | | SEQUENCE
   | | | OBJECT IDENTIFIER : Country Name
   | | | CHAR : <nom du pays>
   | SET
   | | SEQUENCE
   | | | OBJECT IDENTIFIER : State or Province Name
   | | | CHAR : <nom de la province>
   | SET
   | | SEQUENCE
   | | | OBJECT IDENTIFIER : Locality Name
   | | | CHAR : <nom de la localité>
   | SET
   | | SEQUENCE
   | | | OBJECT IDENTIFIER : Organization Name
   | | | CHAR : <nom de l'organisation>
   | SET
   | | SEQUENCE
   | | | OBJECT IDENTIFIER : Organizational Unit Name
   | | | CHAR : <nom de l'unité>
   | SET
   | | SEQUENCE
   | | | OBJECT IDENTIFIER : Common Name
   | | | CHAR : <nom commun (par ex.: adresse web pour un site)>
   | SET
   | | SEQUENCE
   | | | OBJECT IDENTIFIER : E-Mail
   | | | CHAR : <adresse électronique>
*/



// Méthodes de ASN1_DN
//--------------------


/** ASN1_DN : Constructeur trivial à partir de chaînes de caractères */
ASN1_DN::ASN1_DN () {
  nFields = 0;
  unknownFields = false;
}

/** ASN1_DN : Constructeur par copie */
ASN1_DN::ASN1_DN (const ASN1_DN& dn)
  : unknownFields (dn.unknownFields), nFields (dn.nFields)
{
  if (unknownFields >= MAX_DN_ATTRIBUTES)
    unknownFields = MAX_DN_ATTRIBUTES - 1;

  for (unsigned int i=0; i<nFields; i++)
    fields[i]=new ASN1_OBJECT (*dn.fields[i]);
}

/** ASN1_DN : Destructeur */
ASN1_DN::~ASN1_DN () {
  for (unsigned int i=0; i<nFields; i++)
    delete (fields[i]);
}

/** ASN1_DN : construit un objet Distinguished Name ASN.1 à partir
    d'une chaîne au format DER. L'index de la chaîne est mis à jour.

    Paramètres
       DERstring : chaîne au format DER pointant sur un élément ASN.1
    Exception possible
       E_DER_INVALID_FILE en cas de sous-chaîne non conforme au format DER
       E_DER_SIZE_TOO_LONG si la taille ne tient pas sur 32 bits
       E_OID_EXPECTED si le premier élément rencontré n'est pas un Object Identifier
*/
ASN1_DN::ASN1_DN (const String& DERString) {
  nFields = 0;
  unknownFields = false;

  try {
    String issuerContent = decapsulate (DERString, T_SEQU);
    
    while (! issuerContent.eof()) {
      String setContent = decapsulate (issuerContent, T_SETS);
      String seqContent = decapsulate (setContent, T_SEQU);
      ASN1_OBJECT o (seqContent);
      bool fieldOK = false;

      for (int i=0; i<nDNOIDs; i++) {
	if (compareOIDs (o.objectType.value, DNOIDs[i])) {
	  add (new ASN1_OBJECT (o));
	  fieldOK = true;
	}
      }

      if (!fieldOK) {
	// On ignore les champs inconnus pour l'affichage, mais on le signale
	unknownFields = true;

	// TODO: Gestion des avertissements ?
	//	message (M_AVERTISSEMENT, "Le nom distinctif contient des attributs non reconnus.");
      }
    }
  } catch (DEROIDExpected& e) {
    throw ANSSIPKIException (E_DER_INVALID_FILE, "Champ Distinguished Name mal formé.");
  } catch (DERSequenceExpected& e) {
    throw ANSSIPKIException (E_DER_INVALID_FILE, "Champ Distinguished Name mal formé.");
  } catch (DERSetExpected& e) {
    throw ANSSIPKIException (E_DER_INVALID_FILE, "Champ Distinguished Name mal formé.");
  } catch (ANSSIPKIException& e) {
    throw UnexpectedError (e.what());
  }
}


/** add et addXXX : méthodes d'ajout de champs dans le Distinguished Name */
void ASN1_DN::add (const ASN1_OBJECT* const o) {
  if (nFields < MAX_DN_ATTRIBUTES) {
    fields[nFields++] = o;
  } else if (nFields == MAX_DN_ATTRIBUTES) {
    throw UnexpectedError (String ("le nom distinctif contient plus de ") +
			   String (MAX_DN_ATTRIBUTES, 1) + " attributs ! Seuls les " +
			   String (MAX_DN_ATTRIBUTES, 1) + " premiers sont pris en compte.");
  }
}

void ASN1_DN::addCountry (const String& c, const asn1_tagnumber tag) {
  add (new ASN1_OBJECT (DNOIDs[OID_COUNTRY_NAME], c, tag));
}

void ASN1_DN::addState (const String& s, const asn1_tagnumber tag) {
  add (new ASN1_OBJECT (DNOIDs[OID_STATE_OR_PROVINCE_NAME], s, tag));
}

void ASN1_DN::addLocation (const String& l, const asn1_tagnumber tag) {
  add (new ASN1_OBJECT (DNOIDs[OID_LOCALITY_NAME], l, tag));
}

void ASN1_DN::addOrganization (const String& o, const asn1_tagnumber tag) {
  add (new ASN1_OBJECT (DNOIDs[OID_ORGANIZATION_NAME], o, tag));
}

void ASN1_DN::addOrganizationUnit (const String& ou, const asn1_tagnumber tag) {
  add (new ASN1_OBJECT (DNOIDs[OID_ORGANIZATIONAL_UNIT_NAME], ou, tag));
}

void ASN1_DN::addCommonName (const String& cn, const asn1_tagnumber tag) {
  add (new ASN1_OBJECT (DNOIDs[OID_COMMON_NAME], cn, tag));
}

void ASN1_DN::addEMail (const String& em, const asn1_tagnumber tag) {
  add (new ASN1_OBJECT (DNOIDs[OID_RSA_EMAIL_ADDR_NAME], em, tag));
}




/** toDER : produit une chaîne de caractères au format DER représentant
    le Distinquished Name. */
const String ASN1_DN::toDER () const {
  String res;

  for (unsigned int i=0; i<nFields; i++)
    res += encapsulate (encapsulate (fields[i]->toDER(), T_SEQU), T_SETS);

  return encapsulate (res, T_SEQU);
}



/** toString : produit une chaîne de caractères lisible destinée à un
    affichage. */
const String ASN1_DN::toString () const {
  const String prefix ("  ");

  String res;

  for (unsigned int i=0; i<nFields; i++)
    res += prefix + fields[i]->toString();

  if (unknownFields)
    res += ("  Attention ! Le nom distinctif contient des attributs non interprétés.\n");

  return res;
}




/** toString : produit une chaîne de caractères lisible respectant
    la RFC 1779 */
const String ASN1_DN::toDNString () const {
  String prefix ("");
  String comma ("");

  String res;

  for (unsigned int i=0; i<nFields; i++)
  {
      if (compareOIDs (fields[i]->objectType.value, DNOIDs[OID_COMMON_NAME]))
        prefix="CN=";
      else if (compareOIDs (fields[i]->objectType.value, DNOIDs[OID_COUNTRY_NAME]))
        prefix="C=";
      else if (compareOIDs (fields[i]->objectType.value, DNOIDs[OID_LOCALITY_NAME]))
        prefix="L=";
      else if (compareOIDs (fields[i]->objectType.value, DNOIDs[OID_STATE_OR_PROVINCE_NAME]))
        prefix="ST=";
      else if (compareOIDs (fields[i]->objectType.value, DNOIDs[OID_ORGANIZATION_NAME]))
        prefix="O=";
      else if (compareOIDs (fields[i]->objectType.value, DNOIDs[OID_ORGANIZATIONAL_UNIT_NAME]))
        prefix="OU=";
      else if (compareOIDs (fields[i]->objectType.value, DNOIDs[OID_RSA_EMAIL_ADDR_NAME]))
        prefix="MAIL=";
      else if (compareOIDs (fields[i]->objectType.value, DNOIDs[OID_DOMAIN_CONTROLLER]))
        prefix="DC=";

    res += (res.size() ? String(",") : String()) +  prefix + fields[i]->object.value;
  }
  return res;
}









//////////////////////////
// Classe ASN1_VALIDITY //
//////////////////////////


/* Un champ de validité ASN.1 a la structure suivante :

   SEQUENCE
   | TIME : <date de début de validité>
   | TIME : <date de fin de validité>
*/



// TODO: For the moment, we only deal with UTC TIME objects...

/** ASN1_VALIDITY : construit un objet Validité du certificat ASN.1 à
    partir d'une chaîne au format DER. L'index de la chaîne est mis à
    jour.

    Paramètres
       DERstring : chaîne au format DER pointant sur un élément ASN.1
    Exception possible
       E_DER_INVALID_FILE en cas de sous-chaîne non conforme au format DER
       E_DER_SIZE_TOO_LONG si la taille ne tient pas sur 32 bits
       E_UNKNOWN_CERT_FORMAT si le champ validité est incorrect
*/
ASN1_VALIDITY::ASN1_VALIDITY (const String& DERString) {
  try {
    String seqContent = decapsulate (DERString, T_SEQU);

    ASN1_BASIC start = ASN1_BASIC::makeAndCheckBasic (C_UNIV, M_PRIM, T_UTCT, seqContent,
						      DERUnknownCertFormat ("Le champ date de début de validité est incorrect."));
    ASN1_BASIC end = ASN1_BASIC::makeAndCheckBasic (C_UNIV, M_PRIM, T_UTCT, seqContent,
						    DERUnknownCertFormat ("Le champ date de fin de validité est incorrect."));
    startDate = start.value;
    endDate = end.value;
  } catch (DERSequenceExpected& e) {
    throw ANSSIPKIException (E_DER_INVALID_FILE, "Invalid validity field.");
  } catch (ANSSIPKIException e) {
    throw UnexpectedError (e.what());
  }
}


/** ASN1_VALIDITY : construit un objet Validité du certificat ASN.1 à
    partir de deux chaînes de caractères codant les bornes. */
ASN1_VALIDITY::ASN1_VALIDITY (const String& sd, const String& ed)
  : startDate (sd), endDate (ed) {

  // Si la représentation des dates n'est pas calculable, on renvoie une erreur
  if (dateToString (sd) == sd || dateToString (ed) == ed)
    throw UnexpectedError ("Format des dates invalides");
}



/** toDER : produit une chaîne de caractères au format DER représentant
    les dates de validité. */
const String ASN1_VALIDITY::toDER () const {
  ASN1_BASIC start (C_UNIV, M_PRIM, T_UTCT, startDate);
  ASN1_BASIC end (C_UNIV, M_PRIM, T_UTCT, endDate);
  return encapsulate (start.toDER() + end.toDER(), T_SEQU);
}



/** toString : produit une chaîne de caractères lisible destinée à un
    affichage. */
const String ASN1_VALIDITY::toString () const {
  return (String ("Période de validité :\n") +
	  String ("  pas avant ") + dateToString(startDate) + "\n" +
	  String ("  pas après ") + dateToString(endDate) + "\n");
}







///////////////////////////
// Classe ASN1_EXTENSION //
///////////////////////////


/* Une extension X.509 a la structure suivante :

   SEQUENCE
   | OBJET IDENTIFIER : <identifiant de l'extension>
   | BOOLEAN : <criticité de l'extension> (OPTIONNEL)
   | OCTETSTRING : <valeur de l'extension>
*/



/** ASN1_EXTENSION : construit une extension à partir d'un identifiant
    et d'une valeur. Il est possible d'utiliser le premier
    constructeur pour spécifier de plus la criticité  */

ASN1_EXTENSION::ASN1_EXTENSION (const ASN1_BASIC& id, const bool crit, const ASN1_BASIC& value)
  : extnId (id), critical_present (true), critical_value (crit),
    extnValue (C_UNIV, M_PRIM, T_OSTR, value.toDER()) {}


ASN1_EXTENSION::ASN1_EXTENSION (const ASN1_BASIC& id, const ASN1_BASIC& value)
  : extnId (id), critical_present (false), critical_value (false),
    extnValue (C_UNIV, M_PRIM, T_OSTR, value.toDER()) {}





/** toDER : produit une chaîne de caractères au format DER représentant
    les dates de validité. */
const String ASN1_EXTENSION::toDER () const {
  String res = extnId.toDER();
  if (critical_present) {
    String b;
    if (critical_value)
      b = String (&B_TRUE, 1);
    else
      b = String (&B_FALSE, 1);

    res += (ASN1_BASIC (C_UNIV, M_PRIM, T_BOOL, b).toDER());
  }
  res += extnValue.toDER();

  return encapsulate (res, T_SEQU);
}



/** toString : produit une chaîne de caractères lisible destinée à un
    affichage. */
const String ASN1_EXTENSION::toString () const {
  String res = String ("  ") + extnId.toString();
  if (critical_present) {
    if (critical_value)
      res += String (" (critique) : ");
    else
      res += String (" (non critique) : ");
  } else
    res += String (" : ");

  res += extnValue.toString ();
  return (res);
}
