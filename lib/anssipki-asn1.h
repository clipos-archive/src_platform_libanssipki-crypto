// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2000-2018 ANSSI. All Rights Reserved.
/**
 * @file
 * @author Frederic Gauche <clipos@ssi.gouv.fr>
 * @author Olivier Levillain <clipos@ssi.gouv.fr>
 *
 * @section DESCRIPTION
 *
 * This file defines the classes allowing to manipulate ASN.1 objects,
 * for example certificates and CRLs.
 */


#ifndef ANSSIPKI_ASN1_H
#define ANSSIPKI_ASN1_H


#include "anssipki-common.h"
#include <gmp.h>


/*********
 * Types *
 *********/

/// Enumeration expressing the type of object expected after an OID.
typedef enum {
  TE_STRING,          /**< A String (Printable, IA5, T61, UTF8, etc.) should follow */
  TE_NULL,            /**< A Null ASN.1 Object should follow (this is the case for the rsaEncryption OID) */
  TE_OCTETSTRING      /**< An OctetString is expected (this is typical when dealing with X.509 extensions) */
} tag_expected_t;

/// Structure describing useful OIDs.
typedef struct {
  size_t len;                   /**< The number of chars to take into account in hoid */
  char hoid[32];                /**< The binary DER encoding of the OID */
  char desc[64];                /**< A textual description of the OID */
  tag_expected_t tag_expected;  /**< The kind of object that should follow this OID in the pair (OID, Object) */
} asn1_oid;


/*************
 * Constants *
 *************/

/// ASN.1 elements have a property named the class, which can take 4 different values.
typedef enum {
  C_UNIV = 0,		/**< Universal: the element has a type defined by the ASN.1 standard */
  C_APPL = 1,		/**< Application: the element has a customized type defined by a specification */
  C_CSPE = 2,           /**< Context Specific: the element has a customized type defined by a specification, which depends of its location */
  C_PRIV = 3	        /**< Private: the element's type is private */
} asn1_class;


/// ASN.1 elements can either be primitive (scalar values) or constructed (e.g. sequences)
typedef enum {
  M_PRIM = 0,           /**< Primitive */
  M_CONS = 1            /**< Constructed */
} asn1_method;


/// Enumeration listing the relevant standard Universal ASN.1 elements.
typedef enum {
  T_BOOL = 1,           /**< Boolean */
  T_INTG = 2,           /**< Integer */
  T_BSTR = 3,        	/**< Bit String */
  T_OSTR = 4,        	/**< Octet String */
  T_NULL = 5,           /**< Null */
  T_OIDR = 6,        	/**< Object Identifier */
  T_UTF8 = 12,          /**< UTF8 String */
  T_SEQU = 16,          /**< Sequence type */
  T_SETS = 17,          /**< Set type */
  T_PRTS = 19,          /**< Printable String */
  T_T61S = 20,          /**< T61 String */
  T_IA5S = 22,          /**< IA5 String */
  T_UTCT = 23,          /**< UTC Time */
  T_GENT = 24           /**< Generelized Time */
} asn1_tagnumber;


/// Boolean value for True, encoded in binary DER
const char B_TRUE = '\xFF';

/// Boolean value for False, encoded in binary DER
const char B_FALSE = '\x00';



// Identifiants des objets d'un Distinguished Name
//------------------------------------------------

#define MAX_DN_ATTRIBUTES 30

// Numérotation interne
typedef enum {
  OID_COMMON_NAME = 0,
  OID_COUNTRY_NAME,
  OID_LOCALITY_NAME,
  OID_STATE_OR_PROVINCE_NAME,
  OID_ORGANIZATION_NAME,
  OID_ORGANIZATIONAL_UNIT_NAME,
  OID_RSA_EMAIL_ADDR_NAME,
  OID_DOMAIN_CONTROLLER,
  nDNOIDs                               // Nombre d'OIDs correspondant au DNs
} oid_dn_index;

// Tableau des Object Identifiers
const asn1_oid DNOIDs [nDNOIDs] = {
  {/*len :*/  3,
   /*hoid :*/ "\x55\x04\x03", // 2.5.4.3
   /*desc :*/ "Nom commun",
   /*tag_expected :*/ TE_STRING},
  {/*len :*/  3,
   /*hoid :*/ "\x55\x04\x06", // 2.5.4.6
   /*desc :*/ "Pays",
   /*tag_expected :*/ TE_STRING},
  {/*len :*/  3,
   /*hoid :*/ "\x55\x04\x07", // 2.5.4.7
   /*desc :*/ "Localité",
   /*tag_expected :*/ TE_STRING},
  {/*len :*/  3,
   /*hoid :*/ "\x55\x04\x08", // 2.5.4.8
   /*desc :*/ "Etat ou province",
   /*tag_expected :*/ TE_STRING},
  {/*len :*/  3,
   /*hoid :*/ "\x55\x04\x0A", // 2.5.4.10
   /*desc :*/ "Organisation",
   /*tag_expected :*/ TE_STRING},
  {/*len :*/  3,
   /*hoid :*/ "\x55\x04\x0B", // 2.5.4.11
   /*desc :*/ "Unité de l'organisation",
   /*tag_expected :*/ TE_STRING},
  {/*len :*/  9,
   /*hoid :*/ "\x2A\x86\x48\x86\xF7\x0D\x01\x09\x01", // 1.2.840.113549.1.9.1
   /*desc :*/ "Adresse électronique",
   /*tag_expected :*/ TE_STRING},
  {/*len :*/  10,
   /*hoid :*/ "\x09\x92\x26\x89\x93\xf2\x2c\x64\x01\x19", // 0.9.2342.19200300.100.1.25
   /*desc :*/ "Composant de domaine",
   /*tag_expected :*/ TE_STRING}};


// Identifiants des algorithmes de signature (hachage + chiffrement asymétrique)
//------------------------------------------------------------------------------

// Numérotation interne
typedef enum {
  S_ALGO_SHA1RSA = 0,   // SHA1 + RSA
  S_ALGO_SHA256RSA,     // SHA256 + RSA
  S_ALGO_SHA512RSA,     // SHA512 + RSA
  nSignAlgos            // Nombre d'algorithmes de signature reconnus
} sign_algo;


// Tableau des Object Identifiers
const asn1_oid signAlgoOIDs [nSignAlgos] = {
  {/*len :*/  9,
   /*hoid :*/ "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05", // 1.2.840.113549.1.1.5
   /*desc :*/ "SHA1 / RSA",
   /*tag_expected :*/ TE_NULL},
  {/*len :*/  9,
   /*hoid :*/ "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0b", // 1.2.840.113549.1.1.11
   /*desc :*/ "SHA256 / RSA",
   /*tag_expected :*/ TE_NULL},
  {/*len :*/  9,
   /*hoid :*/ "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0d", // 1.2.840.113549.1.1.13
   /*desc :*/ "SHA512 / RSA",
   /*tag_expected :*/ TE_NULL}
};


// Numérotation interne
typedef enum {
  H_ALGO_SHA1 = 0,   // SHA1
  H_ALGO_SHA256,     // SHA256
  H_ALGO_SHA512,     // SHA512
  nHashAlgos         // Nombre d'algorithmes de signature reconnus
} hash_algo;


// Tableau des Object Identifiers (hachage seulement)
const asn1_oid hashAlgoOIDs [nHashAlgos] = {
  {/*len :*/  5,
   /*hoid :*/ "\x2B\x0E\x03\x02\x1A",                     // 1.3.14.3.2.26
   /*desc :*/ "SHA1",
   /*tag_expected :*/ TE_NULL},
  {/*len :*/  9,
   /*hoid :*/ "\x60\x86\x48\x01\x65\x3\x04\x02\x01",      // 2.16.840.1.101.3.4.2.1
   /*desc :*/ "SHA256",
   /*tag_expected :*/ TE_NULL},
  {/*len :*/  9,
   /*hoid :*/ "\x60\x86\x48\x01\x65\x3\x04\x02\x03",      // 2.16.840.1.101.3.4.2.3
   /*desc :*/ "SHA512",
   /*tag_expected :*/ TE_NULL}
};


// Numérotation interne
typedef enum {
  PK_ALGO_RSA = 0,   // SHA1 + RSA
  nPubKeyAlgos         // Nombre d'algorithmes de signature reconnus
} pubkey_algo;


// Tableau des Object Identifiers (chiffrement asymétrique seulement)
const asn1_oid pubKeyAlgoOIDs [nPubKeyAlgos] = {
  {/*len :*/  9,
   /*hoid :*/ "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01", // 1.2.840.113549.1.1.1
   /*desc :*/ "RSA",
   /*tag_expected :*/ TE_NULL}
};



hash_algo hashAlgo (const sign_algo sa);
pubkey_algo pubkeyAlgo (const sign_algo sa);
sign_algo sigAlgo (const hash_algo ha, const pubkey_algo pka);



// Identifiants des extensions
//----------------------------

// Numérotation interne
typedef enum {
  EXT_BASIC_CONSTRAINTS = 0,
  EXT_KEY_USAGE,
  EXT_CERTIFICATE_POLICIES,
  EXT_AUTHORITY_KEY_IDENTIFIER,
  EXT_SUBJECT_KEY_IDENTIFIER,
  EXT_EXTENDED_KEY_USAGE,
  EXT_SUBJECT_ALT_NAME,
  nExtensionIds                         // Nombre des extensions reconnues
} extnension_id;

// Tableau des Object Identifiers
const asn1_oid extensionOIDs [nExtensionIds] = {
  {/*len :*/  3,
   /*hoid :*/ "\x55\x1D\x13", // 2.5.29.19
   /*desc :*/ "Contraintes de base",
   /*tag_expected :*/ TE_OCTETSTRING},
  {/*len :*/  3,
   /*hoid :*/ "\x55\x1D\x0F", // 2.5.29.15
   /*desc :*/ "Utilisation de la clé",
   /*tag_expected :*/ TE_OCTETSTRING},
  {/*len :*/  3,
   /*hoid :*/ "\x55\x1D\x20", // 2.5.29.32
   /*desc :*/ "Stratégie du certificat",
   /*tag_expected :*/ TE_OCTETSTRING},
  {/*len :*/  3,
   /*hoid :*/ "\x55\x1D\x23", // 2.5.29.35
   /*desc :*/ "Identificateur de la clé de l'autorité",
   /*tag_expected :*/ TE_OCTETSTRING},
  {/*len :*/  3,
   /*hoid :*/ "\x55\x1D\x0E", // 2.5.29.14
   /*desc :*/ "Identificateur de la clé du sujet",
   /*tag_expected :*/ TE_OCTETSTRING},
  {/*len :*/  3,
   /*hoid :*/ "\x55\x1D\x25", // 2.5.29.37
   /*desc :*/ "Utilisation détaillée de la clé",
   /*tag_expected :*/ TE_OCTETSTRING},
  {/*len :*/  3,
   /*hoid :*/ "\x55\x1D\x11", // 2.5.29.17
   /*desc :*/ "Nom alternatif du sujet",
   /*tag_expected :*/ TE_OCTETSTRING}
};





//////////////////////
// Fonctions utiles //
//////////////////////

const String decapsulate (const String& DERString, const asn1_tagnumber t);

const String encapsulate (const String& DERString, const asn1_tagnumber t, const asn1_class = C_UNIV);

const String INTtoASN1_BSTR(unsigned int flags, size_t lenght);

unsigned int ASN1_BSTRtoINT(const String bstr, size_t& bfLength);


namespace ANSSIPKI_ASN1
{

///////////////////////
// Classe ASN1_BASIC //
///////////////////////

class ASN1_BASIC {
 public:
  asn1_class classe;
  asn1_method method;
  asn1_tagnumber tagNumber;
  String value;

  // Constructeur trivial
  ASN1_BASIC (const asn1_class c, const asn1_method m, const asn1_tagnumber n, const String& v = String());

  // Constructeur à partir d'une chaîne au format DER
  ASN1_BASIC (const String& DERString);
  static ASN1_BASIC makeAndCheckBasic (const asn1_class c, const asn1_method m, const asn1_tagnumber n,
				       const String& DERString, const ANSSIPKIException& e);
  static ASN1_BASIC makeAndCheckBasic (const asn1_class c, const asn1_method m,
				       const asn1_tagnumber n, const String& DERString,
				       const String& v, const ANSSIPKIException& e);
    
  // Constructeur d'un Obejct Identifier
  ASN1_BASIC (const asn1_oid& oid);

  // Export de l'élément en une chaîne DER
  const String toDER () const;

  // Export de l'objet pour être affichable
  const String toString () const;

 private:
  ASN1_BASIC ();
};

/////////////////////////
// Classe ASN1_VERSION //
/////////////////////////

class ASN1_VERSION : public ASN1_BASIC {
 public:
  int version;

  // Constructeur à partir d'un numéro de version (entre 1 et 3)
  ASN1_VERSION (const int v);

  // Constructeur à partir d'une chaîne au format DER
  ASN1_VERSION (const String& DERString);

  // Export de l'objet pour être affichable
  const String toString () const;

 private:
  ASN1_VERSION ();
};


/////////////////////////
// Classe ASN1_INTEGER //
/////////////////////////

class ASN1_INTEGER : public ASN1_BASIC {
 public:
  // Constructeur à partir d'un entier GMP
  ASN1_INTEGER (const mpz_t n);

  ASN1_INTEGER (String raw);
 private:
  ASN1_INTEGER ();
};


////////////////////////
// Classe ASN1_OBJECT //
////////////////////////


class ASN1_OBJECT {
 public:
  ASN1_BASIC objectType;
  ASN1_BASIC object;

  // Constructeur à partir d'un identifiant et d'une valeur
  ASN1_OBJECT (const asn1_oid& oid, const String& value, const asn1_tagnumber n = T_PRTS);

  // Constructeur à partir d'une chaîne au format DER
  ASN1_OBJECT (const String& DERString);

  // Export de l'objet en une chaîne DER
  const String toDER () const;

  // Export de l'objet pour être affichable
  const String toString () const;

 private:
  ASN1_OBJECT ();
};


///////////////////////////
// Classe ASN1_SIGN_ALGO //
///////////////////////////

class ASN1_SIGN_ALGO : public ASN1_OBJECT {
 public:
  sign_algo sa;

  // Constructeur à partir de la numérotation du type sign_algo
  ASN1_SIGN_ALGO (const sign_algo);

  // Constructeur à partir d'une chaîne au format DER
  ASN1_SIGN_ALGO (const String& DERString);

  // Export de l'objet pour être affichable
  const String toString () const;

 private:
  ASN1_SIGN_ALGO ();
};



//////////////////////////////
// Classe ASN1_HASH_ALGO //
//////////////////////////////

class ASN1_HASH_ALGO : public ASN1_OBJECT {
 public:
  hash_algo ha;

  // Constructeur à partir de la numérotation interne
  ASN1_HASH_ALGO (const hash_algo);

  // Constructeur à partir d'une chaîne au format DER
  ASN1_HASH_ALGO (const String& DERString);

  // Export de l'objet pour être affichable
  const String toString () const;

 private:
  ASN1_HASH_ALGO ();
};




//////////////////////////////
// Classe ASN1_ENCRYPT_ALGO //
//////////////////////////////

class ASN1_ENCRYPT_ALGO : public ASN1_OBJECT {
 public:
  pubkey_algo pka;

  // Constructeur à partir de la numérotation interne
  ASN1_ENCRYPT_ALGO (const pubkey_algo);

  // Constructeur à partir d'une chaîne au format DER
  ASN1_ENCRYPT_ALGO (const String& DERString);

  // Export de l'objet pour être affichable
  const String toString () const;

 private:
  ASN1_ENCRYPT_ALGO ();
};




////////////////////
// Classe ASN1_DN //
////////////////////

class ASN1_DN {
 public:
  ASN1_DN ();
  ~ASN1_DN ();

  // Méthodes pour ajouter des champs dans un DN
  void addCountry (const String& c, const asn1_tagnumber tag);
  void addState (const String& s, const asn1_tagnumber tag);
  void addLocation (const String& l, const asn1_tagnumber tag);
  void addOrganization (const String& o, const asn1_tagnumber tag);
  void addOrganizationUnit (const String& ou, const asn1_tagnumber tag);
  void addCommonName (const String& cn, const asn1_tagnumber tag);
  void addEMail (const String& em, const asn1_tagnumber tag);

  // Initialisation à partir d'une chaîne DER
  ASN1_DN (const String& DERString);

  // Constructeur par copie
  ASN1_DN (const ASN1_DN& dn);

  const String toDNString () const;
  const String toString () const;
  const String toDER () const;

 private:
  // Au plus, on stockera MAX_DN_ATTRIBUTES sous-champs dans un DN
  const ASN1_OBJECT* fields[MAX_DN_ATTRIBUTES];
  bool unknownFields;
  unsigned int nFields;

  // Méthode générique d'ajout d'objet
  void add (const ASN1_OBJECT* const o);
};



//////////////////////////
// Classe ASN1_VALIDITY //
//////////////////////////

class ASN1_VALIDITY {
 public:
  // Dates de début et de fin de validité
  String startDate, endDate;

  // Initialisation à partir d'une chaîne DER
  ASN1_VALIDITY (const String& DERString);

  // Initialisation à partir de deux chaînes de caractères
  ASN1_VALIDITY (const String& sd, const String& ed);

  const String toString () const;

  const String toDER () const;

 private:
  ASN1_VALIDITY ();
};




///////////////////////////
// Classe ASN1_EXTENSION //
///////////////////////////

class ASN1_EXTENSION {
 public:
  ASN1_BASIC extnId;
  bool critical_present;
  bool critical_value;
  ASN1_BASIC extnValue;
 
  // Initialisation à partir d'un OID et d'une valeur, et de la criticité éventuellement
  ASN1_EXTENSION (const ASN1_BASIC& id, const bool crit, const ASN1_BASIC& value);
  ASN1_EXTENSION (const ASN1_BASIC& id, const ASN1_BASIC& value);

  const String toString () const;

  const String toDER () const;

 private:
  ASN1_EXTENSION ();
};



//////////////////////////
// Classe abstraite TBS //
//////////////////////////

class TBS {
 public:
  TBS () {}

  // Version affichable des informations décodées
  virtual const String toString () const = 0;

  // Version DER du fichier à signer
  virtual const String toDER() const = 0;

  // Renvoie l'algorithme de signature utilisé
  virtual sign_algo get_sign_algo () const = 0;

  // Renvoie le numéro de série (provoque une erreur pour autre chose que AC_TBS)
  virtual const ASN1_BASIC get_serial_no () const;

  // Ajoute la signature au bloc a signer et renvoie une chaine au format DER
  const String appendSignatureToDER (const String& signature) const;

 private:
  // On empêche certains constructeurs et opérateurs.
  void operator=(const TBS&);
  TBS (const TBS&);
};

} // namespace ANSSIPKI_ASN1


#endif  // ifndef ANSSIPKI_ASN1_H
