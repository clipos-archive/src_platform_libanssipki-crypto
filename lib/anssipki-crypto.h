// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2000-2018 ANSSI. All Rights Reserved.
/************************************************************************

   anssipki-crypto.h

   Ce fichier définit l'ensemble des fonctions exportées par la
   bibliothèque cryptographique.

************************************************************************/

#ifndef ANSSIPKI_CRYPTO_H
#define ANSSIPKI_CRYPTO_H

#include <stdint.h>
#include <sys/types.h>
#include <gmp.h>

#include "anssipki-common.h"
#include "anssipki-asn1.h"



/*********************************
 * Raccourcis et types pratiques *
 *********************************/
typedef uint32_t u32;
typedef enum {B_RSA, B_ECDSA, B_UNKNOWN} bicle_t;


/************************
 * Fonctions de hachage *
 ************************/

/* Various Length Definitions */
/******************************/

#define SHA1_DIGEST_LENGTH		20
#define SHA256_DIGEST_LENGTH		32
#define SHA384_DIGEST_LENGTH		48
#define SHA512_DIGEST_LENGTH		64


/* Prototypes */
/**************/

int sha1 (const char* string, const size_t string_len, char* result);
int sha512 (const char* string, const size_t string_len, char* result);
int sha256 (const char* string, const size_t string_len, char* result);
int sha384 (const char* string, const size_t string_len, char* result);


/* Type pour les fonctions de hachage */
/**********************************************/

namespace ANSSIPKI_HASH
{
  typedef enum {invalid, sha1, sha256, sha384, sha512} hash_function_t;

  const size_t digestInfoHeader_sha1_len = 15;
  const unsigned char digestInfoHeader_sha1 [digestInfoHeader_sha1_len] = {
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 
  };

  const size_t digestInfoHeader_sha256_len = 19;
  const unsigned char digestInfoHeader_sha256 [digestInfoHeader_sha256_len] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
  };

  const size_t digestInfoHeader_sha384_len = 19;
  const unsigned char digestInfoHeader_sha384 [digestInfoHeader_sha384_len] = {
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30
  };

  const size_t digestInfoHeader_sha512_len = 19;
  const unsigned char digestInfoHeader_sha512 [digestInfoHeader_sha512_len] = {
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40
  };

  int copyDigestInfoHeader (unsigned char *dst, size_t *len, hash_function_t hash);

}


/**********************
 * Générateurs d'aléa *
 **********************/

class PRNG {
 public:
  /* Raffraîchissement de l'état Barak-Halevi */
  virtual void refresh (const char* input, const size_t input_len) = 0;

  /* Raffraîchissement à partir d'un autre PRNG */
  void refresh (PRNG& src, const size_t input_len);

  /* Extraction d'aléa dans un format brut */
  virtual void getRandomBytes (char* ouput, size_t output_len) = 0;
  String getRandomString (size_t output_len);

  /* Extraction d'aléa au format "entier GMP" (mpz_t), uniformément distribué
   * entre 0 et 2^(output_nbits) - 1 inclus */
  void getRandomInt (mpz_t output, const size_t output_nbits, bool init_mpz);

  /* Extraction d'aléa au format "entier GMP" (mpz_t), uniformément distribué
   * entre 0 et q-1 inclus */
  void getRandomIntNB (mpz_t output, const mpz_t q, bool init_mpz);

  /* Demande explicite de sauver l'état */
  virtual void saveState ();

  virtual ~PRNG ();
};


class CombinedPRNG : public PRNG {
 public:
  CombinedPRNG (PRNG* src1, PRNG* src2)
    : src1 (src1), src2 (src2)
  {
    if (src1 == src2)
      throw UnexpectedError ("CombinedPRNG called with two identical sources");
  }

  virtual ~CombinedPRNG ();

  virtual void refresh (const char* input, const size_t input_len);
  virtual void getRandomBytes (char* ouput, size_t output_len);

  virtual void saveState ();

 private:
  PRNG *src1, *src2;

  CombinedPRNG ();
  CombinedPRNG (const CombinedPRNG&);
  CombinedPRNG operator= (const CombinedPRNG&);
};




/***********************************
 * Générateurs d'aléa /dev/urandom *
 ***********************************/

class DevUrandomPRNG : public PRNG {
 public:
  DevUrandomPRNG ();
  virtual ~DevUrandomPRNG ();

  virtual void refresh (const char* input __attribute__((unused)),
			const size_t input_len __attribute__((unused))) {}
  virtual void getRandomBytes (char* ouput, size_t output_len);

  

 private:
  int fd;
};


/**********************************
 * Générateur d'aléa Barak-Halevi *
 **********************************/

/* Paramètres Barak-Halevi */
/***************************/

/* On utilise SHA256 */
#define UNDERYLING_HASH_FUNCTION sha256
#define BARAK_HALEVI_ONE_BLOCK_SIZE 32

/* Taille de l'état interne */
#define BARAK_HALEVI_STATE_BYTE_SIZE BARAK_HALEVI_ONE_BLOCK_SIZE


/* Etat interne Barak-Halevi */
/*****************************/

class BarakHaleviPRNG : public PRNG {
 public:
  BarakHaleviPRNG ();
  virtual ~BarakHaleviPRNG ();

  /* Raffraîchissement de l'état Barak-Halevi */
  virtual void refresh (const char* input, const size_t input_len);

  /* Extraction d'aléa dans un format brut */
  virtual void getRandomBytes (char* ouput, size_t output_len);

  /* Cette fonction existe à des fins de debug */
  /* TODO: compiler cette fonctiond e façon conditionnelle */
  const char* state () const { return _state; }

 protected:
  char _state[BARAK_HALEVI_STATE_BYTE_SIZE];

 private:
  BarakHaleviPRNG (const BarakHaleviPRNG&);
  BarakHaleviPRNG operator= (const BarakHaleviPRNG&);
};


class StatefulBarakHaleviPRNG : public BarakHaleviPRNG {
 public:
  /* Ouverture d'un état précédent */
  StatefulBarakHaleviPRNG (const char* filename, const int autoSaveEvery = 10000);

  /* Création d'un état à partir d'une autre source d'aléa */
  StatefulBarakHaleviPRNG (const char* filename, PRNG& source, const int autoSaveEvery = 10000);

  /* Création d'un état à partir d'une graine */
  StatefulBarakHaleviPRNG (const char* filename, char* seed, size_t seed_len,
			   const int autoSaveEvery = 10000);

  virtual ~StatefulBarakHaleviPRNG ();

  /* Ces deux fonctions sont surchargées pour garantir que l'état est
     sauvegardé dans le fichier à chaque utilisation */
  virtual void refresh (const char* input, const size_t input_len);
  virtual void getRandomBytes (char* ouput, size_t output_len);

  virtual void saveState ();

 private:
  char* _filename;
  int _autoSaveEvery;
  int counter;

  StatefulBarakHaleviPRNG ();
  StatefulBarakHaleviPRNG (const StatefulBarakHaleviPRNG&);
  StatefulBarakHaleviPRNG operator= (const StatefulBarakHaleviPRNG&);
};



/********************************
 * Gestion des nombres premiers *
 ********************************/

/* A plusieurs endroits, on utilise le générateur d'aléa de GMP. Voici
   les paramètres correspondants */
/* Size of the initializer and the seed of GMP's linear congruential
   algorithm to produce random numbers */
#define GMP_RANDOM_INITIALIZER_SIZE 128
#define GMP_RANDOM_SEED_SIZE 256


/* Génération des variables globales (à appeler avant toute
   utilisation des fonctions sur les nombres premiers !) */
void initPrimes (PRNG& rng);

bool isPrime (mpz_t n);
bool isPrime_Sieve (mpz_t n, size_t bound=0);
bool isPrime_MillerRabin (mpz_t n, int iter=0);
bool isPrime_Lucas (mpz_t n);
bool isSmooth (mpz_t n);

void genPrimeFT(mpz_t p, const size_t n, PRNG& generator, bool init_mpz);
/* Extraction d'aléa au format "entier GMP" (mpz_t) jusqu'à obtenir un
   entier p vérifiant certaines propriétés :
     - p est premier
     - (p-1)/2 est premier
     - p+1 n'est pas friable
     - (p-1)/2 - 1 n'est pas friable
     - (p-1)/2 + 1 n'est pas friable
*/
void findRSAFactor (mpz_t factor, const size_t nbits, PRNG& generator, bool init_mpz);
//TODO LCR supprimer cet api quand la nouvelle implem aura remplacée la vieille
void findRSAFactorFT (mpz_t factor, const size_t nbits, PRNG& generator, bool init_mpz);




/*******************************************
 * Définition des algorithmes de signature *
 *******************************************/


class RSAKey {
 public:


  RSAKey ();

  /* Génération d'une nouvelle clé RSA. Elle comprend sur un module n =
     pq, un exposant public e et un exposant privé d vérifiant :
       - p et q sont des "facteurs RSA" au sens de la fonction précédente
       - | p - q | > 2^(nbits/2 -20)
       - En notant phi = (p-1) (q-1), ed = 1 [phi]
       - e < n et d < n
       - si e vaut 65537 (càd si useF4 vaut vrai), d > 2^(nbits/2)
       - si e est choisi aléatoirement, e, d > 2^(nbits - 10)
  */
  RSAKey (PRNG& prng, const size_t nBits, bool useF4);

  /* Création de l'objet RSAPrivateKey à partir d'entiers
     GMP. Attention, les entiers passés en arguments seront
     détruits. Le générateur d'aléa à fournir n'est là que pour les
     tests de chiffrement/déchiffrement */
  RSAKey (PRNG& prng, mpz_t n, mpz_t d, mpz_t e, mpz_t p, mpz_t q);

  /* Création de l'objet RSAPrivateKey à partir d'un objet ASN.1
     standard, encodé en DER */
  RSAKey (PRNG& prng, const String& DERString);
  

  void forgetKey ();
  ~RSAKey ();


  const String sign (const ANSSIPKI_ASN1::TBS& tbs) const;

  bool verify (const mpz_t msg, const mpz_t sig) const;

  /*
    SEQUENCE
    | SEQUENCE
    | | OBJECT IDENTIFIER : <identifiant de l'algorithme>
    | | NULL
    | BITSTRING
    | | SEQUENCE
    | | | INTEGER (module RSA)
    | | | INTEGER (exposant public)
  */
  const String ASN1PubKeyInfo () const;

  /*
    SEQUENCE
    | INTEGER (version)
    | SEQUENCE
    | | OBJECT IDENTIFIER : <identifiant de l'algorithme>
    | | NULL
    | OCTET STRING
    | | ANS1PrivateKey
  */
  const String ASN1PrivateKeyInfo () const;

  bool setFromASN1PrivateKeyInfo (const String& DERString);

  /*
    SEQUENCE
    | INTEGER (version)
    | INTEGER (n)
    | INTEGER (e)
    | INTEGER (d)
    | INTEGER (p)
    | INTEGER (q)
    | INTEGER (d mod (p-1))
    | INTEGER (d mod (q-1))
    | INTEGER ((inverse of q) mod p)
  */
  const String ASN1PrivateKey () const;
  bool setFromASN1PrivateKey (const String& DERString);

  /*
     SEQUENCE
     | INTEGER (module RSA)
     | INTEGER (exposant public)
  */
  const String ASN1PublicKey () const;

  /* keyIdentifierHash : Production de l'identifiant de la clé qui
     servira dans les extensions (Authority Key Identifier et Subject
     Key Identifier). Il s'agit du haché SHA-1 de la structure publique
  */
  const String keyIdentifierHash ();

  #ifdef ANSSIPKI_TEST_RSA
  const mpz_t& n () const { return _n; }
  const mpz_t& e () const { return _e; }
  const mpz_t& d () const { return _d; }
  #endif


  bool isInitialized () const { return _initialized; }
  int copyN (mpz_t *) const;
  int copyE (mpz_t *) const;
  int copyD (mpz_t *) const;
  int copyP (mpz_t *) const;
  int copyQ (mpz_t *) const;

  void setN (const mpz_t *newN);
  void setE (const mpz_t *newE);
  void setD (const mpz_t *newD);
  void setQ (const mpz_t *newP);
  void setP (const mpz_t *newQ);

  void setInitialized () { _initialized = true; }


  // Calcule res = data ^ d mod (n)
  // conditions : 
  // 0 <= data <= n, sinon retourne -1
  // objet initialise sinon retourne -2
  // pointeurs res et data non nuls, sinon retourne -3
  int private_exponentiation (mpz_t *res, mpz_t *data);
  int private_exponentiation (unsigned char *res, size_t *resLen, const unsigned char *data, const size_t dataLen);

  // Calcule res = data ^ e mod (n)
  int public_exponentiation (mpz_t *res, mpz_t *data);
  int public_exponentiation (unsigned char *res, size_t *resLen, const unsigned char *data, const size_t dataLen);


  int pkcs1_v1_5_encode (unsigned char *res, const size_t emLen, const unsigned char *data, const size_t dataLen, ANSSIPKI_HASH::hash_function_t hashFunc = ANSSIPKI_HASH::invalid);

 private:
  bool _initialized;
  mpz_t _n;
  mpz_t _d;
  mpz_t _p;
  mpz_t _q;
  mpz_t _e;

  /* Réalisation de tests de correction de la clé générée, et création
     de l'objet pubkey */
  void checkKey (const size_t nbits, const mpz_t randomSeed);

  //  RSAKey ();
  RSAKey (const RSAKey&);
  RSAKey operator= (const RSAKey&);
};


#endif // ifndef ANSSIPKI_CRYPTO_H
