// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2000-2018 ANSSI. All Rights Reserved.
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Génération de clés de signature RSA / DSA / ECDSA (version 1.2)
//
// Implémentation RSA
//
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

#include "anssipki-crypto.h"
#include "anssipki-common.h"
#include "anssipki-asn1.h"
using namespace ANSSIPKI_ASN1;


#include "string.h"

/* Taille du tableau servant à cribler le module RSA pour le test de
   friabilité (auto-test) */
static const int trivialSieve_size = 100000;

/* Nombre de vérifications chiffrement / déchiffrement réalisées avec
   la clé tout juste générées à des fins d'auto-test */
static const int nEncryptionDecryptionVerif = 10;





RSAKey::RSAKey (PRNG& prng, const size_t nBits, bool useF4) {
  _initialized = false;
  // TODO: This line does not compile anymore. However, it seems this
  // constructor either throws an exception, or fills the fields with
  // real values
  //  _n = _d = _p = _q = _e = NULL;

  initPrimes (prng);

  mpz_t p, q;
  mpz_t n, e, d;
  mpz_t diff, diff_min;
  mpz_t p_minus_1, q_minus_1, phi;  
  mpz_t min_d_size_with_F4, min_exp_size_when_not_F4;

  mpz_init (n);
  mpz_init (e);
  mpz_init (d);
  mpz_init (p);
  mpz_init (q);
  mpz_init (p_minus_1);
  mpz_init (q_minus_1);
  mpz_init (phi);
  mpz_init (diff);
  mpz_init (diff_min);
  mpz_init (min_d_size_with_F4);
  mpz_init (min_exp_size_when_not_F4);

  // Cette borne permet de s'assurer que les facteurs premiers ne sont
  // pas trop proches l'un de l'autre. En effet, certaines attaques
  // reposent sur une trop grande proximité entre p et q.
  // | p - q | doit être supérieur à 2 ^ ((nBits/2) - 20)
  mpz_ui_pow_ui (diff_min, 2, (nBits / 2) - 20);

  // TODO: Pourquoi cette borne est inférieure à la suivante ?
  // TODO: Regrouper les deux bornes en une seule ?
  // Cette borne correspond à la valeur minimum de d nécessaire pour
  // éviter les attaques utilisant le fait que k est petit dans la
  // formule ed = 1 + k x phi
  // d doit être supérieur à 2 ^ (nBits/2)
  mpz_ui_pow_ui(min_d_size_with_F4, 2, nBits / 2);

  // Cette borne correspond à la valeur minimum des exposants lorsque
  // l'exposant public est choisi au hasard parmi l'ensemble des
  // nombres possibles dans Z/nZ*. Là encore, si ed est trop petit, on
  // peut avoir des attaques utilisant le fait que k soit petit dans
  // ed = 1 + k x phi
  // e et d doivent alors être supérieur à 2 ^ (nBits-10)
  mpz_ui_pow_ui(min_exp_size_when_not_F4, 2, nBits - 10);


  while (true) {

    do {
      findRSAFactor (p, nBits / 2, prng, false);
      findRSAFactor (q, nBits / 2, prng, false);

      mpz_sub (diff, p, q);
      mpz_abs (diff, diff);
    } while (mpz_cmp(diff, diff_min) <= 0);
    
    mpz_mul (n, p, q);

    mpz_sub_ui (p_minus_1, p, 1);
    mpz_sub_ui (q_minus_1, q, 1);
    mpz_mul (phi, p_minus_1, q_minus_1);

    if (useF4) {
      mpz_set_ui (e, 65537);
      if (mpz_invert (d, e, phi) == 0)
	throw CryptoInternalMayhem ("65537 et phi non premiers entre eux");

      // Si d est trop petit, on regénère un module RSA
      // Cet événement est fort peu probable
      if (mpz_cmp (d, min_d_size_with_F4) <= 0)
	continue;

    } else {
      // Si useF4 est faux, on génère un entier aléatoire dans
      // l'ensemble [0, n-1] qui soit inversible modulo phi

      do {
	prng.getRandomInt (e, nBits, false);

	// On force le bit de poids faible à 1 car un exposant pair ne
	// pourra faire l'affaire (il ne sera pas premier avec phi = 4
	// p' q' avec p' et q' premiers)
	mpz_setbit(e, 0);
      } while ( (mpz_cmp (e, n) >= 0) ||
		(mpz_cmp (e, min_exp_size_when_not_F4) <= 0) ||
		(mpz_invert (d, e, phi) == 0) ||
		(mpz_cmp (d, min_exp_size_when_not_F4) <= 0) );
    }

    break;
  }

  // Stockage des informations concernant la clé
  mpz_init_set (_n, n);
  mpz_init_set (_d, d);
  mpz_init_set (_p, p);
  mpz_init_set (_q, q);
  mpz_init_set (_e, e);

  // Vérifications sur la clé publique et création de l'objet _pubkey
  mpz_t seed;
  prng.getRandomInt (seed, GMP_RANDOM_SEED_SIZE, true);
  checkKey (nBits, seed);
  mpz_shred (seed);

  // Tout s'est bien passé, il ne reste plus qu'à détruire tous ces
  // entiers GMP
  _initialized = true;

  mpz_shred (n);
  mpz_shred (e);
  mpz_shred (d);
  mpz_shred (p);
  mpz_shred (q);
  mpz_shred (p_minus_1);
  mpz_shred (q_minus_1);
  mpz_shred (phi);
  mpz_shred (diff);
  mpz_shred (diff_min);
  mpz_shred (min_d_size_with_F4);
  mpz_shred (min_exp_size_when_not_F4);
}


RSAKey::RSAKey (PRNG& prng, mpz_t n, mpz_t d, mpz_t e, mpz_t p, mpz_t q) {
  _initialized = false;

  mpz_init_set (_n, n);
  mpz_init_set (_d, d);
  mpz_init_set (_e, e);
  mpz_init_set (_p, p);
  mpz_init_set (_q, q);
  mpz_shred (n);
  mpz_shred (d);
  mpz_shred (e);
  mpz_shred (p);
  mpz_shred (q);

  // Vérifications sur la clé publique et création de l'objet _pubkey
  mpz_t seed;
  prng.getRandomInt (seed, GMP_RANDOM_SEED_SIZE, true);
  checkKey (mpz_sizeinbase(_n, 2), seed);
  mpz_shred (seed);

  _initialized = true;
}


static inline void getNextInt (const String& DERString, mpz_t i) {
  ANSSIPKI_ASN1::ASN1_BASIC asn1Integer (DERString);
  String n_hexa = asn1Integer.value.toAsciiHexa (0);
  mpz_init_set_str (i, n_hexa.toChar(), 16);
}


RSAKey::RSAKey (PRNG& prng, const String& DERString) {
  _initialized = false;

  String content (decapsulate (DERString, T_SEQU));

  ANSSIPKI_ASN1::ASN1_BASIC version (content);
  getNextInt (content, _n);
  getNextInt (content, _e);
  getNextInt (content, _d);
  getNextInt (content, _p);
  getNextInt (content, _q);

  // Vérifications sur la clé publique et création de l'objet _pubkey
  mpz_t seed;
  prng.getRandomInt (seed, GMP_RANDOM_SEED_SIZE, true);
  checkKey (mpz_sizeinbase(_n, 2), seed);
  mpz_shred (seed);

  _initialized = true;
}



RSAKey::RSAKey () 
{
  _initialized = false;
  mpz_init (_n);
  mpz_init (_d);
  mpz_init (_e);
  mpz_init (_p);
  mpz_init (_q);
}


void RSAKey::forgetKey () {
  mpz_shred (_n);
  mpz_shred (_d);
  mpz_shred (_e);
  _initialized = false;
}


RSAKey::~RSAKey () {
  forgetKey ();
}





bool RSAKey::verify (const mpz_t msg, const mpz_t sig) const {
  mpz_t x;
  bool res;

  mpz_init (x);
  mpz_powm (x, sig, _e, _n);
  res = (mpz_cmp (msg, x) == 0);
  mpz_shred (x);
  return res;
}


const String RSAKey::sign (const TBS& tbs) const {
  char hash[64];
  size_t hashlen = 0;
  hash_algo ha = hash_algo (tbs.get_sign_algo());
  String tbsString = tbs.toDER();

  switch (ha) {
  case H_ALGO_SHA1:
    sha1 (tbsString.toChar(), tbsString.size(), hash);
    hashlen = 20;
    break;

  case H_ALGO_SHA256:
    sha256 (tbsString.toChar(), tbsString.size(), hash);
    hashlen = 32;
    break;

  case H_ALGO_SHA512:
    sha512 (tbsString.toChar(), tbsString.size(), hash);
    hashlen = 64;
    break;

  default:
    throw NotImplemented ("Fonction de hachage inconnue");
  }

  /*
    SEQUENCE
    | SEQUENCE
    | | OBJECT IDENTIFIER hash algorithm
    | | NULL
    | OCTET STRING condensat calculé sur le bloc de données
  */
  String blockToSign = encapsulate  (encapsulate (ASN1_HASH_ALGO(ha).toDER(), T_SEQU) +
				     ANSSIPKI_ASN1::ASN1_BASIC(C_UNIV, M_PRIM, T_OSTR, String (hash, hashlen)).toDER(), T_SEQU);

  uint modulusSize = (uint)((mpz_sizeinbase (_n, 16) + 1) / 2);
  
  // PKCS#1 indique que la taille du bourrage doit être au moins de 8
  // octets (auquels on ajoute les 0x00 0x01 correspondant au bloc de
  // type 1 et le 0x00 terminant le bourrage)
  if (blockToSign.size() + 11 > modulusSize)
    throw UnexpectedError ("Le bloc haché à signer a une taille incorrecte.");
  
  String tmp;
  tmp.resize (modulusSize);
  
  // On bourre le tampon tmp avec le padding requis par PKCS#1 v1.5
  tmp.pushChar ('\x00');
  tmp.pushChar ('\x01');
  for (uint i=2; i < (modulusSize - blockToSign.size() - 1); i++)
    tmp.pushChar ('\xff');
  tmp.pushChar ('\x00');

  // Enfin, on recopie le bloc tbs
  tmp.pushString (blockToSign);

  // On crée le grand entier GMP correspondant au message
  tmp.bignumToAsciiHexa ();

  mpz_t msg;
  mpz_init_set_str(msg, tmp.toChar(), 16);


  if (mpz_cmp(msg, _n) >= 0) {
    mpz_shred (msg);
    throw UnexpectedError ("Le bloc haché à signer a une taille incorrecte.");
  }
  
  // Enfin, on élève le message à la puissance d modulo N
  mpz_t sig;
  mpz_init (sig);
  mpz_powm (sig, msg, _d, _n);
  
  String res_unpadded (sig, String::ENC_BINARY);

  String res;
  res.resize (modulusSize);
  for (uint i=0; i < (modulusSize - res_unpadded.size()); i++)
    res.pushChar ('\x00');
  res.pushString (res_unpadded);

  // On efface les entiers GMP utilisés
  mpz_shred (sig);
  mpz_shred (msg);

  return tbs.appendSignatureToDER (res);
}






// Cette fonction réalise un rapide crible pour vérifier par une
// implémentation triviale indépendante que le module n'est pas
// friable.
static bool isSmoothTrivial (mpz_t n) {
  static bool pr[trivialSieve_size];
  static bool init=false;

  int i, j;

  if (!init) {
    for (i=0; i<trivialSieve_size; i++)
      pr[i] = true;

    pr[0] = pr[1] = false;

    for (i=2; i<trivialSieve_size; i++) {
      if (pr[i]) {
	for (j=2; i*j<trivialSieve_size; j++)
	  pr[i*j] = false;
      }
    }
  }

  for(i=2; i<trivialSieve_size; i++) {
    if (pr[i] && mpz_fdiv_ui (n, i) == 0)
	return true;
  }

  return false;
}


const String RSAKey::ASN1PubKeyInfo () const {
  ASN1_ENCRYPT_ALGO algo (PK_ALGO_RSA);
  ANSSIPKI_ASN1::ASN1_INTEGER n (_n);
  ANSSIPKI_ASN1::ASN1_INTEGER e (_e);

  String padding;
  padding.resize(1);
    
  ANSSIPKI_ASN1::ASN1_BASIC pubKey (C_UNIV, M_PRIM, T_BSTR,
		     (padding +
		      encapsulate (n.toDER() + e.toDER(), T_SEQU)));
  
  return (encapsulate (encapsulate (algo.toDER(), T_SEQU) + pubKey.toDER(), T_SEQU));
}



const String RSAKey::ASN1PrivateKeyInfo () const 
{
  ASN1_ENCRYPT_ALGO algo (PK_ALGO_RSA);
  String algoDer = encapsulate (algo.toDER (), T_SEQU);
  mpz_t zero;
  mpz_init_set_ui (zero, 0);

  ANSSIPKI_ASN1::ASN1_INTEGER version (zero);
  String privKey = ASN1PrivateKey ();
  ANSSIPKI_ASN1::ASN1_BASIC prim_os_privKey (C_UNIV, M_PRIM, T_OSTR, privKey);
  
  return (encapsulate (version.toDER () +
		       algoDer +
		       prim_os_privKey.toDER (),
		       T_SEQU));
}


const String RSAKey::ASN1PrivateKey () const {
  mpz_t _d_mod_p_minus_1, _d_mod_q_minus_1, _invq;
  mpz_t zero;
  mpz_t p_minus_1, q_minus_1;  

  mpz_init (_d_mod_p_minus_1);
  mpz_init (_d_mod_q_minus_1);
  mpz_init (_invq);
  mpz_init_set_ui (zero, 0);

  mpz_init (p_minus_1);
  mpz_init (q_minus_1);
  mpz_sub_ui (p_minus_1, _p, 1);
  mpz_sub_ui (q_minus_1, _q, 1);

  if (mpz_invert (_d_mod_p_minus_1, _e, p_minus_1) == 0 ||
      mpz_invert (_d_mod_q_minus_1, _e, q_minus_1) == 0)
    throw CryptoInternalMayhem ("En fait, d est pas vraiment inversible modulo p-1 ou q-1");

  if (mpz_invert (_invq, _q, _p) == 0)
    throw CryptoInternalMayhem ("q et p-1 non premiers entre eux");

  ANSSIPKI_ASN1::ASN1_INTEGER version (zero);
  ANSSIPKI_ASN1::ASN1_INTEGER n (_n);
  ANSSIPKI_ASN1::ASN1_INTEGER e (_e);
  ANSSIPKI_ASN1::ASN1_INTEGER d (_d);
  ANSSIPKI_ASN1::ASN1_INTEGER p (_p);
  ANSSIPKI_ASN1::ASN1_INTEGER q (_q);
  ANSSIPKI_ASN1::ASN1_INTEGER d_mod_p (_d_mod_p_minus_1);
  ANSSIPKI_ASN1::ASN1_INTEGER d_mod_q (_d_mod_q_minus_1);
  ANSSIPKI_ASN1::ASN1_INTEGER invq (_invq);

  mpz_shred (zero);
  mpz_shred (_d_mod_p_minus_1);
  mpz_shred (_d_mod_q_minus_1);
  mpz_shred (p_minus_1);
  mpz_shred (q_minus_1);
  mpz_shred (_invq);

  return (encapsulate (version.toDER() +
		       n.toDER () +
		       e.toDER () +
		       d.toDER () +
		       p.toDER () +
		       q.toDER () +
		       d_mod_p.toDER () +
		       d_mod_q.toDER () +
		       invq.toDER (), T_SEQU));
}

bool RSAKey::setFromASN1PrivateKey (const String& DERString)
{
  if (_initialized)
    return false;

  try 
    {
      String content (decapsulate (DERString, T_SEQU));

      ANSSIPKI_ASN1::ASN1_BASIC version (content);
      getNextInt (content, _n);
      getNextInt (content, _e);
      getNextInt (content, _d);
      getNextInt (content, _p);
      getNextInt (content, _q);
    }
  catch (ANSSIPKIException &e)
    {
      return false;
    }
  /*
  // Vérifications sur la clé publique et création de l'objet _pubkey
  mpz_t seed;
  prng.getRandomInt (seed, GMP_RANDOM_SEED_SIZE, true);
  checkKey (mpz_sizeinbase(_n, 2), seed);
  mpz_shred (seed);
  */
  _initialized = true;
  return true;
}

bool RSAKey::setFromASN1PrivateKeyInfo (const String& DERString)
{
  bool br = false;

  if (_initialized)
    return false;

  try 
    {
      String content (decapsulate (DERString, T_SEQU));
      ANSSIPKI_ASN1::ASN1_BASIC version (content);
      // verifier que version = ...
      String oid (decapsulate (content, T_SEQU));
      // verifier que oid = rsaencryption
      String prkey (decapsulate (content, T_OSTR));
      br = setFromASN1PrivateKey (prkey);
    }
  catch (ANSSIPKIException &e)
    {
      return false;
    }
  return br;
}

const String RSAKey::ASN1PublicKey () const {
  ANSSIPKI_ASN1::ASN1_INTEGER n (_n);
  ANSSIPKI_ASN1::ASN1_INTEGER e (_e);
  return (encapsulate (n.toDER () + e.toDER (), T_SEQU));
}


void RSAKey::checkKey (const size_t nBits, const mpz_t seed) {
  if (mpz_cmp_ui (_n, 0) < 0)
    throw CryptoInternalMayhem ("le module RSA est négatif");

  if (mpz_cmp_ui (_e, 0) < 0)
    throw CryptoInternalMayhem ("l'exposant public est négatif");

  if (mpz_cmp (_e, _n) >= 0)
    throw CryptoInternalMayhem ("l'exposant public est supérieur à n");

  if (mpz_cmp_ui (_d, 0) < 0)
    throw CryptoInternalMayhem ("l'exposant privé est négatif");

  if (mpz_cmp (_d, _n) >= 0)
    throw CryptoInternalMayhem ("l'exposant privé est supérieur à n");

  // Comme p et q vérifient 3 x 2^((nBits/2)-2) <= p, q < 2^(nBits/2))
  // on a 9 x 2 ^ nBits - 4 <= n < 2^nBits
  // d'où comme 2^nBits - 1 = 8 x 2 ^ nBits - 4 < 9 x 2 ^ nBits - 4,
  // n est strictement compris entre 2^nBits - 1 et 2^nBits
  //
  // En conclusion, n s'écrit sur *exactement* nBits.
  if (mpz_sizeinbase(_n, 2) != nBits) 
    throw CryptoInternalMayhem ("le module RSA n'a pas la bonne taille");

  if (isSmoothTrivial (_n))
    throw CryptoInternalMayhem ("le module RSA est friable");

  // Terminons par quelques tests de chiffrement / déchiffrement
  gmp_randstate_t GMP_state;
  mpz_t m, c, x;
  
  if (gmp_randinit_lc_2exp_size (GMP_state, GMP_RANDOM_INITIALIZER_SIZE) == 0)
    throw ANSSIPKIException (E_CRYPTO_BAD_PARAMETER, "GMP_RANDOM_INITIALIZER_SIZE est trop grand");
  gmp_randseed (GMP_state, seed);

  mpz_init (m);
  mpz_init (c);
  mpz_init (x);

  for (int i=0; i<nEncryptionDecryptionVerif; i++) {
    mpz_urandomm (m, GMP_state, _n);
    mpz_powm (c, m, _e, _n);
    mpz_powm (x, c, _d, _n);
    if (mpz_cmp (m, x) != 0)
      throw CryptoInternalMayhem ("la succession chiffrement / déchiffrement n'est pas l'identité");
  }

  mpz_shred (m);
  mpz_shred (c);
  mpz_shred (x);
}



const String RSAKey::keyIdentifierHash () {
  String toBeHashed = ASN1PublicKey ();

  char buffer[20];
  sha1 (toBeHashed.toChar(), toBeHashed.size(), buffer);
  return String (buffer, 20);
}

// AD
int RSAKey::copyN (mpz_t *to) const
{
  if (!to)
    return -1;
  mpz_init_set (*to, _n);
  return 1;
}

int RSAKey::copyE (mpz_t *to) const
{
  if (!to)
    return -1;
  mpz_init_set (*to, _e);
  return 1;
}

int RSAKey::copyD (mpz_t *to) const
{
  if (!to)
    return -1;
  mpz_init_set (*to, _d);
  return 1;
}

int RSAKey::copyP (mpz_t *to) const
{
  if (!to)
    return -1;
  mpz_init_set (*to, _p);
  return 1;
}

int RSAKey::copyQ (mpz_t *to) const
{
  if (!to)
    return -1;
  mpz_init_set (*to, _q);
  return 1;
}

void RSAKey::setN (const mpz_t *newN)
{
  if (_initialized)
    {
      mpz_shred (_n);
    }
  mpz_init_set (_n, *newN);
}

void RSAKey::setE (const mpz_t *newE)
{
  if (_initialized)
    {
      mpz_shred (_e);
    }
  mpz_init_set (_e, *newE);
}


void RSAKey::setD (const mpz_t *newD)
{
  if (_initialized)
    {
      mpz_shred (_d);
    }
  mpz_init_set (_d, *newD);
}


void RSAKey::setP (const mpz_t *newP)
{
  if (_initialized)
    {
      mpz_shred (_p);
    }
  mpz_init_set (_p, *newP);
}


void RSAKey::setQ (const mpz_t *newQ)
{
  if (_initialized)
    {
      mpz_shred (_q);
    }
  mpz_init_set (_q, *newQ);
}


// Calcule res = data ^ d mod (n)
int RSAKey::private_exponentiation (mpz_t *res, mpz_t *data)
{
  // verifier que les pointeurs sont non nuls
  if (!res || !data)
    return -3;
  
  // verifier que l'objet est initialise
  /*
  if (! _initialized)
    return -2;
  */
  // verifier que data < n
  if (mpz_cmp (*data, _n) >= 0)
    {
      return -1;
    }

  // calculer res
  mpz_init (*res);
  mpz_powm (*res, *data, _d, _n);

  return 0;
}


int RSAKey::private_exponentiation (unsigned char *res, size_t *resLen, const unsigned char *data, const size_t dataLen)
{
  mpz_t mpz_data, mpz_res;
  size_t resLen_tmp = 0;
  int rv = 0;

  mpz_init (mpz_data);
  mpz_init (mpz_res);

  if ((!res) || (!resLen) || (!data))
    {
      rv = -1;
      goto end;
    }
  
  // conversion de data en mpz
  mpz_import (mpz_data, dataLen, 1, sizeof (unsigned char), 0, 0, data);

  // exponentiation
  rv = private_exponentiation (&mpz_res, &mpz_data);
  if (rv != 0)
    {
      rv = -3;
      goto end;
    }

  // conversion du resultat mpz en uchar *res
  mpz_export (res, &resLen_tmp, 1, sizeof (unsigned char), 0, 0, mpz_res);

  *resLen = resLen_tmp;

 end:

  mpz_shred (mpz_data);
  mpz_shred (mpz_res);

  return rv;
}

// Calcule res = data ^ e mod (n)
int RSAKey::public_exponentiation (mpz_t *res, mpz_t *data)
{
  // verifier que les pointeurs sont non nuls
  if (!res || !data)
    return -3;
  
  // verifier que l'objet est initialise
  /*
  if (! _initialized)
    return -2;
  */
  // verifier que data < n
  if (mpz_cmp (*data, _n) >= 0)
    {
      return -1;
    }

  // calculer res
  mpz_init (*res);
  mpz_powm (*res, *data, _e, _n);

  return 0;
}


int RSAKey::public_exponentiation (unsigned char *res, size_t *resLen, const unsigned char *data, const size_t dataLen)
{
  mpz_t mpz_data, mpz_res;
  size_t resLen_tmp = 0;
  int rv = 0;

  mpz_init (mpz_data);
  mpz_init (mpz_res);

  if ((!res) || (!resLen) || (!data))
    {
      rv = -1;
      goto end;
    }
  
  // conversion de data en mpz
  mpz_import (mpz_data, dataLen, 1, sizeof (unsigned char), 0, 0, data);

  // exponentiation
  rv = public_exponentiation (&mpz_res, &mpz_data);
  if (rv != 0)
    {
      rv = -3;
      goto end;
    }

  // conversion du resultat mpz en uchar *res
  mpz_export (res, &resLen_tmp, 1, sizeof (unsigned char), 0, 0, mpz_res);

  *resLen = resLen_tmp;

 end:

  mpz_shred (mpz_data);
  mpz_shred (mpz_res);

  return rv;
}

int RSAKey::pkcs1_v1_5_encode (unsigned char *res, const size_t emLen, const unsigned char *data, const size_t dataLen, ANSSIPKI_HASH::hash_function_t hashFunc)
{
  int rv = 0;
  size_t psLen = 0;
  unsigned int i = 0;
  size_t dihLen = 0; 
  size_t tLen = 0;
  
  if (!data)
    {
      rv = -1;
      goto end;
    }

  if (emLen < dataLen + 11)
    {
      rv = -2;
      goto end;
    }

  // hashFunc == (ANSSIPKI_HASH::sha1) ? dihLen = ANSSIPKI_HASH::digestInfoHeader_sha1_len : dihLen = 0;
  if (!ANSSIPKI_HASH::copyDigestInfoHeader (NULL, &dihLen, hashFunc))
    {
      rv = -3;
      goto end;
    }

  tLen = dataLen + dihLen;
  psLen = emLen - tLen - 3;
  
  /* res = 0x00 | 0x01 | PS | 0x00 | dih | data ; PS = 0xFF | ... | 0xFF */
  // 00 | 01
  res[0] = 0x00;
  res[1] = 0x01;
  // PS
  for (i=2; i<2+psLen; i++)
    {
      res[i] = 0xFF;
    }
  // 00
  res[i] = 0x00;
  i ++;
  // dih
  if (!ANSSIPKI_HASH::copyDigestInfoHeader (&(res[i]), &dihLen, hashFunc))
    {
      rv = -3;
      goto end;
    }
  i += (unsigned int) dihLen;
  /*
  if (dihLen)
    {
      memcpy (&(res[i]), &(ANSSIPKI_HASH::digestInfoHeader_sha1)[0], dihLen);
      i += dihLen;
    }
  */
  // data
  memcpy (&(res[i]), data, dataLen);

  rv = 0;

 end:

  return rv;
}

int ANSSIPKI_HASH::copyDigestInfoHeader (unsigned char *dst, size_t *len, hash_function_t hash)
{
  const unsigned char *pSrc = NULL;
  size_t srcLen = 0;

  if (!len)
    return -1;

  if (hash == ANSSIPKI_HASH::invalid)
    {
      *len = 0;
      return 1;
    }
  switch (hash)
    {
    case ANSSIPKI_HASH::sha1:
      pSrc = ANSSIPKI_HASH::digestInfoHeader_sha1;
      srcLen = ANSSIPKI_HASH::digestInfoHeader_sha1_len;
      break;

    case ANSSIPKI_HASH::sha256:
      pSrc = ANSSIPKI_HASH::digestInfoHeader_sha256;
      srcLen = ANSSIPKI_HASH::digestInfoHeader_sha256_len;
      break;

    case ANSSIPKI_HASH::sha384:
      pSrc = ANSSIPKI_HASH::digestInfoHeader_sha384;
      srcLen = ANSSIPKI_HASH::digestInfoHeader_sha384_len;
      break;

    case ANSSIPKI_HASH::sha512:
      pSrc = ANSSIPKI_HASH::digestInfoHeader_sha512;
      srcLen = ANSSIPKI_HASH::digestInfoHeader_sha512_len;
      break;

    default:
      return -2;
    }
  
  if (!dst)
    {
      *len = srcLen;
      return 1;
    }
  
  if (srcLen > *len)
    return -3;

  *len = srcLen;
  memcpy (dst, pSrc, srcLen);
  return 1;
}
