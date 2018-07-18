// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2000-2018 ANSSI. All Rights Reserved.
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Génération de clés de signature RSA / DSA / ECDSA (version 1.2)
//
// Routines de test de primalité
//
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

#include <cstdlib>

#include "anssipki-crypto.h"
#include "anssipki-common.h"

#include "gmp.h"
#include "nb_iter_MR.h"

/* Quelques notions de complexité */
/**********************************/
/* + Notation L :
   L_x(a, c) = e^(c ln(x)^a ln(ln(x))^(1-a))
   + Probabilité qu'un entier <= x soit y-(super)friable :
   Psi(x, y)/x = u^(-u) avec u = log(x)/log(y)
   + Complexité de NFS :
   L_x(1/3, (64/9)^1/3)
   + Complexité du crible quadratique et d'ECM :
   L_x(1/2, 1)
   + Complexité de Pollard's p-1 (et de Williams' p+1) avec borne de superfriabilité B :
   O(B log_2(B) (log_2(x))^2)
   + Complexité de Pollard's rho :
   O((\pi/2)^(1/2) p^(1/2))
*/

/* Quelques probabilités de friabilité */
/***************************************/
/* La probabilité qu'un entier de N=2^n bits soit 2^B=2^(2^b)-friable est :
   + 2^((b-n) 2^(b-n))
   + N = 128, B = 32 : 2^(-8)
   + N = 256, B = 32 : 2^(-24)
   + N = 512, B = 32 : 2^(-64)
   + N = 1024, B = 32 : 2^(-160)
   + N = 2048, B = 32 : 2^(-384)
   + N = 128, B = 64 : 2^(-2)
   + N = 256, B = 64 : 2^(-8)
   + N = 512, B = 64 : 2^(-24)
   + N = 1024, B = 64 : 2^(-64)
   + N = 2048, B = 64 : 2^(-160)
   + ...
   Coût de Pollard's p-1/Williams' p+1 avec borne 2^B :
   + N = 128, B = 32 : 2^(51)
   + N = 256, B = 32 : 2^(53)
   + N = 512, B = 32 : 2^(55)
   + N = 1024, B = 32 : 2^(57)
   + N = 2048, B = 32 : 2^(59)
   + N = 128, B = 64 : 2^(84)
   + N = 256, B = 64 : 2^(86)
   + N = 512, B = 64 : 2^(88)
   + N = 1024, B = 64 : 2^(90)
   + N = 2048, B = 64 : 2^(92)
*/

/* Considérations sur les nombres premiers d'un module RSA */
/***********************************************************/
/* + p et q doivent être de même taille (pour une sécurité optimale).
   + p et q doivent être uniformément distribués.
   + p et q ne doivent pas être trop proches.
   + p+-1 (et q+-1) ne doit pas être friable, voire être premier.
   + (p-1)/2 +(-)1 ne doit pas être friable, voire être premier.

   + Le point 3 est nécessaire pour éviter de retrouver p et q en calculant une
   racine carrée.
   Pour des tailles de modules RSA usuelles, si le point 2 est vérifié,
   il est obtenu automatiquement.
   + Le point 4 peut se justifier pour éviter des faiblesses vis-à-vis des méthodes
   de factorisations p+-1. Notons cependant que pour des tailles de modules RSA
   usuelles la probabilité que ces méthodes s'appliquent est négligeable.
   Si le point 2 est vérifié, il est donc obtenu automatiquement.
   + Le point 5 semble émaner des attaques consistant à chiffrer de façon répétitive
   un message jusqu'à obtenir une collision. Notons qu'une telle méthode s'apparente
   à de la factorisation en moins efficace.
   Quoi qu'il en soit, si le point 2 est vérifié, il est donc obtenu automatiquement.
   + Les méthodes ECM et NFS s'appliquent inconditionnellement, c'est-à-dire
   qu'il est impossible de filtrer les premiers générés pour s'assurer qu'elles
   ne s'appliquent pas comme dans le cas des méthodes p+-1.
   La seule défense contre ces méthodes est d'utiliser des modules suffisamment
   grands.
   + Pour conclure, le seul critère important à prendre en compte pour générer des
   modules RSA sûrs est de les prendre suffisamment grand et uniformément distribués.

   Référence : "Are 'Strong' Primes Needed for RSA?" par Rivest et Silverman, 1999/2001.
*/

/* Paramètres concernant les nombres premiers */
/**********************************************/

/* PRIMES_SIZE est la taille du tableau contenant les petits nombres premiers
   précalculés.
   PRIMES_PRODUCTS_SIZE est la taille du tableau des produits (tenant dans un
   registre) des  nombres premiers impairs précalculés.
   On omet le premier produit qui est traité à part et stocké dans PP;
   PP_FIRST_OMITTED est la valeur du premier nombre premier utilisé dans ce
   tableau de produits.
   Ces nombres premiers et leurs produits sont utilisés afin de :
   + filtrer des nombres candidats à la primalité;
   + décrêter qu'un nombre est friable.

   Pour le premier point, un choix de PRIMES_SIZE tel que le plus grand nombre
   premier précalculé est le plus grand nombre premier strictement plus petit
   que 2^b permet donc de filter des candidats p à la primalité plus petits que
   2^(2^b) en utilisant comme borne (au moins) log_2(p), ce qui semble
   raisonnable.
*/
/* Ci-dessous les valeurs de PRIMES_SIZE et PRIMES_PRODUCTS_SIZE pour quelques
   choix de b et pouvant être obtenues de la façon suivante à l'aide de Sage:

   sage: b = 16
   sage: prime_pi(2**b)
   6542
   sage: previous_prime(2**b)
   65521
   sage: BITS = 64;
   sage: def pp(first, size, bits):
   ....:     # Start with i=0 because we omit the first product
   ....:     i = 0; p = 1
   ....:     for q in prime_range(first, 2**size):
   ....:         p *= q
   ....:         if log(p, 2).n() >= bits:
   ....:             p = q
   ....:             i += 1
   ....:     return i
   ....: 
   sage: pp(3, b, BITS)
   1576

   + b = 16, BITS = 64 : PRIMES_SIZE=6542, PRIMES_PRODUCTS_SIZE=1576
   + b = 16, BITS = 32 : PRIMES_SIZE=6542, PRIMES_PRODUCTS_SIZE=3221
   + b = 18, BITS = 64 : PRIMES_SIZE=23000, PRIMES_PRODUCTS_SIZE=7062
   + b = 18, BITS = 32 : PRIMES_SIZE=23000, PRIMES_PRODUCTS_SIZE=19678
   + b = 20, BITS = 64 : PRIMES_SIZE=82025, PRIMES_PRODUCTS_SIZE=26737
   + b = 20, BITS = 32 : PRIMES_SIZE=82025, PRIMES_PRODUCTS_SIZE=78703
   + b = 22, BITS = 64 : PRIMES_SIZE=295947, PRIMES_PRODUCTS_SIZE=115248
   + b = 22, BITS = 32 : PRIMES_SIZE=295947, PRIMES_PRODUCTS_SIZE=292625
   + b = 23, BITS = 64 : PRIMES_SIZE=564163, PRIMES_PRODUCTS_SIZE=249356
   + b = 23, BITS = 32 : PRIMES_SIZE=564163, PRIMES_PRODUCTS_SIZE=560841
*/

/* Borne maximale utilisée pour rejeter par division des nombres visiblement
   non premiers avant d'utiliser des tests probabilistes coûteux.
   Cette borne n'a pas d'implications de sécurité, uniquement de performances.
*/
static const unsigned int NB_PRIMES_IN_SIEVE = 6542;
/* Borne maximale utilisée lors de la phase de crible pour décrêter qu'un
   nombre est friable.
   Comme indiqué plus haut, un nombre aléatoire de grande taille ne sera
   en général pas friable.
*/
static const unsigned int NB_PRIMES_TO_CHECK_SMOOTHNESS = 6542;
/* Taille du tableau des premiers nombres premiers.
   Le maximum des deux valeurs ci-dessus.
*/
static const unsigned int PRIMES_SIZE = (NB_PRIMES_IN_SIEVE > NB_PRIMES_TO_CHECK_SMOOTHNESS)
  ? NB_PRIMES_IN_SIEVE : NB_PRIMES_TO_CHECK_SMOOTHNESS;

/* Taille maximale (en bits) du facteur friable d'un nombre pour décrêter
   qu'il n'est pas friable.
   Vu autrement c'est la borne relative qu'on se fixe pour décrêter que le
   cofacteur restant une fois le crible terminé est suffisamment grand
   (bien qu'il n'ait aucune raison de ne pas être friable pour une borne
   légèrement supérieure à primes[PRIMES_SIZE-1])
   et donc que le nombre initial ne semble pas friable.
*/
static const unsigned int SMOOTH_PART_SIZE_LIMIT = 128;

/* Assurons-nous que GMP n'a pas été compilé de façon exotique */
#if GMP_NAIL_BITS != 0
#error GMP nails are not supported.
#endif /* GMP_NAIL_BITS */

/* Quelques constantes pour tester la friabilité/divisibilité par des
   petits premiers.
   Tiré de GMP (gmp-impl.h). */
#if (GMP_NUMB_BITS == 32)
/* 3 x 5 x 7 x 11 x ... x 29 */
static const mp_limb_t PP = 0xC0CFD797;
/* For simplicity we don't use the following constant. */
//#define PP_INVERTED 0x53E5645CL
static const mp_limb_t PP_FIRST_OMITTED = 31;
static const unsigned int PRIMES_PRODUCTS_SIZE = 3221;
#else
#if (GMP_NUMB_BITS == 64)
/* 3 x 5 x 7 x 11 x ... x 53 */
static const mp_limb_t PP = 0xE221F97C30E94E1D;
/* For simplicity we don't use the following constant. */
//#define PP_INVERTED (0x21CFE6CFC938B36BL)
static const mp_limb_t PP_FIRST_OMITTED = 59;
static const unsigned int PRIMES_PRODUCTS_SIZE = 1576;
#else
#error GMP_NUMB_BITS value not supported.
#endif
#endif /* GMP_NUMB_BITS */

/* Une routine de multiplication. On pourrait utiliser __int64/__int128.
   Tiré de GMP/FLINT (longlong.h). */
#if (GMP_LIMB_BITS == 32) && (defined (__i386__) || defined (__i486__) || defined(__amd64__))
#define umul_ppmm(w1, w0, u, v) \
  __asm__ ("mull %3"							\
	   : "=a" (w0), "=d" (w1)					\
	   : "%0" ((mp_limb_t)(u)), "rm" ((mp_limb_t)(v)))
#else
#if (GMP_LIMB_BITS == 64) && defined (__amd64__)
#define umul_ppmm(w1, w0, u, v) \
  __asm__ ("mulq %3"							\
	   : "=a" (w0), "=d" (w1)					\
	   : "%0" ((mp_limb_t)(u)), "rm" ((mp_limb_t)(v)))
#else
#error Architecture not supported.
#endif
#endif /* architecture */

/* Paramètres "l" de l'algorithme 2 de Fouque-Tibouchi: taille des aléas
   générés pendant la deuxième phase */
static const unsigned int FT_ALGO_PARAM_L = GMP_LIMB_BITS;

/* Variables globales (initialisées par initPrimes) */
/****************************************************/

/* Tableaux contenant les premiers utiles a la smoothness (pour
   eviter des attaques), mais également à la vitesse de génération
   (trial division avec les petits nombres premiers, pour éviter une
   expo pour rien) */
static mp_limb_t primes[PRIMES_SIZE];
/* Ainsi que leurs produits et les indices des premiers correspondants */
static unsigned int primesProductsIndices[PRIMES_PRODUCTS_SIZE][2];
static mp_limb_t primesProducts[PRIMES_PRODUCTS_SIZE];

/* Générateur d'aléa non sensible utilisé pour les tests de Miller-Rabbin */
static gmp_randstate_t GMP_state;

//Barak_Halevi_PRNG* rabbinMillerPRNG;

//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Test de (vraie) primalité pour un petit entier par divisibilité
// par des petits entiers.
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Tiré de GMP (mpz/pprime.c).
bool isSmallPrime_Naive (unsigned long int t)
{
  unsigned long int q, r, d;

  if (t < 3 || (t & 1) == 0)
    return t == 2;

  for (d = 3, r = 1; r != 0; d += 2)
    {
      q = t / d;
      r = t - q * d;
      if (q < d)
        return true;
    }
  return false;
}

//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Test de (vraie) primalité pour un petit entier par divisibilité par
// les petits premiers précalculés.
// Ce test est limité par le nombre de nombres premiers précalculés.
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
static bool isSmallPrime_Sieve (unsigned long int t, int bound=0)
{
  unsigned long int q, r, d;

  if (bound == 0)
    bound = PRIMES_SIZE;

  if (t < 3 || (t & 1) == 0)
    return t == 2;

  r = 1;
  for (int i = 1; i < bound; i++)
    {
      d = primes[i];
      q = t / d;
      r = t - q * d;
      if (r == 0)
        return false;
      if (q < d)
        return true;
    }

  throw ANSSIPKIException (E_CRYPTO_BAD_PARAMETER, "Pas assez de nombres premiers précalculés");
}

//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Génération des variables globales (à appeler avant toute utilisation des
// fonctions sur les nombres premiers, excepté les deux ci-dessus !)
// Si cette fonction est appelée plus d'une fois, seule la graine du
// générateur d'aléa servant aux tests de primalité probabiliste est rafraîchie
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
void initPrimes (PRNG& rng) {
  static bool primesInitialized = false;

  if (!primesInitialized) {
    if (gmp_randinit_lc_2exp_size (GMP_state, GMP_RANDOM_INITIALIZER_SIZE) == 0)
      throw ANSSIPKIException (E_CRYPTO_BAD_PARAMETER, "GMP_RANDOM_INITIALIZER_SIZE est trop grand");
  }

  // Initialisation du générateur d'aléa nécessaire au bon
  // fonctionnement de Miller Rabbin
  mpz_t seed;
  rng.getRandomInt (seed, GMP_RANDOM_SEED_SIZE, true);
  gmp_randseed (GMP_state, seed);
  mpz_shred (seed);

  if (primesInitialized) return;

  // Initialisation du tableau des nombres premiers
  unsigned int i = 0;            // i contient le nombre de premiers déjà stockés
  unsigned int j = 0;            //
  unsigned int tested_int = 5;   // il s'agit du prochain nombre à tester
  unsigned int delta = 2;
  unsigned int next;

  if (PRIMES_SIZE < 2) // Code non atteignable ; TODO : le mettre en #if
    throw ANSSIPKIException (E_CRYPTO_BAD_PARAMETER, "PRIMES_SIZE est trop petit");

  primes[i++] = 2;
  primes[i++] = 3;

  while (i < PRIMES_SIZE) {
    bool isPrime = true;

    // On crible avec les entiers premiers déjà trouvés
    isPrime = isSmallPrime_Sieve(tested_int);

    if (isPrime)
      primes[i++] = tested_int;

    next = tested_int + delta;
    if (next < tested_int)
      throw ANSSIPKIException (E_CRYPTO_BAD_PARAMETER, "PRIMES_SIZE est trop grand");
    tested_int = next;

    // Optimisation simple (pour éviter les multiples de 3)
    // Lorsque tested_int = 2 [3], delta vaut 2
    //      si tested_int = 1 [3], delta vaut 4
    delta = 6-delta;
  }

  // Calcul des produits de nombres premiers à partir de PP_FIRST_OMITTED
  mp_limb_t p1, p0, p, q;
  for (i = 0; primes[i] < PP_FIRST_OMITTED; i++)
    ;
  for (j = 0; j < PRIMES_PRODUCTS_SIZE; j++) {
    p = 1;
    primesProductsIndices[j][0] = i;
    for (; i < PRIMES_SIZE; i++) {
      q = primes[i];
      umul_ppmm(p1, p0, p, q);
      if (p1 != 0) {
          break;
      }
      else {
          p = p0;
      }
    }
    primesProductsIndices[j][1] = i;
    primesProducts[j] = p;
  }

  primesInitialized = true;
}

//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Test de pseudo-primalité (ou plutôt de composition) pour un entier
// multiprécision par divisibilité par des petits entiers premiers.
// On suppose que l'entier est impair, voire plus.
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
bool isPrime_Sieve (mpz_t n, size_t bound) {
  /* If n is even, it is not a prime.  */
  if ((mpz_get_ui (n) & 1) == 0)
    return false;
  /* Small odd primes */
  {
  mp_limb_t r;
  /* There is a MPN_MOD_OR_PREINV_MOD_1 macro defined in gmp-impl.h
     which decides whether to use a precomputed inverse or not.
     The threshold for using the precomputed inverse is typically
     below 10 limbs on modern archs, so won't be useful for generating large
     enough RSA keys. */
  /* r = MPN_MOD_OR_PREINV_MOD_1 (PTR(n), (mp_size_t) SIZ(n), (mp_limb_t) PP,
         (mp_limb_t) PP_INVERTED); */
  r = mpn_mod_1((n)->_mp_d, (mp_size_t) ((n)->_mp_size), (mp_limb_t) PP);
  /* To be on the very safe size and be sure to respect the GMP API,
     we could also use mpz_fdiv_ui. */
  /* r = mpz_fdiv_ui(n, PP); */
  if (r % 3 == 0
      || r % 5 == 0
      || r % 7 == 0
      || r % 11 == 0 || r % 13 == 0
      || r % 17 == 0 || r % 19 == 0 || r % 23 == 0 || r % 29 == 0
#if GMP_LIMB_BITS >= 64
      || r % 31 == 0 || r % 37 == 0 || r % 41 == 0 || r % 43 == 0
      || r % 47 == 0 || r % 53 == 0
#endif
      )
    {
      return false;
    }
  }
  /* Other odd primes */
  {
  /* Do more dividing.  We divide our number by the small primes products,
     and look for factors in the remainders.  */
  mp_limb_t r;
  unsigned int i, j;

  if (bound == 0)
    //bound = mpz_sizeinbase(n, 2);
    bound = primes[NB_PRIMES_IN_SIEVE-1];

  if (bound > primes[PRIMES_SIZE-1])
      throw ANSSIPKIException (E_CRYPTO_BAD_PARAMETER, "Pas assez de nombres premiers précalculés");

  for (i = 0, j = primesProductsIndices[i][0]; primes[j-1] < bound; i++) {
    /* Perform one long/short division and then a bunch of short/short divisions */
    /* There is a MPN_MOD_OR_MODEXACT_ODD_1 macro defined in gmp-impl.h
       which decides whether to use a tricky division for odd values and
       usual division.
       The threshold for using the former one is typically around 20 limbs
       on modern archs, which is only relevant for generating moderatly
       large RSA keys. */
    /* r = MPN_MOD_OR_MODEXACT_1_ODD (PTR(n), (mp_size_t) SIZ(n), primesProducts[i]); */
    r = mpn_mod_1((n)->_mp_d, (mp_size_t) ((n)->_mp_size), (mp_limb_t) primesProducts[i]);
    /* r = mpz_fdiv_ui(n, primesProducts[i]); */
    for (; j < primesProductsIndices[i][1]; j++){
      /* Check for factors for each prime by performing a bunch of small divisions */
      if (r % primes[j] == 0) {
        return false;
      }
    }
  }
  }

  /* The following code does the same as above but one prime at a time. */
  /*
  for(unsigned int i = 0; i < NB_PRIMES_IN_SIEVE; i++)
    if (mpz_fdiv_ui(n, primes[i]) == 0)
      return false;
  */

  return true;
}

//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Test de pseudo-primalité (ou plutôt de composition) de Fermat en base 2
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
bool isPrime_Fermat (mpz_t n) {
  mpz_t res;
  int compare;

  mpz_init (res);
  mpz_set_ui(res, 2);
  mpz_powm (res, res, n, n);
  compare= (mpz_cmp_ui(res,2)==0);
  mpz_shred(res);

  return (compare != 0);
}

//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Test de pseudo-primalité (ou plutôt de composition) de Miller-Rabin
// On suppose n impair, voire n > 3
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
bool isPrime_MillerRabin (mpz_t n, int iter) {
  mpz_t r, n_minus_3, n_minus_1, a, y;
  unsigned long s, j;
  bool res = false;
  size_t k;

  k = mpz_sizeinbase(n, 2);
  if (iter == 0)
      iter = nb_iter_MR(k);

  mpz_init(a);
  mpz_init(r);
  mpz_init(y);
  mpz_init(n_minus_3);
  mpz_init(n_minus_1);

  mpz_sub_ui(n_minus_3, n, 3);
  mpz_sub_ui(n_minus_1, n, 1);

  // r et s vérifient n-1 = 2^s * r where r is odd
  s = mpz_scan1(n_minus_1, 0UL);
  mpz_tdiv_q_2exp(r, n_minus_1, s);

  // TODO: Impossible ! A documenter...
  // Si r vaut 0, c'est que n-1 est impair, donc que n vaut 2^s avec s > 1
  // Dans ce cas, il est donc composé
  if (mpz_cmp_ui(r, 0) == 0)
    goto free;

  // Algorithme inspiré de la figure 7.3 P.188 du livre de Serge Vaudenay
  // A Classical Introduction to Cryptography
  // The number of iterations is computed by a function in nb_iter_MR.h
  for(int i=0; i < iter; i++) {
    mpz_urandomm(a, GMP_state, n_minus_3);
    mpz_add_ui(a, a, 2);

    // y = a^r [n]
    mpz_powm(y, a, r, n);

    if (mpz_cmp_ui(y, 1) != 0) {
      for (j=1; mpz_cmp(y, n_minus_1) != 0; j++) {
	// y = a^(r * 2^j)
	mpz_powm_ui(y,y,2,n);

	if (j == s || mpz_cmp_ui(y,1) == 0)
	  goto free;
      }
    }
  }

  res = true;

 free:
  mpz_shred(n_minus_1);
  mpz_shred(n_minus_3);
  mpz_shred(y);
  mpz_shred(r);
  mpz_shred (a);

  return res;
}

//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Test de pseudo-primalité (ou plutôt de composition) de Lucas (FIPS 186-4 C.3.3)
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
bool isPrime_Lucas (mpz_t n) {
  mpz_t m, u, v, u1, v1;
  mpz_t x;
  // D fits in a long
  long D;
  int sign_d;
  size_t r, i;
  int compare;

  if (mpz_perfect_square_p (n)) {
    return false;
  }
  D = 5;
  while (mpz_si_kronecker (D, n) != -1) {
    // produces the sequence (5, -7, 9, -11, ...)
    // until (D / p) = -1
    // groumpf, no mpz_add_si
    if (D  > 0)
      D = -(D + 2);
    else
      D = -(D - 2);
  }
  if (mpz_si_kronecker (D, n) == 0) {
    return false;
  }
  // we may assume that the case jacobi (D, p) == 0 has already been
  // detected by sieving or uniform generation
  sign_d = D > 0 ? 1 : 0;
  D = D > 0 ? D : -D;

  mpz_init (m);
  mpz_init_set_ui (u, 1UL); mpz_init_set_ui (v, 1UL);
  mpz_init (u1); mpz_init (v1);
  mpz_init (x);
  mpz_add_ui (m, n, 1UL);         // m  <- n+1
  r = mpz_sizeinbase (m, 2) - 1;
  for (i = r ; i > 0; i--) {
    mpz_mul (u1, u, v);
    mpz_mul_2exp (u1, u1, 1); // u1 <- 2 u·v
    mpz_mul (v1, v, v);
    mpz_mul (x, u, u);
    // groumpf, there is no mpz_addmul_si
    if (sign_d > 0) {
      mpz_addmul_ui (v1, x, D);
    } else {
      mpz_submul_ui (v1, x, D);
    } // v1 <- v² + D·u²
    if (mpz_tstbit (m, i-1)) {
      mpz_add (u, u1, v1); // u  <- u1 + v1
      // groumpf again
      if (sign_d > 0) {
        mpz_addmul_ui (v1, u1, D);
      } else {
        mpz_submul_ui (v1, u1, D);
      } // v  <- (v + D·u)/2
    } else {
      mpz_swap (u, u1);
    }
    mpz_swap (v, v1);

    mpz_mod (u, u, n);
    mpz_mod (v, v, n);
  } // for (i)

  compare = (!mpz_cmp_ui (u, 0UL));

  mpz_shred(u1);
  mpz_shred(v1);
  mpz_shred(u);
  mpz_shred(v);
  mpz_shred(x);

  return compare;
}

//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Test de pseudo-primalité (ou plutôt de composition) complet
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
bool isPrime(mpz_t n) {
  // TODO : Ajouter une preuve de primalité avec courbes elliptiques ?
    return (isPrime_Sieve (n) && isPrime_MillerRabin (n) && isPrime_Lucas(n));
}

/* Pour l'algorithme de Fouque-Tibouchi il est inutile de cribler par des
   petits premiers pour gagner du temps car les nombres à tester sont
   générer spécifiquement pour ne pas avoir de petits facteurs. */
static bool isPrimeFT(mpz_t n) {
  return (isPrime_MillerRabin(n) && isPrime_Lucas(n));
}

//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Test si un nombre est produit de petits facteurs premiers
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
bool isSmooth(mpz_t n) {
  /* A priori l'entier est friable. */
  bool res = true;

  /* Cette boucle égrenne les petits facteurs premiers en se servant
     des tableaux pré-calculés */
  mpz_t q, cofac;
  mpz_init(cofac);
  mpz_init(q);
  /* Premier pair */
  {
  unsigned long s;
  // cofac et s vérifient n = 2^s * cofac where cofac is odd
  s = mpz_scan1(n, 0UL);
  mpz_tdiv_q_2exp(cofac, n, s);
  }
  /* Petits premiers impairs */
  {
  mp_limb_t r;
  unsigned int j;
  r = mpn_mod_1((cofac)->_mp_d, (mp_size_t) ((cofac)->_mp_size), (mp_limb_t) PP);
  /* r = mpz_fdiv_ui(cofac, PP); */
  for (j = 1; j < primesProductsIndices[0][0]; j++)
      /* Check for factors for each prime by performing a bunch of small divisions */
      if (r % primes[j] == 0)
        while (mpz_fdiv_q_ui(q, cofac, primes[j]) == 0)
          mpz_swap(cofac, q);
  }
  /* Autres premiers impairs */
  {
  /* Do more dividing.  We divide our number by the small primes products,
     and look for factors in the remainders.  */
  mp_limb_t r;
  unsigned int i, j;

  for (i = 0, j = primesProductsIndices[i][0]; j < NB_PRIMES_TO_CHECK_SMOOTHNESS; i++) {
    /* Perform one long/short division and then a bunch of short/short divisions */
    r = mpn_mod_1((cofac)->_mp_d, (mp_size_t) ((cofac)->_mp_size), (mp_limb_t) primesProducts[i]);
    /* r = mpz_fdiv_ui(cofac, primesProducts[i]); */
    for (; j < primesProductsIndices[i][1]; j++)
      /* Check for factors for each prime by performing a bunch of small divisions */
      if (r % primes[j] == 0)
        while (mpz_fdiv_q_ui(q, cofac, primes[j]) == 0)
          mpz_swap(cofac, q);
  }
  }

  if (mpz_cmp_ui(cofac, 1) == 0)
    goto free;

  /* The following code does the same as above but one prime at a time. */
  /*
  mpz_t q, cofac;
  mpz_init_set(cofac, n);
  mpz_init(q);

  for(unsigned int i = 0; i < NB_PRIMES_TO_CHECK_SMOOTHNESS; i++) {
    while (mpz_fdiv_q_ui(q, cofac, primes[i]) == 0)
      mpz_swap(cofac, q);

    if (mpz_cmp_ui(cofac, 1) == 0)
      goto free;
  }
  */

  /* On a vérifié dans la boucle que le cofacteur n'était pas 1.
     Vérifions à présent que les divisions précédentes n'ont pas trop
     effrité le nombre testé : n = cofac * (petits facteurs premiers),
     c'est-à-dire que la partie friable trouvée n'est pas trop grande.
     On veut avoir cofac > n / 2^SMOOTH_PART_SIZE_LIMIT */
  if (mpz_sizeinbase(cofac, 2) > mpz_sizeinbase(n, 2) - SMOOTH_PART_SIZE_LIMIT)
    res = false;
  /* Si le morceau restant est assez grand, on renvoie false (l'entier
     n'est pas friable) */

 free:
  mpz_shred(q);
  mpz_shred(cofac);

  return res;
}

//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Retourne un nombre n tel que
//   * n a les bits nbits - 1 et nbits - 2 à 1 (i.e. 3 x 2^(nbits-2) <= n < 2^nbits)
//   * n est premier
//   * On note m = (n-1)/2
//   * m est premier
//   * n+1 n'est pas friable
//   * m+1 n'est pas friable
//   * m-1 n'est pas friable
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
void findRSAFactor (mpz_t n, const size_t nbits, PRNG& generator, bool init_mpz) {
  // On note n le facteur RSA et m = (n-1) / 2
  mpz_t m;
  mpz_t tmp;

  if (init_mpz) mpz_init (n);
  mpz_init (m);
  mpz_init (tmp);
  while (true) {
    generator.getRandomInt (m, nbits-1, false);

    // On force les 2 bits de poids fort à 1. Ceci nous assure que le
    // module, produit des deux premiers, fera exactement la taille
    // voulue.
    mpz_setbit(m, nbits-2);
    mpz_setbit(m, nbits-3);

    // Un nombre premier supérieur à 6 est égal à 1 ou 5 modulo 6.
    // Cependant, comme n = 2 * m + 1, si m = 1 [6], alors n = 3 [6]
    // et n'est donc pas premier -> si on veut m et n=2m+1 premiers,
    // on a donc nécessairement n = 5 [6]
    mpz_add_ui(m, m, 5 - mpz_fdiv_ui(m,6));

    if (!isPrime_Sieve (m)) continue;

    // Calcul et test de primalité de n=2m+1, candidat pour le résultat
    mpz_mul_2exp(n, m, 1);
    mpz_add_ui(n, n, 1);
    if (!isPrime_Sieve (n)) continue;

    // Test de primalité complets des deux nombres n et m
    //if (!isPrime_Fermat (m)) continue;
    //if (!isPrime_Fermat (n)) continue;
    if (!isPrime_MillerRabin (m)) continue;
    if (!isPrime_MillerRabin (n)) continue;
    if (!isPrime_Lucas (m)) continue;
    if (!isPrime_Lucas (n)) continue;

    // Vérification que m-1 n'est pas friable
    mpz_sub_ui(tmp, m, 1);
    if (isSmooth (tmp)) continue;

    // Vérification que m+1 n'est pas friable
    mpz_add_ui(tmp, m, 1);
    if (isSmooth (tmp)) continue;

    // Vérification que n+1 n'est pas friable
    mpz_add_ui(tmp, n, 1);
    if (isSmooth (tmp)) continue;

    break;
  }

  mpz_shred (m);
  mpz_shred (tmp);
}

//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Genere les paramatres de l'algorithme de generation de premier de
// Fouque-Tibouchi
//  * m et lambda sont les parametres a generer, il s'agit du produit des
//    petits nombres premiers, et de l'exposant correspondant
//    lambda=lambda(m)
//  * wlen taille des limbs gmp
//  * k taille des premiers a generer
// Retourne le plus grand entier inclus dans le produit m.
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
static mp_limb_t genParamFT(mpz_t m, mpz_t lambda, unsigned int wlen, size_t k)
{
    mpz_set_ui(m, 1UL);
    mpz_set_ui(lambda, 1UL);
    unsigned int i = 0;
    while((k - mpz_sizeinbase(m, 2)) >= wlen && i < PRIMES_SIZE) {
        mpz_mul_si(m, m, primes[i]);
        mpz_lcm_ui(lambda, lambda, primes[i]-1);
        i++;
    }
    return primes[i-1];
}

//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Genere un premier p de n bits en utilisant la méthode Fouque-Tibouchi,
// le PRNG generator. Garantit que le premier généré fait exactement n bits.
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
void genPrimeFT(mpz_t p, const size_t n, PRNG& generator, bool init_mpz)
{
    mpz_t b, r, u, l, a;
    mpz_t m, lambda;

    mpz_init(m);
    mpz_init(lambda);
// Génération de (p-1)/2
    genParamFT(m, lambda, FT_ALGO_PARAM_L, n-1);

    mpz_init(a);
    mpz_init(b);
    mpz_init(r);
    mpz_init(u);
    mpz_init(l);
    if (init_mpz) mpz_init(p);

    mpz_sub_ui(l, m, 1UL);
//1
    generator.getRandomIntNB(b, l, false);
    mpz_add_ui(b, b, 1UL);
//2
step2:
    mpz_powm(u, b, lambda, m);
    mpz_neg(u, u);
    mpz_add_ui(u, u, 1UL);
    mpz_mod(u, u, m);
//3
    if (mpz_sgn(u)) {
        generator.getRandomIntNB(r, l, false);
        mpz_add_ui(r, r, 1UL);
        mpz_addmul(b, r, u);
        mpz_mod(b, b, m);
        goto step2;
    }
//Garantir que p fait n bits exactement
    mpz_set_ui(p, 0UL);
    mpz_setbit(p, n-1);
    mpz_sub(r, p, b);
    mpz_cdiv_q(r, r, m);
    mpz_mul_2exp(p, p, 1UL);
    mpz_sub(p, p, b);
    mpz_fdiv_q(p, p, m);
    mpz_sub(l, p, r);
    do {
        generator.getRandomIntNB(a, l, false);
        mpz_add(a, a, r);
        mpz_set(p, b);
        mpz_addmul(p, a, m);
    } while (!isPrimeFT(p));

    mpz_clear(m);
    mpz_clear(lambda);
    mpz_shred(a);
    mpz_shred(b);
    mpz_shred(r);
    mpz_shred(u);
    mpz_shred(l);
}

//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Genere un facteur RSA p de n bits.
// Le premier p satisfait les propriétés suivantes :
// - pdemi = p-1/2 est premier
// - Les deux bits de poids forts de p (et donc p-1/2) sont égaux à 1
// - p+1 n'est pas friable
// - (p-1)/2 - 1 n'est pas friable
// - (p-1)/2 + 1 n'est pas friable
// (p-1)/2 est généré en utilisant la méthode Fouque-Tibouchi, puis la
// primalité de p est testée
// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
void findRSAFactorFT(mpz_t p, const size_t n, PRNG& generator, bool init_mpz)
{
    mpz_t b, r, u, l, a, pdemi;
    mpz_t m, lambda;

    mpz_init(m);
    mpz_init(lambda);
// Calcul des paramètres pour la génération de pdemi
    genParamFT(m, lambda, FT_ALGO_PARAM_L, n-1);

    mpz_init(a);
    mpz_init(b);
    mpz_init(r);
    mpz_init(u);
    mpz_init(l);
    mpz_init(pdemi);
    if (init_mpz) mpz_init(p);

    mpz_sub_ui(l, m, 1UL);
//1
    generator.getRandomIntNB(b, l, false);
    mpz_add_ui(b, b, 1UL);
//2
step2: // Adapté pour tester que ni b, ni 2b+1 n'a de petits facteurs
    mpz_mul_2exp(r, b, 1UL);
    mpz_setbit(r, 0UL); //r <- 2b+1
    mpz_mul(u, b, r);
    mpz_powm(u, u, lambda, m); // u <- b^lambda(2b+1)^lambda mod m
    mpz_neg(u, u);
    mpz_add_ui(u, u, 1UL);
    mpz_mod(u, u, m); //u <- 1 - b^lambda(2b+1)^lambda mod m
//3
    if (mpz_sgn(u)) {
        generator.getRandomIntNB(r, l, false);
        mpz_add_ui(r, r, 1UL);
        mpz_addmul(b, r, u);
        mpz_mod(b, b, m);
        goto step2;
    }
//On garantit que les deux bits de poids fort de pdemi sont à 1
    mpz_set_ui(pdemi, 3UL);
    mpz_mul_2exp(pdemi, pdemi, n-3); // pdemi <- 2^(n-2) + 2^(n-3)
    mpz_sub(r, pdemi, b);
    mpz_cdiv_q(r, r, m); //r <- ceil((2^(n-2) + 2^(n-3) - b)/m)
    mpz_set_ui(pdemi, 0UL);
    mpz_setbit(pdemi, n-1); // pdemi <- 2^(n-1)
    mpz_sub(pdemi, pdemi, b); //pdemi <- 2^(n-1) - b
    mpz_fdiv_q(pdemi, pdemi, m); //pdemi <- floor ((2^(n-1) - b) /m)
    mpz_sub(l, pdemi, r);

    do {
        generator.getRandomIntNB(a, l, false);
        mpz_add(a, a, r);
        mpz_set(pdemi, b);
        mpz_addmul(pdemi, a, m);
        if(!isPrimeFT(pdemi)) continue; //Primality of pdemi
        mpz_mul_2exp(p, pdemi, 1UL);
        mpz_setbit(p, 0UL); // p <- 2pdemi+1
        if (!isPrimeFT(p)) continue; //Primality of p
        // Vérification que pdemi-1 n'est pas friable
        mpz_clrbit(pdemi, 0UL); //pdemi est pseudo premier :
                            //soit il vaut 2 et pdemi-1 sera detecté smooth
                            //soit il est impair et pdemi-1 s'obtient en faisant
                            //un clr du bit 0
        if (isSmooth (pdemi)) continue;

        // Vérification que pdemi+1 n'est pas friable
        mpz_add_ui(pdemi, pdemi, 2UL);
        if (isSmooth (pdemi)) continue;

        // Vérification que p+1 n'est pas friable
        mpz_add_ui(pdemi, p, 1);
        if (isSmooth (pdemi)) continue;

        // On a trouvé!
        break;
    } while (true);

    mpz_clear(m);
    mpz_clear(lambda);
    mpz_shred(a);
    mpz_shred(b);
    mpz_shred(r);
    mpz_shred(u);
    mpz_shred(l);
    mpz_shred(pdemi);
}
