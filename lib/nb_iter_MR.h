// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2000-2018 ANSSI. All Rights Reserved.
#ifndef NB_ITER_MR_H
#define NB_ITER_MR_H

//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Détermination du nombre d'itérations de Miller-Rabin nécessaires
//
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

/* Une entrée {k, t} de la table indique que t itérations sont suffisantes
   pour des entiers de longueur supérieure ou égale à k bits. Elle a été générée
   à partir d'une formule basée sur l'article "Average Case Error Estimates For
   The Strong Probable Test Prime", de Damgard, Landrock et Pomerance.  Elle
   correspond à une probabilité d'erreur du test de 2^{-128}, l'entrée du test
   de MR étant un entier aléatoire. Le NIST s'appuie sur le même article
   pour justifier le nombre d'itération de MR qu'il préconise, cf annexe C de
   FIPS 186-4. */

static const unsigned int nb_iter_MR_table_len = 60;

static unsigned int nb_iter_MR_table[nb_iter_MR_table_len][2] = {
{0, 200},
{50, 60},
{54, 59},
{61, 58},
{67, 57},
{74, 56},
{80, 55},
{86, 54},
{93, 53},
{99, 52},
{105, 51},
{111, 50},
{118, 49},
{124, 48},
{130, 47},
{136, 46},
{142, 45},
{149, 44},
{155, 43},
{161, 42},
{167, 41},
{173, 40},
{179, 39},
{186, 38},
{192, 37},
{198, 36},
{204, 35},
{210, 34},
{216, 33},
{222, 32},
{229, 31},
{235, 30},
{241, 29},
{247, 28},
{253, 27},
{259, 26},
{266, 25},
{273, 24},
{281, 23},
{291, 22},
{302, 21},
{314, 20},
{327, 19},
{341, 18},
{357, 17},
{375, 16},
{396, 15},
{419, 14},
{447, 13},
{479, 12},
{517, 11},
{563, 10},
{620, 9},
{691, 8},
{782, 7},
{906, 6},
{1080, 5},
{1345, 4},
{1794, 3},
{2719, 2}};

/* Cette fonction détermine, pour un entier k le nombre suffisant
   d'itérations de Miller-Rabin */
static unsigned int nb_iter_MR(size_t k) {
  unsigned int i, a = 0, b = nb_iter_MR_table_len;
  while (b-a > 1) {
      i = (a + b) / 2;
      if (k < nb_iter_MR_table[i][0])
          b = i;
      else
          a = i;
  }
  return nb_iter_MR_table[a][1];
}

#endif
