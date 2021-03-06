// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2000-2018 ANSSI. All Rights Reserved.
#include <anssipki-crypto.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


typedef int (*hash_function_t) (const char* string, const size_t string_len, char* result);

typedef struct {
  char* test;
  size_t len;
  char expected_digest[SHA1_DIGEST_LENGTH + 1];
} sha1_test_t;


void init_million_A (void);
extern sha1_test_t sha1_tests[];


static int check_hash_function (const char* test, const size_t len, const char* expected_digest,
				hash_function_t fn, int digest_len) {
  char digest[digest_len];
  int i, res;

  res = fn(test, len, digest);
  if (res != 0) return 1;

  for (i=0; i<digest_len; i++) {
    if (digest[i] != expected_digest[i])
      return 1;
  }
  return 0;
}


int main (int argc __attribute__((unused)), char* argv[] __attribute__((unused))) {
  try {
    sha1_test_t* t_sha1;
    
    init_million_A ();
    
    for (t_sha1 = sha1_tests; t_sha1->test != NULL; t_sha1++)
      if (check_hash_function (t_sha1->test, t_sha1->len, t_sha1->expected_digest,
			       sha1, SHA1_DIGEST_LENGTH)) {
	fprintf (stderr, "Error while computing a SHA-1 test\n");
	return 1;
      }
    
    return 0;
  } catch (std::exception& e) {
    printf ("Exception caught: %s\n", e.what());
    return 1;
  }
}




char abc[] = {'a', 'b', 'c'};

char million_A[1000*1000];
void init_million_A (void) { 
  memset(million_A ,'a', 1000*1000);
}

char test_str[] = "123456789012345678901234567890123456789012345678901234567890"
  "12345678901234567890123456789012345678901234567890123456789012345678";

sha1_test_t sha1_tests[68] = {
  {abc, 3, "\xa9\x99\x3e\x36\x47\x06\x81\x6a\xba\x3e\x25\x71\x78\x50\xc2\x6c\x9c\xd0\xd8\x9d"},
  {million_A, 1000*1000, "\x34\xaa\x97\x3c\xd4\xc4\xda\xa4\xf6\x1e\xeb\x2b\xdb\xad\x27\x31\x65\x34\x01\x6f"},

  {test_str, 0, "\xda\x39\xa3\xee\x5e\x6b\x4b\x0d\x32\x55\xbf\xef\x95\x60\x18\x90\xaf\xd8\x07\x09"},
  {test_str, 1, "\x35\x6a\x19\x2b\x79\x13\xb0\x4c\x54\x57\x4d\x18\xc2\x8d\x46\xe6\x39\x54\x28\xab"},
  {test_str, 2, "\x7b\x52\x00\x9b\x64\xfd\x0a\x2a\x49\xe6\xd8\xa9\x39\x75\x30\x77\x79\x2b\x05\x54"},
  {test_str, 3, "\x40\xbd\x00\x15\x63\x08\x5f\xc3\x51\x65\x32\x9e\xa1\xff\x5c\x5e\xcb\xdb\xbe\xef"},
  {test_str, 4, "\x71\x10\xed\xa4\xd0\x9e\x06\x2a\xa5\xe4\xa3\x90\xb0\xa5\x72\xac\x0d\x2c\x02\x20"},
  {test_str, 5, "\x8c\xb2\x23\x7d\x06\x79\xca\x88\xdb\x64\x64\xea\xc6\x0d\xa9\x63\x45\x51\x39\x64"},
  {test_str, 6, "\x7c\x4a\x8d\x09\xca\x37\x62\xaf\x61\xe5\x95\x20\x94\x3d\xc2\x64\x94\xf8\x94\x1b"},
  {test_str, 7, "\x20\xea\xbe\x5d\x64\xb0\xe2\x16\x79\x6e\x83\x4f\x52\xd6\x1f\xd0\xb7\x03\x32\xfc"},
  {test_str, 8, "\x7c\x22\x2f\xb2\x92\x7d\x82\x8a\xf2\x2f\x59\x21\x34\xe8\x93\x24\x80\x63\x7c\x0d"},
  {test_str, 9, "\xf7\xc3\xbc\x1d\x80\x8e\x04\x73\x2a\xdf\x67\x99\x65\xcc\xc3\x4c\xa7\xae\x34\x41"},
  {test_str, 10, "\x01\xb3\x07\xac\xba\x4f\x54\xf5\x5a\xaf\xc3\x3b\xb0\x6b\xbb\xf6\xca\x80\x3e\x9a"},
  {test_str, 11, "\x26\x6d\xc0\x53\xa8\x16\x3e\x67\x6e\x83\x24\x30\x70\x24\x1c\x89\x17\xf8\xa8\xa3"},
  {test_str, 12, "\x8d\x99\x3c\xcd\xf6\x28\xe2\x6e\x17\x0a\x94\x9e\xe2\xa3\x87\x04\x55\xdb\xd8\xfa"},
  {test_str, 13, "\x08\xd7\xde\x6c\xbf\x6c\x3f\xa0\xa2\x6e\x09\x4e\x51\x15\xbc\xd1\xa0\xe3\xd2\xc3"},
  {test_str, 14, "\xa0\xc5\x5f\xdf\x6b\x3c\x10\x90\x9d\x8b\x57\x0f\xa4\x21\x9f\x94\x12\x75\xe7\x50"},
  {test_str, 15, "\x65\xcc\x4c\x0b\x6c\xf9\xc5\x6e\x2a\x2d\x80\x1d\xf1\xb9\x9d\xc9\x33\xdb\x99\x91"},
  {test_str, 16, "\xde\xed\x2a\x88\xe7\x3d\xcc\xaa\x30\xa9\xe6\xe2\x96\xf6\x2b\xe2\x38\xbe\x4a\xde"},
  {test_str, 17, "\xa2\x39\x7c\x30\x7a\xec\x53\x3a\xc1\x5d\xdf\x4e\x93\x14\x1e\x1f\x6d\x28\x33\x01"},
  {test_str, 18, "\xc7\x8f\x34\x6c\x2b\x0d\xf0\x2c\xba\x03\x79\x49\x11\x05\x0a\x71\x8c\xa8\xaa\x20"},
  {test_str, 19, "\x25\x0f\x1f\x6e\x73\xf0\xb3\x58\x89\x65\x50\xf6\xf2\x0f\xdc\x1a\x8e\xb1\xe9\xa8"},
  {test_str, 20, "\x7e\x0a\x12\x42\xbd\x8e\xf9\x04\x4f\x27\xdc\xa4\x5f\x5f\x72\xad\x5a\x11\x25\xbf"},
  {test_str, 21, "\xd4\x44\x5e\xe4\xde\x67\xd1\x18\x03\xd3\x55\x27\xd7\xee\x8a\xa2\xaf\x71\xeb\xd8"},
  {test_str, 22, "\x6a\x51\x9f\xa1\x55\x9a\x35\x0c\xf3\x61\x9a\x44\xfe\x76\x98\xe2\x5f\x88\x3a\xd6"},
  {test_str, 23, "\xb3\x8f\xe9\xc4\xf4\x45\x27\x0d\xba\xbe\xf5\x6a\xe6\x68\x09\x6e\xbd\xae\x3b\x2c"},
  {test_str, 24, "\x02\x01\xd3\x57\x98\x25\x19\xfb\xf3\x8e\xd2\x7a\xf9\x4a\xc2\xff\x85\x94\x3f\x07"},
  {test_str, 25, "\xa0\xc8\x4b\x9b\xed\x7a\x6b\x4a\x70\x68\x0a\xac\xc8\x0e\xc7\x8c\xb3\x8f\x19\x7a"},
  {test_str, 26, "\x6f\xe7\x02\x9d\xa5\x6c\xe1\xd1\xa8\x8f\x03\x06\xad\x93\xec\xfb\x1b\xa6\xa2\x65"},
  {test_str, 27, "\xe1\xbd\x63\x30\x42\x94\xfa\xb6\xde\x45\x58\x20\xe4\x45\xcc\xdf\x38\xe9\x18\x59"},
  {test_str, 28, "\x57\x27\x2c\xf5\xd2\xac\x55\x0f\xf7\x09\x7d\xe6\x03\x68\x70\x0e\xf2\x43\xd6\x8b"},
  {test_str, 29, "\xa8\xe6\xa1\x26\x97\xc9\xc4\x5c\xbf\x1e\xae\x53\x1a\xec\xae\x35\x05\x6c\xc4\x7b"},
  {test_str, 30, "\xcc\x84\xfa\x5a\x36\x1f\x86\xa5\x89\x16\x9f\xde\x1e\x4e\x6d\x62\xbc\x78\x6e\x6c"},
  {test_str, 31, "\xa0\x63\x9c\xe4\xaa\xf8\xca\x08\x49\xea\xab\xa4\xd5\x75\x90\xcf\x38\x9e\x30\x86"},
  {test_str, 32, "\x93\x7d\xcb\x68\xf7\x30\x8e\xec\xdb\x70\x2e\xf1\x5f\xaa\x02\x73\x5f\xc3\xcc\x61"},
  {test_str, 33, "\x91\x5c\xd1\x2d\x58\xce\x2f\x82\x09\x59\xe9\xba\x41\xb2\xeb\xb0\x2f\x2e\x60\x05"},
  {test_str, 34, "\x78\x72\x80\xe5\x6b\x6e\xe7\xe3\x8d\xe3\xbd\x38\xda\x85\x97\x3d\xb8\x6b\xef\x9b"},
  {test_str, 35, "\x55\x0f\xdb\x89\xc6\x39\xfd\xf2\xe4\x8b\xc3\x16\x35\xe3\x39\xa6\xd3\x9f\xdf\x9e"},
  {test_str, 36, "\xb0\xf7\xa3\xb2\x1a\x94\x45\x13\x9e\xac\xae\xa9\x69\x64\xd6\x93\x8b\x1c\x10\xb8"},
  {test_str, 37, "\xbc\x34\x2b\x6a\xa8\x35\x4f\xb4\x3d\x20\x00\x28\xe8\x17\xa5\x31\x37\xf1\x1a\x79"},
  {test_str, 38, "\xe8\x56\x66\xa4\x00\x4e\x32\xec\xcf\x19\xdc\xc0\x6e\x60\x16\xc8\xd6\x75\x27\x2e"},
  {test_str, 39, "\x95\xb9\x26\x96\x82\xea\xa8\xa4\xb4\xfe\x5b\xd2\xea\xe1\xbc\x20\x0d\x78\xd0\x05"},
  {test_str, 40, "\xc6\x1a\x2c\x24\x5c\xb0\x7a\x04\x48\x2c\xe5\xb6\x62\xae\x67\xdb\xdb\xe0\x10\xdb"},
  {test_str, 41, "\xa8\xfa\x9c\xa9\x6a\xfd\x91\xf9\x3d\x0f\xc5\x3e\xe7\x6d\xcc\xc1\x19\x9b\x20\xe3"},
  {test_str, 42, "\xf8\xe6\xe8\xb8\xfa\xe7\x32\xca\x8c\xa1\x1f\xd4\xde\xee\x01\xcf\x77\x31\xf4\xa4"},
  {test_str, 43, "\xe4\xf1\x48\x05\xdf\xd1\xe6\xaf\x03\x03\x59\x09\x0c\x53\x5e\x14\x9e\x6b\x42\x07"},
  {test_str, 44, "\x7a\x97\xd4\xed\xef\xd9\x13\x22\xd8\xfd\x61\x14\x52\xe4\xb3\x3b\xf7\x51\x2d\xf3"},
  {test_str, 45, "\x10\xe7\x63\x00\xed\xe8\xaf\x4d\xe8\x96\x9d\xd8\xbc\x41\x93\x93\xf0\x15\x02\x53"},
  {test_str, 46, "\x16\x69\x95\x12\xff\xc0\x0f\x5a\x72\x24\x05\xa1\x0b\x78\xa7\x8c\xb1\xd3\x90\x1a"},
  {test_str, 47, "\xff\x05\xde\x91\x61\xd3\x46\x98\xc5\x55\xdc\x77\x41\xc5\xf7\x0d\x28\xbf\xf9\x6e"},
  {test_str, 48, "\x1a\xb7\xca\xbd\xcc\xce\x0a\xd1\xf1\x7f\x64\x02\xad\x35\xcc\xa4\x33\x86\x9c\xe3"},
  {test_str, 49, "\xcb\x2c\x8d\x54\x98\x46\x4b\xaa\xf7\x80\x90\x63\xd3\xf7\x28\xca\x1e\x23\x3a\x98"},
  {test_str, 50, "\x42\xfc\xb0\x41\xbd\x2c\x58\xec\xb9\x32\xec\x07\x78\xb1\x7f\xf9\x67\x8a\xbc\x60"},
  {test_str, 51, "\x0d\x27\xee\x26\x9e\xec\xfb\x57\x67\x29\x5a\x95\x75\x53\x18\xd3\x45\x7a\x43\x1d"},
  {test_str, 52, "\x52\x94\xe0\x3a\xe8\xeb\x33\xe9\x59\xcb\x16\xd9\x64\x53\x5d\x60\xd8\x08\x46\x74"},
  {test_str, 53, "\xff\xdd\x76\x8b\x4c\x90\x63\x87\x21\x50\xa8\x9b\x94\x21\xe6\xbb\xde\xf1\x9d\x64"},
  {test_str, 54, "\xac\xae\x03\x2b\x28\x1a\x05\x68\xd3\x53\x20\x10\x40\xe4\xbe\xa8\x2e\x87\x87\x83"},
  {test_str, 55, "\x82\x7a\x68\x3f\xdf\xdb\xef\x22\x5a\x24\x21\x07\x8b\x77\x89\xb1\x34\xc7\xea\xfa"},
  {test_str, 56, "\x0a\x84\x66\x6b\x66\xe8\x43\xa4\x14\x60\x88\xfb\x46\xaa\xba\xa9\x98\xb4\xc2\xb1"},
  {test_str, 57, "\x2b\xf2\x16\xf1\xb6\xc7\xe4\x0e\x56\xd3\x66\x57\x79\x49\xb6\x2b\x40\x63\x93\x91"},
  {test_str, 58, "\x54\xac\x6d\xf4\xe1\x1f\xe9\xb1\x1e\x47\x54\x06\xe2\x3a\x17\x1d\xac\x88\x98\x8e"},
  {test_str, 59, "\xb9\xbb\x1e\x4e\x23\xff\x5a\xbd\xd2\x44\x36\x87\xd2\xc6\x17\x47\xd9\x25\x5e\xbc"},
  {test_str, 60, "\x24\x5b\xe3\x00\x91\xfd\x39\x2f\xe1\x91\xf4\xbf\xce\xc2\x2d\xcb\x30\xa0\x3a\xe6"},
  {test_str, 61, "\x04\xae\xb6\x2a\x9e\xdf\xe2\x5e\x6a\xb4\xc0\x0f\x98\x7e\x32\x4d\x71\x87\x52\x73"},
  {test_str, 62, "\xd8\xd0\x73\xb3\x83\x15\x66\x17\xc5\xca\xdf\x17\xf6\x15\x96\xa3\x84\x0a\xfd\x8b"},
  {test_str, 63, "\x98\xb4\xb1\x76\x4e\xa8\x8d\x6c\x3f\xa6\x3b\x70\x79\x9d\xbd\x0c\x03\x37\x2d\x1a"},
  {test_str, 64, "\xc7\x14\x90\xfc\x24\xaa\x3d\x19\xe1\x12\x82\xda\x77\x03\x2d\xd9\xcd\xb3\x31\x03"},
  {NULL, 0, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"}
};
