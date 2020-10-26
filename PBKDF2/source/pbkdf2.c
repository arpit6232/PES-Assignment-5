/*
 * pbkdf2.c
 *
 * A perfectly legitimate implementation of HMAC and PBKDF2, but based
 * on the "ISHA" insecure and bad hashing algorithm.
 * 
 * Author: Howdy Pierce, howdy.pierce@colorado.edu
 */

#include <assert.h>
#include "pbkdf2.h"
#include <string.h>


/*
 * See function description in pbkdf2.h
 */
void hmac_isha(const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t *digest)
{
  uint8_t ipad[ISHA_BLOCKLEN];
  uint8_t opad[ISHA_BLOCKLEN];
  uint8_t keypad[ISHA_BLOCKLEN];
  uint8_t inner_digest[ISHA_DIGESTLEN];
  size_t i;
  ISHAContext ctx;

  if (key_len > ISHA_BLOCKLEN) {
    // If key_len > ISHA_BLOCKLEN reset it to key=ISHA(key)
    ISHAReset(&ctx);
    ISHAInput(&ctx, key, key_len);
    ISHAResult(&ctx, keypad);

  } else {
    // key_len <= ISHA_BLOCKLEN; copy key into keypad, zero pad the result
	memcpy( keypad, key, key_len );
	memset( keypad + key_len, 0x00, ISHA_BLOCKLEN );
  }

  // XOR key into ipad and opad
  i = 0;
  while(i<ISHA_BLOCKLEN) {
	  ipad[i] = keypad[i] ^ 0x36;
	  opad[i] = keypad[i] ^ 0x5c;
	  i++;
  }

  // Perform inner ISHA
  ISHAReset(&ctx);
  ISHAInput(&ctx, ipad, ISHA_BLOCKLEN);
  ISHAInput(&ctx, msg, msg_len);
  ISHAResult(&ctx, inner_digest);

  // perform outer ISHA
  ISHAReset(&ctx);
  ISHAInput(&ctx, opad, ISHA_BLOCKLEN);
  ISHAInput(&ctx, inner_digest, ISHA_DIGESTLEN);
  ISHAResult(&ctx, digest);

}


/*
 * Implements the F function as defined in RFC 8018 section 5.2
 *
 * Parameters:
 *   pass      The password
 *   pass_len  length of pass
 *   salt      The salt
 *   salt_len  length of salt
 *   iter      The iteration count ("c" in RFC 8018)
 *   blkidx    the block index ("i" in RFC 8018)
 *   result    The result, which is ISHA_DIGESTLEN bytes long
 * 
 * Returns:
 *   The result of computing the F function, in result
 */
static void F(const uint8_t *pass, size_t pass_len,
    const uint8_t *salt, size_t salt_len,
    int iter, unsigned int blkidx, uint8_t *result)
{

	uint8_t inner_digest[ISHA_DIGESTLEN];
		  	ISHAContext ctx;


  uint8_t temp[ISHA_DIGESTLEN];
  uint8_t saltplus[2048];
  size_t i;
  uint8_t ipad[ISHA_BLOCKLEN];
  uint8_t opad[ISHA_BLOCKLEN];
  assert(salt_len + 4 <= sizeof(saltplus));

  for (i=0; i<pass_len; i++) {
	  ipad[i] = pass[i] ^ 0x36;
	  opad[i] = pass[i] ^ 0x5c;
  }

  memset( ipad + i, 0x36, ISHA_BLOCKLEN - i );
  memset( opad + i, 0x5C, ISHA_BLOCKLEN - i );

  memcpy( saltplus, salt, salt_len );
   i = salt_len;


  // append blkidx in 4 bytes big endian
  saltplus[i] = (blkidx & 0xff000000) >> 24;
  saltplus[i+1] = (blkidx & 0x00ff0000) >> 16;
  saltplus[i+2] = (blkidx & 0x0000ff00) >> 8;
  saltplus[i+3] = (blkidx & 0x000000ff);

  // Perform inner ISHA
  ISHAReset(&ctx);
  ISHAInput(&ctx, ipad, ISHA_BLOCKLEN);
  ISHAInput(&ctx, saltplus, salt_len+4);
  ISHAResult(&ctx, inner_digest);

  // perform outer ISHA
  ISHAReset(&ctx);
  ISHAInput(&ctx, opad, ISHA_BLOCKLEN);
  ISHAInput(&ctx, inner_digest, ISHA_DIGESTLEN);
  ISHAResult(&ctx, temp);

  memcpy( result, temp, ISHA_DIGESTLEN );

  int j = 1;
  while(j<iter) {
	  // Perform inner ISHA
	  ISHAReset(&ctx);
	  ISHAInput(&ctx, ipad, ISHA_BLOCKLEN);
	  ISHAInput(&ctx, temp, ISHA_DIGESTLEN);
	  ISHAResult(&ctx, inner_digest);

	  // perform outer ISHA
	  ISHAReset(&ctx);
	  ISHAInput(&ctx, opad, ISHA_BLOCKLEN);
	  ISHAInput(&ctx, inner_digest, ISHA_DIGESTLEN);
	  ISHAResult(&ctx, temp);
	  int i = 0;
	  while(i<ISHA_DIGESTLEN) {
		result[i] ^= temp[i];
		i++;
	  }
	  j++;
  }


}


/*
 * See function description in pbkdf2.h
 */
void pbkdf2_hmac_isha(const uint8_t *pass, size_t pass_len,
    const uint8_t *salt, size_t salt_len, int iter, size_t dkLen, uint8_t *DK)
{
  uint8_t accumulator[2560];
  assert(dkLen < sizeof(accumulator));

  int l = dkLen / ISHA_DIGESTLEN + 1;
  int i = 0;
  while(i<l) {
	  F(pass, pass_len, salt, salt_len, iter, i+1, accumulator + i*ISHA_DIGESTLEN);
	  i++;
  }

  memcpy( DK, accumulator, dkLen );
}



