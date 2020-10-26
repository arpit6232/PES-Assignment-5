/*
 * isha.c
 *
 * A completely insecure and bad hashing algorithm, based loosely on
 * SHA-1 (which is itself no longer considered a good hashing
 * algorithm)
 *
 * Based on code for sha1 processing from Paul E. Jones, available at
 * https://www.packetizer.com/security/sha1/
 *
 *
 * ** Arpit Savarkar Edit**
 * Updated the length logic in accordance to
 * http://mercury.pr.erau.edu/~siewerts/cec450/code/example-3/sha1.c
 */

#include <string.h>
#include "isha.h"


/*
 * circular shift macro
 */
#define ISHACircularShift(bits,word) \
  ((((word) << (bits)) & 0xFFFFFFFF) | ((word) >> (32-(bits))))


/*  
 * Processes the next 512 bits of the message stored in the MBlock
 * array.
 *
 * Parameters:
 *   ctx         The ISHAContext (in/out)
 */
static void ISHAProcessMessageBlock(ISHAContext *ctx)
{
  uint32_t temp;
  int t=0;
  uint32_t A, B, C, D, E;

  A = ctx->MD[0];
  B = ctx->MD[1];
  C = ctx->MD[2];
  D = ctx->MD[3];
  E = ctx->MD[4];

//  for(t=0; t<16; t++) {
  while(t<16) {
	  temp = (ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E +
			  ( (((uint32_t) ctx->MBlock[t*4]) << 24) | (((uint32_t) ctx->MBlock[t*4+1]) << 16) |
					  (((uint32_t) ctx->MBlock[t*4+2]) << 8) | ( ((uint32_t) ctx->MBlock[t*4+3]))) ) & 0xFFFFFFFF ;
	  E = D;
	  D = C;
	  C = ISHACircularShift(30,B);
	  B = A;
	  A = temp;
	  t++;
  }



  ctx->MD[0] = (ctx->MD[0] + A) & 0xFFFFFFFF;
  ctx->MD[1] = (ctx->MD[1] + B) & 0xFFFFFFFF;
  ctx->MD[2] = (ctx->MD[2] + C) & 0xFFFFFFFF;
  ctx->MD[3] = (ctx->MD[3] + D) & 0xFFFFFFFF;
  ctx->MD[4] = (ctx->MD[4] + E) & 0xFFFFFFFF;

  ctx->MB_Idx = 0;


}


/*  
 * The message must be padded to an even 512 bits.  The first padding
 * bit must be a '1'.  The last 64 bits represent the length of the
 * original message.  All bits in between should be 0. This function
 * will pad the message according to those rules by filling the MBlock
 * array accordingly. It will also call ISHAProcessMessageBlock()
 * appropriately. When it returns, it can be assumed that the message
 * digest has been computed.
 *
 * Parameters:
 *   ctx         The ISHAContext (in/out)
 */
static void ISHAPadMessage(ISHAContext *ctx)
{
  /*
   *  Check to see if the current message block is too small to hold
   *  the initial padding bits and length.  If so, we will pad the
   *  block, process it, and then continue padding into a second
   *  block.
   */
  if (ctx->MB_Idx > 55)
  {
    ctx->MBlock[ctx->MB_Idx++] = 0x80;
    memset(ctx->MBlock + ctx->MB_Idx, 0, 64 - ctx->MB_Idx);
    ISHAProcessMessageBlock(ctx);
    memset(ctx->MBlock, 0, 58);
  }
  else
  {
    ctx->MBlock[ctx->MB_Idx++] = 0x80;
    // Had to remove the while loop here
    memset(ctx->MBlock + ctx->MB_Idx, 0, 59 - ctx->MB_Idx);
  }

  /*
   *  Store the message length as the last 8 octets
   */

    ctx->MBlock[59] = (ctx->buffer >> 29) & 0xFF;
    ctx->MBlock[60] = (ctx->buffer >> 21) & 0xFF;
    ctx->MBlock[61] = (ctx->buffer >> 13) & 0xFF;
    ctx->MBlock[62] = (ctx->buffer >> 5) & 0xFF;
    ctx->MBlock[63] = (ctx->buffer << 3) & 0xFF;

  ISHAProcessMessageBlock(ctx);


}


void ISHAReset(ISHAContext *ctx)
{
//  ctx->Length_Low  = 0;
//  ctx->Length_High = 0;
  ctx->MB_Idx = 0;
  ctx->buffer = 0;

  ctx->MD[0]       = 0x67452301;
  ctx->MD[1]       = 0xEFCDAB89;
  ctx->MD[2]       = 0x98BADCFE;
  ctx->MD[3]       = 0x10325476;
  ctx->MD[4]       = 0xC3D2E1F0;

  ctx->Computed    = 0;
  ctx->Corrupted   = 0;


}


void ISHAResult(ISHAContext *ctx, uint8_t *digest_out)
{
  if (!ctx->Computed)
  {
    ISHAPadMessage(ctx);
    ctx->Computed = 1;
  }


  // using built in functions optimizes the code for For faster speed
  // Removing the while loop here
  *((uint32_t *)(digest_out )) = bswap32(ctx->MD[0]);
  *((uint32_t *)(digest_out + 4)) = bswap32(ctx->MD[1]);
  *((uint32_t *)(digest_out + 8)) = bswap32(ctx->MD[2]);
  *((uint32_t *)(digest_out + 12)) = bswap32(ctx->MD[3]);
  *((uint32_t *)(digest_out + 16)) = bswap32(ctx->MD[4]);

  return;
}


void ISHAInput(ISHAContext *ctx, const uint8_t *message_array, size_t length)
{
  int temp = 0;
  if (!length)
  {
    return;
  }

  ctx->buffer += length;

  while(length)
  {
	  temp = length;
	if( (64 - ctx->MB_Idx) < length) {
		temp = 64 - ctx->MB_Idx;
	}

	memcpy(ctx->MBlock + ctx->MB_Idx, message_array, temp);
	ctx->MB_Idx += temp;
	message_array += temp;
	length -= temp;


    if (ctx->MB_Idx == 64)
    {
      ISHAProcessMessageBlock(ctx);
    }
  }

}


