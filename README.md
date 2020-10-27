# Optimization of ISHA 

## Introduction 
The goal here is to optimizing for better performance of key derivation function is known as PBKDF2, which is defined in RFC 8018. PBKDF2 is
used in a number of applications, including WPA2-PSK—perhaps the most widespread authentication
system used today in deployed Wi-Fi networks.
As used in WPA2-PSK, the PBKDF2 function relies on calling HMAC-SHA1 8192 times; each call to
HMAC-SHA1 in turn results in two calls to the SHA-1 secure hashing algorithm. And optimizing the digest/hashing described under ISHA - Insecure Hashing Algorithm 


# Code Optimization 
Following Changes were incorporated . <br />

## Function -> static void ISHAProcessMessageBlock(ISHAContext *ctx):** <br />
1) W(t) loop was combined into a single loop <br />
    -  Previously <br />
        for(t = 0; t < 16; t++) <br />
        { <br /> 
            W[t] = ((uint32_t) ctx->MBlock[t * 4]) << 24; <br />
            W[t] |= ((uint32_t) ctx->MBlock[t * 4 + 1]) << 16; <br />
            W[t] |= ((uint32_t) ctx->MBlock[t * 4 + 2]) << 8; <br />
            W[t] |= ((uint32_t) ctx->MBlock[t * 4 + 3]); <br />
        } 

        for(t = 0; t < 16; t++) <br />
        { <br />
            temp = ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E + W[t]; <br />
            temp &= 0xFFFFFFFF; <br />
            E = D; <br />
            D = C; <br />
            C = ISHACircularShift(30,B); <br />
            B = A; <br />
            A = temp; <br />
        } 
<br />
    - Updated <br />
<br />
        while(t<16) { 
  
        temp = (ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E +  
                ( (((uint32_t) ctx->MBlock[t*4]) << 24) | (((uint32_t) ctx->MBlock[t*4+1]) << 16) |
                        (((uint32_t) ctx->MBlock[t*4+2]) << 8) | ( ((uint32_t) ctx->MBlock[t*4+3]))) ) & 0xFFFFFFFF ; <br />
<br />        
        E = D;  <br />
<br />        
        D = C; <br />
<br />        
        C = ISHACircularShift(30,B); <br />
<br />        
        B = A; <br />
<br />        
        A = temp; <br />
<br />        
        t++; <br />
<br />  
        } <br />
<br />

## Function -> static void ISHAPadMessage(ISHAContext *ctx):** <br />
1) Padding logic was changed to incorporate processing data from a single length file <br />
2) memset replaced setting to '0' logic<br />
3) Padding of length had to be recalculated in terms of bytes and bits 
    -  Previously <br />
        if (ctx->MB_Idx > 55)
            {
                ctx->MBlock[ctx->MB_Idx++] = 0x80;
                while(ctx->MB_Idx < 64)
                {
                ctx->MBlock[ctx->MB_Idx++] = 0;
                }
                ISHAProcessMessageBlock(ctx);
                while(ctx->MB_Idx < 56)
                {
                ctx->MBlock[ctx->MB_Idx++] = 0;
                }
            }
            else
            { 
                ctx->MBlock[ctx->MB_Idx++] = 0x80;
                while(ctx->MB_Idx < 56)
                {
                ctx->MBlock[ctx->MB_Idx++] = 0;
                }
            }

            ctx->MBlock[56] = (ctx->Length_High >> 24) & 0xFF;
            ctx->MBlock[57] = (ctx->Length_High >> 16) & 0xFF;
            ctx->MBlock[58] = (ctx->Length_High >> 8) & 0xFF;
            ctx->MBlock[59] = (ctx->Length_High) & 0xFF;
            ctx->MBlock[60] = (ctx->Length_Low >> 24) & 0xFF;
            ctx->MBlock[61] = (ctx->Length_Low >> 16) & 0xFF;
            ctx->MBlock[62] = (ctx->Length_Low >> 8) & 0xFF;
            ctx->MBlock[63] = (ctx->Length_Low) & 0xFF;

<br />
    - Updated  <br />
        <br />
        <br />if (ctx->MB_Idx > 55) 
            {   
            <br />    ctx->MBlock[ctx->MB_Idx++] = 0x80;
            <br />    memset(ctx->MBlock + ctx->MB_Idx, 0, ISHA_BLOCKLEN - ctx->MB_Idx);
            <br />    ISHAProcessMessageBlock(ctx);
            <br />    memset(ctx->MBlock, 0, ISHA_BLOCKLEN - 6);      
            <br />}
            <br />else
            <br />{
            <br />    ctx->MBlock[ctx->MB_Idx++] = 0x80;
            <br />    // Had to remove the while loop here
            <br />    memset(ctx->MBlock + ctx->MB_Idx, 0, 59 - ctx->MB_Idx);
            <br />}
<strong>
        ctx->MBlock[59] = (ctx->buffer >> MBlockConst1) & 0xFF; <br />
        ctx->MBlock[60] = (ctx->buffer >> MBlockConst2) & 0xFF; <br />
        ctx->MBlock[61] = (ctx->buffer >> MBlockConst3) & 0xFF; <br />
        ctx->MBlock[62] = (ctx->buffer >> MBlockConst4) & 0xFF; <br />
        ctx->MBlock[63] = (ctx->buffer << MBlockConst5) & 0xFF; <br />
</strong>
<br />

## Function -> void ISHAResult(ISHAContext *ctx, uint8_t *digest_out)** <br />
1) All the big endian calculations were replaced with bswap32 <br />
    -  Previously <br />
        for (int i=0; i<20; i+=4) { <br />
        digest_out[i]   = (ctx->MD[i/4] & 0xff000000) >> 24; <br />
        digest_out[i+1] = (ctx->MD[i/4] & 0x00ff0000) >> 16; <br />
        digest_out[i+2] = (ctx->MD[i/4] & 0x0000ff00) >> 8; <br />
        digest_out[i+3] = (ctx->MD[i/4] & 0x000000ff); <br />
        } <br />
<br />

    - Updated <br />
<br />
        *((uint32_t *)(digest_out )) = bswap32(ctx->MD[0]); <br />
        *((uint32_t *)(digest_out + 4)) = bswap32(ctx->MD[1]); <br />
        *((uint32_t *)(digest_out + 8)) = bswap32(ctx->MD[2]); <br />
        *((uint32_t *)(digest_out + 12)) = bswap32(ctx->MD[3]); <br />
        *((uint32_t *)(digest_out + 16)) = bswap32(ctx->MD[4]); <br />
<br />


## Function -> void ISHAInput(ISHAContext *ctx, const uint8_t *message_array, size_t length)** <br />
1) Length_Low and Length_High were replaced by a single buffer calculation and Corrupted check was removed<br />
    -  Previously <br />
        if (ctx->Computed || ctx->Corrupted) <br />
        { <br />
            ctx->Corrupted = 1; <br />
            return; <br /> 
        } <br />

        while(length-- && !ctx->Corrupted) 
            {
            ctx->MBlock[ctx->MB_Idx++] = (*message_array & 0xFF); 

            ctx->Length_Low += 8;
            ctx->Length_Low &= 0xFFFFFFFF;
            if (ctx->Length_Low == 0)
            {
            ctx->Length_High++;
            ctx->Length_High &= 0xFFFFFFFF;
            if (ctx->Length_High == 0)
            {
                ctx->Corrupted = 1;
            }
        }
<br />
    - Updated <br />

        ctx->buffer += length;
        while(length)
        {
        temp = length;
        if( (ISHA_BLOCKLEN - ctx->MB_Idx) < length) {
            temp = ISHA_BLOCKLEN - ctx->MB_Idx;
        }

        memcpy(ctx->MBlock + ctx->MB_Idx, message_array, temp);
        ctx->MB_Idx += temp;
        message_array += temp;
        length -= temp;
        

## Function -> void F(...)** <br />
1) Part of the logic of the hmac_isha into F(__) to remove duplicate checks and assertions<br />
    -  Previously <br />
        for (i=0; i<salt_len; i++)
        saltplus[i] = salt[i];
<br />
        **AND**  
<br />

        for (int j=1; j<iter; j++) {  
        hmac_isha(pass, pass_len, temp, ISHA_DIGESTLEN, temp);
        for (int i=0; i<ISHA_DIGESTLEN; i++)
        result[i] ^= temp[i];
        } 

<br />
    - Updated <br />
        - Following Sections were copied from hmac isha and added here  <br /> 
        uint8_t inner_digest[ISHA_DIGESTLEN]; <br /> 
        ISHAContext ctx; <br /> 
        uint8_t ipad[ISHA_BLOCKLEN]; <br /> 
        uint8_t opad[ISHA_BLOCKLEN]; <br /> 
        for (i=0; i<pass_len; i++) { 
            ipad[i] = pass[i] ^ 0x36; 
            opad[i] = pass[i] ^ 0x5c;
        }

<br /> 

        for (int j=1; j<iter; j++) { 
            hmac_isha(pass, pass_len, temp, ISHA_DIGESTLEN, temp);
            for (int i=0; i<ISHA_DIGESTLEN; i++)
            result[i] ^= temp[i];
        }

<br />
        memset( ipad + i, 0x36, ISHA_BLOCKLEN - i );   <br />
        memset( opad + i, 0x5C, ISHA_BLOCKLEN - i ); <br />
        memcpy( saltplus, salt, salt_len );  <br />
        i = salt_len; <br />
        // Perform inner ISHA <br />
        ISHAReset(&ctx); <br />
        ISHAInput(&ctx, ipad, ISHA_BLOCKLEN);  <br />
        ISHAInput(&ctx, saltplus, salt_len+4); <br />
        ISHAResult(&ctx, inner_digest); <br />
        // perform outer ISHA <br />
        ISHAReset(&ctx); <br />
        ISHAInput(&ctx, opad, ISHA_BLOCKLEN); <br />
        ISHAInput(&ctx, inner_digest, ISHA_DIGESTLEN); <br />
        ISHAResult(&ctx, temp); <br />
        memcpy( result, temp, ISHA_DIGESTLEN ); <br />
        int j = 1; <br />

        while(j<iter) { 
            # Perform inner ISHA
            ISHAReset(&ctx);
            ISHAInput(&ctx, ipad, ISHA_BLOCKLEN);
            ISHAInput(&ctx, temp, ISHA_DIGESTLEN);
            ISHAResult(&ctx, inner_digest);
            # perform outer ISHA
            ISHAReset(&ctx);
            ISHAInput(&ctx, opad, ISHA_BLOCKLEN);
            ISHAInput(&ctx, inner_digest, ISHA_DIGESTLEN);
            ISHAResult(&ctx, temp);
            int i = 0;

<br />

            while(i<ISHA_DIGESTLEN) {
                result[i] ^= temp[i];
                i++;
            }
            j++;
        }
        
  
## Function -> void hmac_isha(...) <br />
1) All the big endian calculations were replaced with bswap32 <br />
    -  Previously <br />

        else { 
        for (i=0; i < key_len; i++)<br />
        keypad[i] = key[i];  <br />
        for(i=key_len; i < ISHA_BLOCKLEN; i++) 
        keypad[i] = 0x00; 
        }
<br />
    - Updated <br />
        memcpy( keypad, key, key_len ); <br />
	    memset( keypad + key_len, 0x00, ISHA_BLOCKLEN ); <br />
<br />


# Size .text Analysis 
    - Previously 
        - 20,712 (bytes) 

    - Updated 
        - 20,680

# Runtime Analysis 
    - Previously 
        - 8776 msec

    - Updated 
        - 2610 msec 