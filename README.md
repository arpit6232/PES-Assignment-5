# Optimization of ISHA 

## Introduction 
The goal here is to optimizing for better performance of key derivation function is known as PBKDF2, which is defined in RFC 8018. PBKDF2 is
used in a number of applications, including WPA2-PSK—perhaps the most widespread authentication
system used today in deployed Wi-Fi networks.
As used in WPA2-PSK, the PBKDF2 function relies on calling HMAC-SHA1 8192 times; each call to
HMAC-SHA1 in turn results in two calls to the SHA-1 secure hashing algorithm. And optimizing the digest/hashing described under ISHA - Insecure Hashing Algorithm 

## Basic Flow of Code 
As defined here : https://tools.ietf.org/html/rfc8018  <br />
Modified here for better clarity and updated parts of the documentation   <br />

Params:        ISHA        Implementation of Insecure Hashing Algorithm ( Basically, a Pseudo Random Function Generator)

Input:          P          password, an octet string <br />
                S          salt, an octet string  <br /> 
                c          iteration count, a positive integer <br />
                dkLen      intended length in octets of the derived key, a positive integer, at most (2^32 - 1) * hLen <br />

Output:         DK         derived key, a dkLen-octet string <br />

Steps: <br />

    -  If dkLen > (2^32 - 1) * hLen, output "derived key too long" and stop 

    -  Let l be the number of hLen-8 bit (1 byte) blocks in the derived key, rounding up, and let r be the number of 8 bits in the last block:

        - l = CEIL (dkLen / hLen) 
        - r = dkLen - (l - 1) * hLen

    -  For each block of the derived key apply the function F defined below to the password P, the salt S, the iteration count c, and the block index to compute the block:

        - T_1 = F (P, S, c, 1) , 
        - T_2 = F (P, S, c, 2) ,
        - ...
        - T_l = F (P, S, c, l) , 

        where the function F is defined as the exclusive-or sum of the first c iterates of the underlying pseudorandom function PRF applied to the password P and the concatenation of the salt S and the block index i:

        - F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c

        where
               - U_1 = ISHA (P, S || INT (i)) ,
               - U_2 = ISHA (P, U_1) ,
               - ...
               - U_c = ISHA (P, U_{c-1}) .

        Here, INT (i) is a four-octet encoding of the integer i, most significant octet first.

    -  Concatenate the blocks and extract the first dkLen octets to produce a derived key DK:

        - DK = T_1 || T_2 ||  ...  || T_l<0..r-1>

    -  Output the derived key DK.

### Outline of ISHA 
A typical application of the key derivation functions defined here
   might include the following steps: <br />

    -  Select a salt S and an iteration count itr 

    -  Select a length in octets for the derived key, dkLen. 

    -  Apply the key derivation function to the password, the salt, the iteration count and the key length to produce a derive key.
        - We define two fixed and different strings ipad and opad as follows (the 'i' and 'o' are mnemonics for inner and outer):

            - ipad = the byte 0x36 repeated B times
            - opad = the byte 0x5C repeated B times.

        - Append zeros to the end of authentication key to create a block length byte string (e.g., if authentication key is of length 20 bytes and Block Length=64, then authentication key will be appended with 44 zero bytes 0x00)
        - XOR (bitwise exclusive-OR) the block length byte string computed in previous with ipad
        - Append the stream of data 'text' to the block length byte string resulting from previous step
        - Apply H to the stream generated in step previous step
        - XOR (bitwise exclusive-OR) the block length byte string computed in First Step with opad
        - Append the H result from step (4) to the block length byte string resulting from previous step
        - Apply H to the stream generated in the previous step and return the result

    -  Output the derived key.  


### Profiling Analsysis before Optimization

Profiling Based Time :<br />
- Following Calculations Exclude the Timings taken by test functions and test_function calls to each function
    - For the base case of the following the Time in Msec run is
        - const char *pass = "Boulder";
        - const char *salt = "Buffaloes";
    <br />
    Without ISHA for 4096 iterations: <br />
    - **pbkdf2_hmac_isha(...)** which calls the **F()** which in turn calls **hmac_isha()** :  107 msec 
    <br />
    With ISHA : <br />
    - A generic code flow is as follows (internal loop branching is ignored),  <br />
        - pbkdf2_hmac_isha() -> F() -> hmac_isha() -> ISHAReset()  <br />
        - ..........................-> hmac_isha() -> ISHAInput()  <br />
        - ..........................-> hmac_isha() -> ISHAResult()  <br />

    With Internal Loops a single iteration of hmac_isha() leads to following times <br />

    For 4096 iterations following is observed <br />
    Single call to F() takes - 2917 msec <br />
    Since F() is called 3 times based on the pbkdf2_hmac_isha() it takes a total of 2917 msec * 3 Iterations = **8751 msec** <br />
    With Function and loop overheads of pbkdf2_hmac_isha() it takes a total of **8776 msec** for the code to run 

    - **Qunatiative Analysis**
        - For the Above Analysis the number of function calls are as follows  (Approximate Results)
            - pbkdf2_hmac_isha(...) = #1 
            - F(...) = #3
            - hmac_isha() = #4096
            - ISHAReset() = #8192
            - ISHAInput() = #16384
            - ISHAResult() = #8192
            
    - **Call Stack Analysis**
            - F(...)
            - ![picture](images/F.png)
            - hmac_isha(...)
            - ![picture](images/hmac_isha.png)
            - ISHAInput(...)
            - ![picture](images/ISHAInput.png)
            - ISHAPadMessage(...)
            - ![picture](images/ISHAPadMessage.png)
            - ISHAReset(...)
            - ![picture](images/ISHAReset.png)
            - ISHAResult(...)
            - ![picture](images/ISHAResult.png)
            - pbkdf2_hmac_isha(...)
            - ![picture](images/pbkdf2_hmac_isha.png)


**Thus it makes sense to Optimize the Functions for speed with the maximum number of function calls, ideally it should Time for single function multiplied by the Number of calls but, it takes approximately 1msec to run ISHA Algorithm** <br />

### Size Analysis** 
<br />    Name	                Size  <br />
.text.hmac_isha 	        0x00000186 <br />
.text.F         	        0x000001dc <br />
.text.pbkdf2_hmac_isha	    0x00000130 <br />
.text.main   	            0x0000004c <br />
.text.time_pbkdf2_hmac_isha 0x00000154 <br />
.text.run_tests 	        0x0000006a <br />
.text.ISHAProcessMessageBlock 	0x00000152 <br />
.text.ISHAPadMessage 	    0x0000010e <br />
.text.ISHAReset	            0x00000060 <br />
.text.ISHAResult	        0x000000c0 <br />
.text.ISHAInput	            0x000000ae <br />




    