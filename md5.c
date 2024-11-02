#include "headerfiles.h"
#include <stdio.h>

//constants use to shift data in different md5 transformation rounds
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

//predefing functions for static helper function
static void md5_transformation PROTO_LIST ((UINT4 [4], unsigned char [64]));
static void encode PROTO_LIST((unsigned char *, UINT4 *, unsigned int));
static void decode PROTO_LIST((UINT4 *, unsigned char *, unsigned int));
static void MD5_memcpy PROTO_LIST ((POINTER, POINTER, unsigned int));
static void MD5_memset PROTO_LIST ((POINTER, int, unsigned int));

//this is 64 byte array used for padding the input data to ensures its length bacame mutiple of 512 bits
static unsigned char padding_array[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

// basic bitwise  operations on input data to mix the bits
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

// this will rotate bits in x to the left by n positions
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

//a,b,c,d represents parts of md5 state, initialised to some specific constants
// x is a 32 bits word from current block of data being processed
// s is the constants defined above for shifting bits 
//ac is a constant for each specific operation
// each of the functions FF,GG,HH,II introduces different bitwise interaction F,G,H,I defined above
//for 1st round
#define FF(a, b, c, d, x, s, ac) { \
 (a) += F ((b), (c), (d)) + (x) + (UINT_4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
// for second round
#define GG(a, b, c, d, x, s, ac) { \
 (a) += G ((b), (c), (d)) + (x) + (UINT_4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
//for third round
#define HH(a, b, c, d, x, s, ac) { \
 (a) += H ((b), (c), (d)) + (x) + (UINT_4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
//for fourth  round
#define II(a, b, c, d, x, s, ac) { \
 (a) += I ((b), (c), (d)) + (x) + (UINT_4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }


//it will print the hash stored in digest
int MD5Print(unsigned char *digest)
{
    int i;
    if (!digest) {
        printf("<empty hash>\n");
        return -1;
    }
     for(i = 0; i< MD5_DIGEST_LENGTH; i++)
        printf("%02x", digest[i]);
     printf("\n");
     return 0;
}


int MD5One(unsigned char *data, unsigned int dataLen, unsigned char *digest)
{
    //unsigned char md[MD5_DIGEST_LENGTH];
    //int i;
    if (!digest || !data)
        return -1;
     MD5_CTX c;
     MD5Init(&c);
     MD5Update(&c, data, dataLen);
     MD5Final(digest, &c);
     return 0;
}

// it will sets up the MD5 context with initial values 
void MD5Init (context)
MD5_CTX *context;                                       
{ 
  //initialises count array to zero preparing it to count the number of bits processed
  context->count[0] = context->count[1] = 0;
  // these constants are the initial values of MD5 hash
  context->state[0] = 0x67452301;
  context->state[1] = 0xefcdab89;
  context->state[2] = 0x98badcfe;
  context->state[3] = 0x10325476;
}

//this function takes data and process it in 64-byte chunks 
//left data is stored in buffer for the next call
//inputlen is the length of input in bytes 
//*input is the pointer to data added to hash
void MD5Update (MD5_CTX *context,unsigned char *input,unsigned int inputLen)                  
{
  unsigned int i, index, partLen;
  //index where the new data will start in the buffer
  index = (unsigned int)((context->count[0] >> 3) & 0x3F);

  //updates the count of bits of input data 
  //checks if context->count[0] overflows after adding the bit_length of input
  if ((context->count[0] += ((UINT_4)inputLen << 3))< ((UINT_4)inputLen << 3))
 //if overflow is there count[1] is increased
 context->count[1]++;
  context->count[1] += ((UINT_4)inputLen >> 29);
  //bytes needed for current block
  partLen = 64 - index;
//if input has enough byte to  brak in 64 bytes chunks
if (inputLen >= partLen) {
 //copies data from one loctaion to another
 MD5_memcpy((POINTER)&context->buffer[index], (POINTER)input, partLen);
 //it will process the chunk 
 md5_transformation (context->state, context->buffer);
 
 //loop through input in 64- bytes blocks after filling context->buffer
 for (i = partLen; i + 63 < inputLen; i += 64)
   md5_transformation (context->state, &input[i]);
 //resets index if buffer was filled and processed
 index = 0;
}
//if inptlen is less than partlen
else
 i = 0;
// copies any remaining input data to the buffer for future processing
MD5_memcpy((POINTER)&context->buffer[index], (POINTER)&input[i],inputLen-i);
}

//stores final hash in digest 
void MD5Final (digest, context)
unsigned char digest[16];      //array digest                   
MD5_CTX *context;              // pointer to md5 context containing current hash        
{ 
  unsigned char bits[8];
  unsigned int index, padLen;

  //it converts total message to an 8 byte array "bits"
  encode (bits, context->count, 8);

  //index computes current length of the message in bytes in buffer
  index = (unsigned int)((context->count[0] >> 3) & 0x3f);
  //determine how much padding is needed 
  padLen = (index < 56) ? (56 - index) : (120 - index);
  //adds the required padding bytes to reach correct length
  MD5Update (context, padding_array, padLen);

  //appends the original bit length of message to the buffer
  MD5Update (context, bits, 8);
  //converts the final state of context->state into 16 byte digest producing MD% hash
  encode (digest, context->state, 16);

  //function to clear 0 from memory in context to prvent data lingering 
  MD5_memset ((POINTER)context, 0, sizeof (*context));
}

//performs core transformations
static void md5_transformation (state, block)
UINT_4 state[4];
unsigned char block[64];
{
  UINT_4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];

  decode (x, block, 64);

  /* Round 1 */
  FF (a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
  FF (d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
  FF (c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
  FF (b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
  FF (a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
  FF (d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
  FF (c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
  FF (b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
  FF (a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
  FF (d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
  FF (c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
  FF (b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
  FF (a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
  FF (d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
  FF (c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
  FF (b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

 /* Round 2 */
  GG (a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
  GG (d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
  GG (c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
  GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
  GG (a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
  GG (d, a, b, c, x[10], S22,  0x2441453); /* 22 */
  GG (c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
  GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
  GG (a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
  GG (d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
  GG (c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */
  GG (b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
  GG (a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
  GG (d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
  GG (c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
  GG (b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

  /* Round 3 */
  HH (a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
  HH (d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
  HH (c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
  HH (b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
  HH (a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
  HH (d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
  HH (c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
  HH (b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
  HH (a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
  HH (d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
  HH (c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
  HH (b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
  HH (a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
  HH (d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
  HH (c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
  HH (b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */

  /* Round 4 */
  II (a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
  II (d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
  II (c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
  II (b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
  II (a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
  II (d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
  II (c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
  II (b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
  II (a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
  II (d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
  II (c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
  II (b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
  II (a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
  II (d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
  II (c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
  II (b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;

  MD5_memset ((POINTER)x, 0, sizeof (x));
}

//function will converts an array of 32 bit unsigned integers into a byte array (output)
static void encode (output, input, len)
unsigned char *output;
UINT_4 *input;
unsigned int len;
{
  unsigned int i, j;

  for (i = 0, j = 0; j < len; i++, j += 4) {
 output[j] = (unsigned char)(input[i] & 0xff);
 output[j+1] = (unsigned char)((input[i] >> 8) & 0xff);
 output[j+2] = (unsigned char)((input[i] >> 16) & 0xff);
 output[j+3] = (unsigned char)((input[i] >> 24) & 0xff);
  }
}

//it will reverse the process of encode taking the output from encode as input 
//it will covert byte array to 32 bit unsigned integers
static void decode (output, input, len)
UINT_4 *output;
unsigned char *input;
unsigned int len;
{
  unsigned int i, j;

  for (i = 0, j = 0; j < len; i++, j += 4)
 output[i] = ((UINT_4)input[j]) | (((UINT_4)input[j+1]) << 8) |
   (((UINT_4)input[j+2]) << 16) | (((UINT_4)input[j+3]) << 24);
}


//copies a specificed number of bytes from input to output
static void MD5_memcpy (output, input, len)
POINTER output;
POINTER input;
unsigned int len;
{
  unsigned int i;

  for (i = 0; i < len; i++)
output[i] = input[i];
}

//sets a block of memory to a specified value
static void MD5_memset (output, value, len)
POINTER output;
int value;
unsigned int len;
{
  unsigned int i;

  for (i = 0; i < len; i++)
 ((char *)output)[i] = (char)value;
}