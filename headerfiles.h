#ifndef PROTOTYPES
#define PROTOTYPES 0
#endif

//POINTER defines a generic byte pointer type,it can point to raw byte data
typedef unsigned char *POINTER;

//UINT_2 defines a 16 bits word 
typedef unsigned short int UINT_2;

//UINT_4 defines a 32 bits word 
typedef unsigned long int UINT_4;

//if prototype is non-zero  that means newer compilers do no need of proto_list
#if PROTOTYPES
#define PROTO_LIST(list) list
// if prototype is 0 then it is older compilers it replaces list with empty ()
#else
#define PROTO_LIST(list) ()
#endif
// the result of md5 hashing is a 16 byte (128 bits) in length
#define MD5_DIGEST_LENGTH 16

//MD5_CTX structure holds ongoing computations 
typedef struct {
  //state[4] is array of (a,b,c,d) 32 bits used to store state of md5 hash
  UINT_4 state[4];                                   
  //count[2] track the number of bits processed so far 
  UINT_4 count[2]; 
  //buffer[64] stores input data until it has 64 bits less than multiple of 512     
  unsigned char buffer[64];                        
} MD5_CTX;
//prints md5 hash in hexadecimal string 
int MD5Print(unsigned char *digest);
//if data contains a single block of data then it will produce hash directly
int MD5One(unsigned char *data, unsigned int dataLen, unsigned char *md5str);
//initialises md5_ctx to prepare for haashing
void MD5Init PROTO_LIST ((MD5_CTX *));
// process data in chunks and update state of md5_ctx
void MD5Update PROTO_LIST ((MD5_CTX *, unsigned char *, unsigned int));
//completes md5 calculations 
void MD5Final PROTO_LIST ((unsigned char [16], MD5_CTX *));