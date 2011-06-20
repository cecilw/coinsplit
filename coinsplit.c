// coinsplit.c by Cecil W.
// Uses some code from bc_key by grondilu
// And some ideas in bitcoin-import by Matt Giuca
#include <sys/types.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <db.h>
#include <string.h> 
#include <unistd.h>
#include <gmp.h>
#include <openssl/buffer.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/evp.h>

#define BUFSIZE 32768

#ifdef USE_TESTNET
#define ADDRESSVERSION 111
#define WALLET_PATH "/.bitcoin/testnet/wallet.dat"
#else
#define ADDRESSVERSION 0
#define WALLET_PATH "/.bitcoin/wallet.dat"
#endif

#if defined(_MSC_VER) || defined(__BORLANDC__)
typedef __int64  int64;
typedef unsigned __int64  uint64;
#else
typedef long long  int64;
typedef unsigned long long  uint64;
#endif

#define die(str) \
  { printf(str); return 1; }

static const char* base58chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

DB *open_wallet(char *path, u_int32_t flags){

    DB *dbp;
    int ret;

    if ((ret = db_create(&dbp, NULL, 0)) != 0) {
        fprintf(stderr, "db_create: %s\n", db_strerror(ret));
        exit (1);
    }
    if ((ret = dbp->open(
                    dbp, NULL, path, "main", DB_BTREE, flags, 0600)) != 0) {
        dbp->err(dbp, ret, "%s", path);
        printf("fail open\n");
        exit (1);
    }
    return dbp;
}

unsigned int get_size(FILE *f){
    int magic;
    unsigned char byte1=0;
    unsigned char byte2=0;
    unsigned char byte3=0;
    unsigned char byte4=0;
    unsigned int size;
    magic=fgetc(f);
    if(magic<253){
        byte1=magic;
    }
    else if(magic==253){
        byte1=fgetc(f);
        byte2=fgetc(f);
    }
    else if(magic==254){
                
        byte1=fgetc(f);
        byte2=fgetc(f);
        byte3=fgetc(f);
        byte4=fgetc(f);
    }
    else{
        exit(1);
    }
    size=((unsigned int) byte4 << 24) + ((unsigned int) byte3 << 16) |  ((unsigned int) byte2 << 8) | (unsigned int) byte1;
    return size;
}


char *get_string(FILE *f){
    unsigned int size=get_size(f);
    char *buffer=(char *) malloc(size+1);
    fread(buffer,size,1,f);
    buffer[size]=0;
    return buffer;
}

char* reverse_string(char* str)
{
    int end= strlen(str)-1;
    int start = 0;

    while( start<end )
    {
        str[start] ^= str[end];
        str[end] ^=  str[start];
        str[start]^= str[end];

        ++start;
        --end;
    }

    return str;
}

char *sha256(char *string,int length)
{
    unsigned char *digest=(unsigned char *) malloc(SHA256_DIGEST_LENGTH);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, length);
    SHA256_Final(digest, &sha256);
    return digest;
}

char *double_sha256(char *string, int length){
    unsigned char *digest1=sha256(string,length);
    unsigned char *digest2=sha256(digest1,SHA256_DIGEST_LENGTH);
    free(digest1);
    return digest2;
}



char *ripemd160(char *string,int length)
{
    unsigned char *digest=(unsigned char *) malloc(RIPEMD160_DIGEST_LENGTH);
    RIPEMD160_CTX ripe;
    RIPEMD160_Init(&ripe);
    RIPEMD160_Update(&ripe, string, length);
    RIPEMD160_Final(digest, &ripe);
    return digest;
}

char *base58_encode(char *buffer, int length){
    mpz_t bn;
    mpz_t bn2;
    mpz_t r;
    char digit;
    size_t result_size;
    char *result;
    FILE *result_stream=open_memstream(&result,&result_size);
    int i;
    mpz_init(bn);
    mpz_init(bn2);
    mpz_init(r);    
    mpz_import(bn,length,1,1,0,0,buffer);
    while(mpz_cmp_ui(bn,58)>=0){
        mpz_fdiv_qr_ui(bn2,r,bn,58);
        mpz_set(bn,bn2);
        digit=base58chars[(int) mpz_get_ui(r)];
        fputc(digit,result_stream);
    }
    digit=base58chars[(int) mpz_get_ui(bn)];
    fputc(digit,result_stream);
    for(i=0;i<length && !buffer[i];i++){
        fputc(base58chars[0],result_stream);
    }
    fclose(result_stream);
    reverse_string(result);
    return result;

}

char *public_key_to_bc_address(char *key, int length){
    char *digest1=sha256(key,length);
    char *digest2=ripemd160(digest1,SHA256_DIGEST_LENGTH);
    size_t result_size;
    char *result;
    char *b58;
    char *checksum;
    char *final=malloc(RIPEMD160_DIGEST_LENGTH+5); /* +1 byte for version, +4 bytes for checksum) */
    final[0]=ADDRESSVERSION; /* version 0 */
    memcpy(final+1,digest2,RIPEMD160_DIGEST_LENGTH);
    checksum=double_sha256(final,RIPEMD160_DIGEST_LENGTH+1);
    memcpy(&final[RIPEMD160_DIGEST_LENGTH+1],checksum,4);
    free(digest1);
    free(digest2);
    free(checksum);
    b58=base58_encode(final,RIPEMD160_DIGEST_LENGTH+5);
    free(final);
    return b58;
    
}

#define KEY_NEW(p) \
  EC_KEY *p = EC_KEY_new_by_curve_name(NID_secp256k1)

#define KEY_FREE(p) \
  EC_KEY_free(p)

void export_key(const unsigned char *key, int length){
  KEY_NEW(pkey);
  BIO *out=BIO_new(BIO_s_file());
  BIO_set_fp(out,stdout,BIO_NOCLOSE);
  if (!d2i_ECPrivateKey(&pkey, &key, length)){
    printf("failed to make key\n");
    goto finish;
  }
  PEM_write_bio_ECPrivateKey(out,pkey,NULL,NULL,0,NULL,NULL);
finish:
  KEY_FREE(pkey);
}

void encrypt_test(const unsigned char *key, int length){
  ECDSA_SIG *sig=NULL;
  const char *msg = "TEST";
  KEY_NEW(pkey);
  if (!d2i_ECPrivateKey(&pkey, &key, length)){
    printf("failed to make key\n");
    goto finish;
  }
  sig = ECDSA_do_sign(msg, strlen(msg), pkey);
  if (sig == NULL) {
    printf("failed to sign in encrypt_test\n");
    goto finish;
  }
  if (!ECDSA_do_verify(msg, strlen(msg), sig, pkey)) {
    printf("failed to verify in encrypt_test\n");
    goto finish;
  }
finish:
  ECDSA_SIG_free(sig);
  KEY_FREE(pkey);
}

typedef void (*KeyFunc)(char *, int);

struct BCKeyFind {
  char *address;
  KeyFunc func;
};

void find_key(DBT *key, DBT *value, void *data){
    struct BCKeyFind *find = (struct BCKeyFind *) data;
    FILE *key_stream=fmemopen(key->data,key->size,"r");
    FILE *value_stream=fmemopen(value->data,value->size,"r");
    char *type;
    char *b58;
    char *public_key;
    int public_key_length;

    char *private_key;
    int private_key_length;
    int found_key=0;
    type=get_string(key_stream);
    if(strcmp("key",type)==0){
        public_key_length=get_size(key_stream);
        public_key=(char *) malloc(public_key_length);
        private_key_length=get_size(value_stream);
        private_key=(char *) malloc(private_key_length);
        fread(public_key,1,public_key_length,key_stream);
        fread(private_key,1,private_key_length,value_stream);
        found_key=1;
    }
    if(found_key){
        b58=public_key_to_bc_address(public_key,public_key_length);
        if(strcmp(b58,find->address)==0){
            find->func(private_key,private_key_length);
        }
        if(strcmp("ALL",find->address)==0){
            find->func(private_key,private_key_length);
        }
        free(public_key);
        free(private_key);
        free(b58);
    }
    free(type);
    fclose(key_stream);
    fclose(value_stream);
}

void foreach_item(DB *db, void func(DBT *, DBT *,void *), void *data){
    DBC *cursor;
    DBT key, value;
    int ret;
    if ((ret = db->cursor(db, NULL, &cursor, 0)) != 0) {
        db->err(db, ret, "DB->cursor");
        exit(1);
    }
    memset(&key, 0, sizeof(key));
    memset(&value, 0, sizeof(value));
    while ((ret = cursor->get(cursor, &key, &value, DB_NEXT)) == 0){
        func(&key,&value,data);
    }
    if (ret != DB_NOTFOUND) {
        db->err(db, ret, "DBcursor->get");
        exit(1);
    }
}

inline int64 GetPerformanceCounter()
{
  int64 nCounter = 0;
  struct timeval t;
  gettimeofday(&t, NULL);
  nCounter = t.tv_sec * 1000000 + t.tv_usec;
  return nCounter;
}

void RandAddSeed()
{
  int64 nCounter = GetPerformanceCounter();
  RAND_add(&nCounter, sizeof(nCounter), 1.5);
  memset(&nCounter, 0, sizeof(nCounter));
}

void
dump_hex(FILE *out, unsigned char *buf, int len)
{
  int i;
  fprintf(out, "  ");
  for (i = 0; i < len; i++)
  {
    fprintf(out, "%02x", buf[i]);
    if (i % 30 == 29)
      fprintf(out, "\n  ");
  }
}

void
print_bc_addr(FILE *out, char *pkey, int len)
{
  char *key58 = public_key_to_bc_address(pkey + 214, 65);
  fprintf(out, "%s", key58);
  free(key58);
}

#define SRC_GENERATE 1
#define SRC_ADDRESS  2
#define SRC_WALLET   3
#define SRC_IMPORT   4

void bufxor(char *buf, char *otp, int len) {
  int i;
  for (i = 0; i < len; i++)
    buf[i] ^= otp[i]; 
}

unsigned char *write_string(unsigned char *dat, unsigned char *buf, int len) {
  if (len < 253)
    *dat++ = len;
  else
  {
    *dat++ = '\xfd';
    *dat++ = len;
    *dat++ = len >> 8;
  }

  if (len > 0)
    memcpy(dat, buf, len);
  return dat + len;
}

#define DB_KEY(kv, dv, dl) \
  memset(&kv, 0, sizeof(DBT)); \
  kv.data = dv; \
  kv.size = dl; \
  kv.ulen = 1024

DB *import_wallet;
void import_each_key(char *buf, int len) {
  DBT kt, vt;
  unsigned char *c = NULL;
  unsigned char *kdat = (unsigned char *)malloc(1024);
  unsigned char *vdat = (unsigned char *)malloc(1024);
  char *key58 = public_key_to_bc_address(buf + 214, 65);

  // Add public/private key
  memset(kdat, 0, 1024);
  c = write_string(kdat, "key", 3);
  c = write_string(c, buf + (len - 65), 65);
  DB_KEY(kt, kdat, c - kdat);

  memset(vdat, 0, 1024);
  c = write_string(vdat, buf, len);
  DB_KEY(vt, vdat, c - vdat);

  import_wallet->put(import_wallet, NULL, &kt, &vt, 0);

  // Add to address list
  memset(kdat, 0, 1024);
  c = write_string(kdat, "name", 4);
  c = write_string(c, key58, 34);
  DB_KEY(kt, kdat, c - kdat);
  memset(vdat, 0, 1024);
  c = write_string(vdat, "", 0);
  DB_KEY(vt, vdat, c - vdat);

  import_wallet->put(import_wallet, NULL, &kt, &vt, 0);

  free(key58);
  free(kdat);
  free(vdat);
}

FILE *read1, *read2, *save1, *save2;
void print_each_key(char *buf, int len) {
  print_bc_addr(save1, buf, len);
  fprintf(save1, "\n");
  dump_hex(save1, buf, len);
  fprintf(save1, "\n---\n", len);
}

void print_split_keys(char *buf, int len) {
  unsigned char *otp = (unsigned char *)OPENSSL_malloc(len);
  RAND_bytes(otp, len);

  print_bc_addr(save1, buf, len);
  fprintf(save1, " (B)\n");
  dump_hex(save1, otp, len);
  fprintf(save1, "\n---\n", len);
  print_bc_addr(save2, buf, len);
  fprintf(save2, " (S)\n");
  bufxor(buf, otp, len);
  dump_hex(save2, buf, len);
  fprintf(save2, "\n---\n", len);

  RAND_bytes(otp, len); // garble
  OPENSSL_free(otp);
}

int load_key(FILE *in, char *addr, char *ptr) {
  int b, i, bi = 0, bb = 0;
  unsigned char buf[BUFSIZE];
  fscanf(in, "%s\n", addr);
  while (1)
  {
    int len = fscanf(in, "%s\n", buf);
    if (buf[0] == '(')
      continue;

    if (!strcmp(buf, "---") || len <= 0)
      break;

    bi = 0;
    while (buf[bi] != '\n' && buf[bi] != '\0')
    {
      b = -1;
      if (buf[bi] >= '0' && buf[bi] <= '9')
        b = buf[bi] - '0';
      if (buf[bi] >= 'a' && buf[bi] <= 'f')
        b = (buf[bi] - 'a') + 0xA;
      if (buf[bi] >= 'A' && buf[bi] <= 'F')
        b = (buf[bi] - 'A') + 0xA;

      if (b >= 0)
        ptr[bb++ / 2] |= b << (bi % 2 == 0 ? 4 : 0);
      bi++;
    }
  }
  ptr[bb] = '\0';
  return bb / 2;
}

int
usage() {
  printf("coinsplit [wallet.dat] [--generate|--address XXX|--wallet|--import file1 file2] [--split] [keyfile1] [keyfile2]\n");
  printf("Generates offline Bitcoin addresses and can split them into halves and import them into wallet.dat files.\n\n");
#ifdef USE_TESTNET
  printf("** THIS BUILD GENERATES ONLY TESTNET ADDRESSES (which start with an 'm'). **\n\n");
#else
  printf("** WARNING: THIS IS BETA SOFTWARE. EXPERIMENT WITH SMALL AMOUNTS OF BITCOINS BEFORE JUMPING IN! **\n\n");
#endif
  printf("Examples:\n");
  printf("\tcoinsplit --generate new.key\n");
  printf("\t\tGenerates a new offline key and stores it in new.key.\n");
  printf("\tcoinsplit --generate --split new.pt1 new.pt2\n");
  printf("\t\tGenerates a new key and splits it into two halves.\n");
  printf("\tcoinsplit wallet.dat --address 13zuMXTyQpCxL2GJZ6pdoVF3RzZiKm7XPu --split old.pt1 old.pt2\n");
  printf("\t\tSplits an address from the wallet into two halves.\n");
  printf("\tcoinsplit wallet.dat --wallet --split old.pt1 old.pt2\n");
  printf("\t\tSplits all addresses from the wallet into two halves.\n");
  printf("\tcoinsplit wallet.dat --import old.key\n");
  printf("\t\tImports the addresses in old.key into the wallet.\n");
  printf("\tcoinsplit wallet.dat --import old.pt1 old.pt2\n");
  printf("\t\tImports the addresses in the split keys into the wallet.\n");
  printf("\tcoinsplit wallet.dat --import old.pt1 old.pt2 old.key\n");
  printf("\t\tRejoins two split keys into a single key.\n");
  printf("\tcoinsplit --generate --split 1>mail 2>curl\n");
  printf("\t\tGenerates a new key and sends the two halves off.\n");
  printf("\tcoinsplit --generate | coinsplit --import\n");
  printf("\t\tGenerate a new key and save the key in the wallet.\n");
  return 0;
}

int
main(int argc, char *argv[]) {
  int i, len, source = 0;
  char wallet_path[PATH_MAX + 1];
  unsigned char *ptr = NULL, *pptr = NULL, *addr, *addr_all = "ALL";
  KeyFunc func = print_each_key;

  read1 = read2 = stdin;
  save1 = (source == SRC_IMPORT ? stdin : stdout);
  save2 = stderr;

  if (argc < 2)
    return usage();

  ENGINE_load_builtin_engines();
  CRYPTO_malloc_init();

  i = 1;
  if (strncmp(argv[i], "--", 2))
    strcpy(wallet_path, argv[i++]);
  else
    sprintf(wallet_path, "%s%s", getenv("HOME"), WALLET_PATH);

  if (!strcmp(argv[i], "--generate"))
    source = SRC_GENERATE;
  else if (!strcmp(argv[i], "--address"))
    source = SRC_ADDRESS;
  else if (!strcmp(argv[i], "--wallet"))
    source = SRC_WALLET;
  else if (!strcmp(argv[i], "--import"))
    source = SRC_IMPORT;
  else
    return usage();

  i++;
  if (source == SRC_ADDRESS)
    if (argc > i)
      addr = argv[i++];
    else
      return usage();

  if (argc > i && !strcmp(argv[i], "--split"))
  {
    func = print_split_keys;
    i++;
  }

  if (source == SRC_IMPORT)
  {
    func = import_each_key;

    if (argc > i && source == SRC_IMPORT)
    {
      read1 = fopen(argv[i], "rb");
      i++;

      if (argc > i && strncmp(argv[i], "--", 2))
      {
        read2 = fopen(argv[i], "rb");
        i++;
      }
    }
  }

  if (argc > i)
  {
    save1 = fopen(argv[i], "ab");
    i++;
  }

  if (argc > i)
  {
    save2 = fopen(argv[i], "ab");
    i++;
  }

  if (source == SRC_GENERATE)
  {
    KEY_NEW(pkey);
    // RandAddSeed();
    if (!pkey)
      die("Problem creating pkey object.\n");

    if (!EC_KEY_generate_key(pkey))
      die("Problem generating key.\n");

    len = i2d_ECPrivateKey(pkey, NULL);
    pptr = ptr = (unsigned char *)OPENSSL_malloc(len + 1);
    len = i2d_ECPrivateKey(pkey, &pptr);
    KEY_FREE(pkey);

    encrypt_test(ptr, len);
    func(ptr, len);
    RAND_bytes(ptr, len); // garble
    OPENSSL_free(ptr);
  }
  else if (source == SRC_ADDRESS || source == SRC_WALLET)
  {
    struct BCKeyFind find;
    DB *wallet = open_wallet(wallet_path, DB_RDONLY);

    find.address = (source == SRC_WALLET ? addr_all : addr);
    find.func = func;
    foreach_item(wallet, find_key, &find);

    wallet->close(wallet, 0);
  }
  else if (source == SRC_IMPORT)
  {
    import_wallet = NULL;
    if (save1 == stdout)
      import_wallet = open_wallet(wallet_path, 0);
    else
      func = print_each_key;

    while (1)
    {
      unsigned char *addr1 = (unsigned char *)calloc(512, sizeof(char));
      ptr = (unsigned char *)calloc(512, sizeof(char));
      len = load_key(read1, addr1, ptr);
      if (!len)
        break;

      if (read2 != stdin)
      {
        unsigned char *addr2 = (unsigned char *)calloc(512, sizeof(char));
        unsigned char *otp = (unsigned char *)calloc(512, sizeof(char));
        int olen = load_key(read2, addr2, otp);

        if (len != olen)
        {
          printf("keys differ in size.\n");
          goto finish;
        }

        if (strcmp(addr1, addr2))
        {
          printf("two unmatched keys found:\n\t- %s\n\t- %s\n", addr1, addr2);
          goto finish;
        }

        bufxor(otp, ptr, len);
        free(ptr);

        ptr = otp;
      }

      func(ptr, len);
      RAND_bytes(ptr, len);
      free(ptr);
    }

    if (save1 == stdout)
      import_wallet->close(import_wallet, 0);
  }

finish:
  if (save1 != stdout)
    fclose(save1);
  if (save2 != stderr)
    fclose(save2);
  if (read1 != stdin)
    fclose(read1);

  return 0;
}
