#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <openssl/sha.h>

/* Checking options */
#define CHECK_MD5SUM        0000001
#define CHECK_PERM          0000002
#define CHECK_SIZE          0000004
#define CHECK_OWNER         0000010
#define CHECK_GROUP         0000020
#define CHECK_SHA1SUM       0000040

#define CHECK_REALTIME      0000100
#define CHECK_SEECHANGES    0000200
#define CHECK_SHA256SUM     0000400
#define CHECK_GENERIC       0001000
#define CHECK_NORECURSE     0002000

#define PATH_MAX            4096
#define OS_BINARY           0
#define OS_MAXSTR           1024
#define SHA_DIGEST_LENGTH   20
#define SHA_LBLOCK          16

typedef char os_md5[33];
typedef char os_sha1[65];

/* Node structure */
typedef struct _OSHashNode {
    struct _OSHashNode *next;

    char *key;
    void *data;
} OSHashNode;

typedef struct _OSHash {
    unsigned int rows;
    unsigned int initial_seed;
    unsigned int constant;

    OSHashNode **table;
} OSHash;

typedef struct _config {
    OSHash *fp;
    char *prefilter_cmd;
    char **nodiff;
    int create_db_flag; 
} syscheck_config;

syscheck_config syscheck;

int __counter = 0;

typedef unsigned int uint32;
struct MD5Context {
    uint32 buf[4];
    uint32 bits[2];
    union {
        unsigned char in[64];
        uint32 in32[16];
    };
};
typedef struct MD5Context MD5_CTX;

#define MD5STEP(f, w, x, y, z, data, s) \
    ( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

//#define os_strdup(x,y) ((y = strdup(x)))?(void)1:ErrorExit(MEM_ERROR, __local_name, errno, strerror(errno))
#define os_strdup(x,y) ((y = strdup(x)))?(void)1:0

int read_dir(char *);

int fim_detection_msg(char *msg)
{
    printf("Scan info =[ %s.]\n", msg);
    return (0);
}

void byteReverse(unsigned char *buf, unsigned longs)
{
    uint32 t;
    do {
        t = (uint32) ((unsigned) buf[3] << 8 | buf[2]) << 16 |
            ((unsigned) buf[1] << 8 | buf[0]);
        *(uint32 *) buf = t;
        buf += 4;
    } while (--longs);
}
void MD5Transform(uint32 buf[4], uint32 in[16])
{
    register uint32 a, b, c, d;

    a = buf[0];
    b = buf[1];
    c = buf[2];
    d = buf[3];

    MD5STEP(F1, a, b, c, d, in[0] + 0xd76aa478, 7);
    MD5STEP(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
    MD5STEP(F1, c, d, a, b, in[2] + 0x242070db, 17);
    MD5STEP(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
    MD5STEP(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);
    MD5STEP(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
    MD5STEP(F1, c, d, a, b, in[6] + 0xa8304613, 17);
    MD5STEP(F1, b, c, d, a, in[7] + 0xfd469501, 22);
    MD5STEP(F1, a, b, c, d, in[8] + 0x698098d8, 7);
    MD5STEP(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
    MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
    MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
    MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7);
    MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
    MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
    MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

    MD5STEP(F2, a, b, c, d, in[1] + 0xf61e2562, 5);
    MD5STEP(F2, d, a, b, c, in[6] + 0xc040b340, 9);
    MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
    MD5STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
    MD5STEP(F2, a, b, c, d, in[5] + 0xd62f105d, 5);
    MD5STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
    MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
    MD5STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
    MD5STEP(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);
    MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
    MD5STEP(F2, c, d, a, b, in[3] + 0xf4d50d87, 14);
    MD5STEP(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
    MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
    MD5STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
    MD5STEP(F2, c, d, a, b, in[7] + 0x676f02d9, 14);
    MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

    MD5STEP(F3, a, b, c, d, in[5] + 0xfffa3942, 4);
    MD5STEP(F3, d, a, b, c, in[8] + 0x8771f681, 11);
    MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
    MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
    MD5STEP(F3, a, b, c, d, in[1] + 0xa4beea44, 4);
    MD5STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
    MD5STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
    MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
    MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
    MD5STEP(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
    MD5STEP(F3, c, d, a, b, in[3] + 0xd4ef3085, 16);
    MD5STEP(F3, b, c, d, a, in[6] + 0x04881d05, 23);
    MD5STEP(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);
    MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
    MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
    MD5STEP(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);

    MD5STEP(F4, a, b, c, d, in[0] + 0xf4292244, 6);
    MD5STEP(F4, d, a, b, c, in[7] + 0x432aff97, 10);
    MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
    MD5STEP(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
    MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
    MD5STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
    MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
    MD5STEP(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
    MD5STEP(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
    MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
    MD5STEP(F4, c, d, a, b, in[6] + 0xa3014314, 15);
    MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
    MD5STEP(F4, a, b, c, d, in[4] + 0xf7537e82, 6);
    MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
    MD5STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
    MD5STEP(F4, b, c, d, a, in[9] + 0xeb86d391, 21);

    buf[0] += a;
    buf[1] += b;
    buf[2] += c;
    buf[3] += d;
}

void MD5Init(struct MD5Context *ctx)
{
    ctx->buf[0] = 0x67452301;
    ctx->buf[1] = 0xefcdab89;
    ctx->buf[2] = 0x98badcfe;
    ctx->buf[3] = 0x10325476;

    ctx->bits[0] = 0;
    ctx->bits[1] = 0;
}
/* Update context to reflect the concatenation of another buffer full of bytes */
void MD5Update(struct MD5Context *ctx, unsigned char *buf, unsigned len)
{
    uint32 t;

    /* Update bitcount */
    t = ctx->bits[0];
    if ((ctx->bits[0] = t + ((uint32) len << 3)) < t) {
        ctx->bits[1]++;    /* Carry from low to high */
    }
    ctx->bits[1] += len >> 29;

    t = (t >> 3) & 0x3f;    /* Bytes already in shsInfo->data */

    /* Handle any leading odd-sized chunks */
    if (t) {
        unsigned char *p = (unsigned char *) ctx->in + t;

        t = 64 - t;
        if (len < t) {
            memcpy(p, buf, len);
            return;
        }
        memcpy(p, buf, t);
        byteReverse(ctx->in, 16);
        MD5Transform(ctx->buf, (uint32 *) ctx->in);
        buf += t;
        len -= t;
    }

    /* Process data in 64-byte chunks */
    while (len >= 64) {
        memcpy(ctx->in, buf, 64);
        byteReverse(ctx->in, 16);
        MD5Transform(ctx->buf, (uint32 *) ctx->in);
        buf += 64;
        len -= 64;
    }

    /* Handle any remaining bytes of data */
    memcpy(ctx->in, buf, len);
}

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
void MD5Final(unsigned char digest[16], struct MD5Context *ctx)
{
    unsigned count;
    unsigned char *p;

    /* Compute number of bytes mod 64 */
    count = (ctx->bits[0] >> 3) & 0x3F;

    /* Set the first char of padding to 0x80. This is safe since there is
     * always at least one byte free
     */
    p = ctx->in + count;
    *p++ = 0x80;

    /* Bytes of padding needed to make 64 bytes */
    count = 64 - 1 - count;

    /* Pad out to 56 mod 64 */
    if (count < 8) {
        /* Two lots of padding:  Pad the first block to 64 bytes */
        memset(p, 0, count);
        byteReverse(ctx->in, 16);
        MD5Transform(ctx->buf, (uint32 *) ctx->in);

        /* Now fill the next block with 56 bytes */
        memset(ctx->in, 0, 56);
    } else {
        /* Pad block to 56 bytes */
        memset(p, 0, count - 8);
    }
    byteReverse(ctx->in, 14);

    /* Append length in bits and transform */
    ctx->in32[14] = ctx->bits[0];
    ctx->in32[15] = ctx->bits[1];

    MD5Transform(ctx->buf, (uint32 *) ctx->in);
    byteReverse((unsigned char *) ctx->buf, 4);
    memcpy(digest, ctx->buf, 16);
    memset(ctx, 0, sizeof(*ctx));   /* In case it's sensitive */
}

// int SHA1_Init(SHA_CTX *c);
// int SHA1_Update(SHA_CTX *c, const void *data, size_t len);
// int SHA1_Final(unsigned char *md, SHA_CTX *c);

int OS_MD5_SHA1_File(char *fname, char *prefilter_cmd, os_md5 md5output, os_sha1 sha1output, int mode)
{
    size_t n;
    FILE *fp;
    unsigned char buf[2048 + 2];
    unsigned char sha1_digest[SHA_DIGEST_LENGTH];
    unsigned char md5_digest[16];

    SHA_CTX sha1_ctx;
    MD5_CTX md5_ctx;

    /* Clear the memory */
    md5output[0] = '\0';
    sha1output[0] = '\0';
    buf[2048 + 1] = '\0';

    /* Use prefilter_cmd if set */
    if (prefilter_cmd == NULL) {
        fp = fopen(fname, mode == OS_BINARY ? "rb" : "r");
        if (!fp) {
            return (-1);
        }
    } else {
        char cmd[OS_MAXSTR];
        size_t target_length = strlen(prefilter_cmd) + 1 + strlen(fname);
        int res = snprintf(cmd, sizeof(cmd), "%s %s", prefilter_cmd, fname);
        if (res < 0 || (unsigned int)res != target_length) {
            return (-1);
        }
        fp = popen(cmd, "r");
        if (!fp) {
            return (-1);
        }
    }

    /* Initialize both hashes */
    MD5Init(&md5_ctx);
    SHA1_Init(&sha1_ctx);

    // /* Update for each one */
    while ((n = fread(buf, 1, 2048, fp)) > 0) {
        buf[n] = '\0';
        SHA1_Update(&sha1_ctx, buf, n);
        MD5Update(&md5_ctx, buf, (unsigned)n);
    }

    SHA1_Final(&(sha1_digest[0]), &sha1_ctx);
    MD5Final(md5_digest, &md5_ctx);

    /* Set output for MD5 */
    for (n = 0; n < 16; n++) {
        snprintf(md5output, 3, "%02x", md5_digest[n]);
        md5output += 2;
    }

    /* Set output for SHA-1 */
    for (n = 0; n < SHA_DIGEST_LENGTH; n++) {
        snprintf(sha1output, 3, "%02x", sha1_digest[n]);
        sha1output += 2;
    }

    /* Close it */
    if (prefilter_cmd == NULL) {
        fclose(fp);
    } else {
        pclose(fp);
    }

    return (0);
}

unsigned int _os_genhash(OSHash *self, char *key)
{
    unsigned int hash_key = self->initial_seed;

    /* What we have here is a simple polynomial hash.
     * x0 * a^k-1 .. xk * a^k-k +1
     */
    while (*key) {
        hash_key *= self->constant;
        hash_key += (unsigned int) * key;
        key++;
    }

    return (hash_key);
}

void *OSHash_Get(OSHash *self, char *key)
{
    unsigned int hash_key;
    unsigned int index;
    const OSHashNode *curr_node;

    /* Generate hash of the message */
    hash_key = _os_genhash(self, key);

    /* Get array index */
    index = hash_key % self->rows;

    /* Get entry */
    curr_node = self->table[index];
    while (curr_node != NULL) {
        /* We may have collisions, so double check with strcmp */
        if (curr_node->key != NULL && strcmp(curr_node->key, key) == 0) {

            return (curr_node->data);
        }

        curr_node = curr_node->next;
    }

    return (NULL);
}

int OSHash_Add(OSHash *self, char *key, void *data)
{
    unsigned int hash_key;
    unsigned int index;
    OSHashNode *curr_node;
    OSHashNode *new_node;

    /* Generate hash of the message */
    hash_key = _os_genhash(self, key);

    /* Get array index */
    index = hash_key % self->rows;

    /* Check for duplicated entries in the index */
    curr_node = self->table[index];
    while (curr_node) {
        /* Checking for duplicated key -- not adding */
        if (strcmp(curr_node->key, key) == 0) {
            /* Not adding */
            return (1);
        }
        curr_node = curr_node->next;
    }

    /* Create new node */
    new_node = (OSHashNode *) calloc(1, sizeof(OSHashNode));
    if (!new_node) {
        return (0);
    }
    new_node->next = NULL;
    new_node->data = data;
    new_node->key = strdup(key);
    if ( new_node->key == NULL ) {
        free(new_node);
        //debug1("hash_op: DEBUG: strdup() failed!");
        return (0);
    }

    /* Add to table */
    if (!self->table[index]) {
        self->table[index] = new_node;
    }
    /* If there is duplicated, add to the beginning */
    else {
        new_node->next = self->table[index];
        self->table[index] = new_node;
    }

    return (2);
}

/* Return a pointer to a hash node if found, that hash node is removed from the table */
void *OSHash_Delete(OSHash *self, char *key)
{
    OSHashNode *curr_node;
    OSHashNode *prev_node = 0;
    unsigned int hash_key;
    unsigned int index;
    void *data;

    /* Generate hash of the message */
    hash_key = _os_genhash(self, key);

    /* Get array index */
    index = hash_key % self->rows;

    curr_node = self->table[index];
    while ( curr_node != NULL ) {
        if (strcmp(curr_node->key, key) == 0) {
            if ( prev_node == NULL ) {
                self->table[index] = curr_node->next;
            } else {
                prev_node->next = curr_node->next;
            }
            free(curr_node->key);
            data = curr_node->data;
            free(curr_node);
            return data;
        }
        prev_node = curr_node;
        curr_node = curr_node->next;
    }

    return NULL;
}

unsigned int os_getprime(unsigned int val)
{
    unsigned int i;
    unsigned int max_i;

    /* Value can't be even */
    if ((val % 2) == 0) {
        val++;
    }

    do {
        /* We just need to check odd numbers up until half
         * the size of the provided value
         */
        i = 3;
        max_i = val / 2;
        while (i <= max_i) {
            /* Not prime */
            if ((val % i) == 0) {
                break;
            }
            i += 2;
        }

        /* Prime */
        if (i >= max_i) {
            return (val);
        }
    } while (val += 2);

    return (0);
}

int OSHash_Update(OSHash *self, char *key, void *data)
{
    unsigned int hash_key;
    unsigned int index;
    OSHashNode *curr_node;

    /* Generate hash of the message */
    hash_key = _os_genhash(self, key);

    /* Get array index */
    index = hash_key % self->rows;

    /* Check for duplicated entries in the index */
    curr_node = self->table[index];
    while (curr_node) {
        /* Checking for duplicated key -- not adding */
        if (strcmp(curr_node->key, key) == 0) {
            curr_node->data = data;
            return (1);
        }
        curr_node = curr_node->next;
    }
    return (0);
}

OSHash *OSHash_Create()
{
    unsigned int i = 0;
    OSHash *self;

    /* Allocate memory for the hash */
    self = (OSHash *) calloc(1, sizeof(OSHash));
    if (!self) {
        return (NULL);
    }

    /* Set default row size */
    self->rows = os_getprime(1024);
    if (self->rows == 0) {
        free(self);
        return (NULL);
    }

    /* Create hashing table */
    self->table = (OSHashNode **)calloc(self->rows + 1, sizeof(OSHashNode *));
    if (!self->table) {
        free(self);
        return (NULL);
    }

    /* Zero our tables */
    for (i = 0; i <= self->rows; i++) {
        self->table[i] = NULL;
    }

    /* Get seed */
    srandom((unsigned int)nice(0));
    self->initial_seed = os_getprime((unsigned)random() % self->rows);
    self->constant = os_getprime((unsigned)random() % self->rows);

    return (self);
}

int IsDir(char *file)
{
    struct stat file_status;
    if (stat(file, &file_status) < 0) {
        return (-1);
    }
    if (S_ISDIR(file_status.st_mode)) {
        return (0);
    }
    return (-1);
}

time_t file_dateofchange(char *file)
{
    struct stat file_status;

    if (stat(file, &file_status) < 0) {
        return (-1);
    }

    return (file_status.st_mtime);
}

int OS_MD5_File(char *fname, os_md5 output, int mode)
{
    FILE *fp;
    MD5_CTX ctx;
    unsigned char buf[1024 + 1];
    unsigned char digest[16];
    size_t n;

    memset(output, 0, 33);
    buf[1024] = '\0';

    fp = fopen(fname, mode == OS_BINARY ? "rb" : "r");
    if (!fp) {
        return (-1);
    }

    MD5Init(&ctx);
    while ((n = fread(buf, 1, sizeof(buf) - 1, fp)) > 0) {
        buf[n] = '\0';
        MD5Update(&ctx, buf, (unsigned)n);
    }

    MD5Final(digest, &ctx);

    for (n = 0; n < 16; n++) {
        snprintf(output, 3, "%02x", digest[n]);
        output += 2;
    }

    fclose(fp);

    return (0);
}

char *substring(char *string, int position, int length)
{
   char *p;
   int c;
 
   p = malloc(length+1);
   
   if (p == NULL)
   {
      printf("Unable to allocate memory.\n");
      exit(1);
   }
 
   for (c = 0; c < length; c++)
   {
      *(p+c) = *(string+position-1);      
      string++;  
   }
 
   *(p+c) = '\0';
 
   return p;
}

void diff_check_func(char *file_name, char *old_checksum, char *new_checksum)
{
    //printf("file name ='%s', \nold = '%s', \nnew = '%s'\n", file_name, old_checksum, new_checksum);
    if(strcmp(old_checksum, new_checksum) != 0)
    {
        char *old_info[7] = {};
        char *new_info[7] = {};

        int i, j = 0;
        int start_pos = 1;
        for(i = 0; i < strlen(old_checksum); i++)
        {
            if(old_checksum[i] == ':')
            {
                old_info[j] = substring(old_checksum, start_pos, i - start_pos + 1);
                start_pos = i + 2;
                j++;
            }
        }

        start_pos = 1; j = 0;
        for(i = 0; i < strlen(new_checksum); i++)
        {
            if(new_checksum[i] == ':')
            {
                new_info[j] = substring(new_checksum, start_pos, i - start_pos + 1);
                start_pos = i + 2;
                j++;
            }
        }

        // Print different information.
        printf("***** '%s' file has changed *****\n", file_name);
        if(strcmp(old_info[0], new_info[0]) != 0)
        {
            printf("* old size = '%s'\n", old_info[0]);
            printf("* new size = '%s'\n", new_info[0]);
        }
        if(strcmp(old_info[1], new_info[1]) != 0)
        {
            printf("* old permission = '%s'\n", old_info[1]);
            printf("* new permission = '%s'\n", new_info[1]);
        }
        if(strcmp(old_info[2], new_info[2]) != 0)
        {
            printf("* old uid = '%s'\n", old_info[2]);
            printf("* new uid = '%s'\n", new_info[2]);
        }
        if(strcmp(old_info[3], new_info[3]) != 0)
        {
            printf("* old gid = '%s'\n", old_info[3]);
            printf("* new gid = '%s'\n", new_info[3]);
        }
        if(strcmp(old_info[4], new_info[4]) != 0)
        {
            printf("* old MD5 = '%s'\n", old_info[4]);
            printf("* new MD5 = '%s'\n", new_info[4]);
        }
        if(strcmp(old_info[5], new_info[5]) != 0)
        {
            printf("* old sha1 = '%s'\n", old_info[5]);
            printf("* new sha1 = '%s'\n", new_info[5]);
        }
        if(strcmp(old_info[6], new_info[6]) != 0)
        {
            char date_ymd[20] = "";

            time_t tm_old = atol(old_info[6]);
            strftime(date_ymd, 20, "%Y-%m-%d %H:%M:%S", localtime(&tm_old)); 
            printf("* old mod date = '%s'\n", date_ymd);

            time_t tm_new = atol(new_info[6]);
            strftime(date_ymd, 20, "%Y-%m-%d %H:%M:%S", localtime(&tm_new));
            printf("* new mod date = '%s'\n", date_ymd);
        }
        printf("************************************************************\n\n");
    }

    return;
}

/* Read and generate the integrity data of a file */
int read_file(char *file_name)
{
    //printf("This is the start of the read_file function.\n");
    char *buf;
    char sha1s = '+';
    struct stat statbuf;

    if (lstat(file_name, &statbuf) < 0)
    {
        if(errno == ENOTDIR)
        {
            /*Deletion message sending*/
            // char alert_msg[PATH_MAX+4];
            // alert_msg[PATH_MAX + 3] = '\0';
            // snprintf(alert_msg, PATH_MAX + 4, "-1 %s", file_name);
            // fim_detection_msg(alert_msg);
            return (0);
        }
        else{
            //merror("%s: Error accessing '%s'.", ARGV0, file_name);
            return (-1);
        }
    }
   
    if (S_ISDIR(statbuf.st_mode)) {
        printf("this is directory %s\n", file_name);
        return (read_dir(file_name));
    }

    if (S_ISREG(statbuf.st_mode) || S_ISLNK(statbuf.st_mode))
    {
        os_md5 mf_sum;
        os_sha1 sf_sum;
        os_sha1 sf_sum2;
        os_sha1 sf_sum3;

        /* Clean sums */
        strncpy(mf_sum,  "xxx", 4);
        strncpy(sf_sum,  "xxx", 4);
        strncpy(sf_sum2, "xxx", 4);
        strncpy(sf_sum3, "xxx", 4);

        /* If it is a link, check if dest is valid */
        if (S_ISLNK(statbuf.st_mode)) 
        {
            struct stat statbuf_lnk;
            if (stat(file_name, &statbuf_lnk) == 0) {
                if (S_ISREG(statbuf_lnk.st_mode)) {
                    if (OS_MD5_SHA1_File(file_name, syscheck.prefilter_cmd, mf_sum, sf_sum, OS_BINARY) < 0) {
                        strncpy(mf_sum, "xxx", 4);
                        strncpy(sf_sum, "xxx", 4);
                    }
                }
            }
        } else if (OS_MD5_SHA1_File(file_name, syscheck.prefilter_cmd, mf_sum, sf_sum, OS_BINARY) < 0)
        {
            strncpy(mf_sum, "xxx", 4);
            strncpy(sf_sum, "xxx", 4);
        }

        //sha1s = 's';

        buf = (char *) OSHash_Get(syscheck.fp, file_name);
        
        time_t mod_date;
        mod_date = file_dateofchange(file_name);
        
        struct passwd *pwd;
        pwd = getpwuid(statbuf.st_uid);

        struct group *grp;
        grp = getgrgid(statbuf.st_gid);

        char new_checksum[1024] = "";
        sprintf(new_checksum, "%ld:%07o:%s:%s:%s:%s:%ld:%s",
                 CHECK_SIZE ? (long)statbuf.st_size : 0,
                 CHECK_PERM ? (int)statbuf.st_mode : 0,
                 CHECK_OWNER ? pwd->pw_name : "unknown",
                 CHECK_GROUP ? grp->gr_name : "unknown",
                 CHECK_MD5SUM ? mf_sum : "xxx",
                 CHECK_SHA1SUM ? sf_sum : "xxx",
                 (long)mod_date,
                 file_name);

        if (!buf)
        {
            if(syscheck.create_db_flag == 1)
            {
                char date_ymd[20] = "";;
                strftime(date_ymd, 20, "%Y-%m-%d %H:%M:%S", localtime(&mod_date)); 

                printf("***** New file '%s' added *****\n", file_name);                
                printf("* size = '%ld'\n", (long)statbuf.st_size);
                printf("* permission = '%07o'\n", (int)statbuf.st_mode);
                printf("* uid = '%s'\n", pwd->pw_name);
                printf("* gid = '%s'\n", grp->gr_name);
                printf("* MD5 = '%s'\n", mf_sum);
                printf("* sha1 = '%s'\n", sf_sum);
                printf("* modified date = '%s'\n", date_ymd);
                printf("***************************************************\n\n");
            }
            if (OSHash_Add(syscheck.fp, file_name, strdup(new_checksum)) <= 0) {  
                printf("Unable to add file to db.\n");
            }

        } 
        else {
            diff_check_func(file_name, buf, new_checksum);
            OSHash_Update(syscheck.fp, file_name, strdup(new_checksum));
        }
    } 
    return (0);
}

int read_dir(char *dir_name)
{
    //printf("This is the start of the read_dir function.\n");
    size_t dir_size;
    char f_name[PATH_MAX + 2];

    DIR *dp;
    struct dirent *entry;

    f_name[PATH_MAX + 1] = '\0';

    /* Directory should be valid. */
    if ((dir_size = strlen(dir_name)) > PATH_MAX) {
       printf("Directry should be valid.\n");
        return (-1);
    }

    /* Open the directory given */
    dp = opendir(dir_name);
    if (!dp) {
        if (errno == ENOTDIR) {
            if (read_file(dir_name) == 0) {
                return (0);
            }
        }
        printf("Error opening directory.\n");
        return (-1);
    }

    while ((entry = readdir(dp)) != NULL) {
        char *s_name;

        /* Ignore . and ..  */
        if ((strcmp(entry->d_name, ".") == 0) ||
                (strcmp(entry->d_name, "..") == 0)) {
            continue;
        }

        strncpy(f_name, dir_name, PATH_MAX);
        s_name = f_name;
        s_name += dir_size;

        /* Check if the file name is already null terminated */
        if (*(s_name - 1) != '/') {
            *s_name++ = '/';
        }

        *s_name = '\0';
        strncpy(s_name, entry->d_name, PATH_MAX - dir_size - 2);

        /* Check if the file is a directory */
        struct stat recurse_sb;
        if((stat(f_name, &recurse_sb)) < 0) {
            //merror("%s: ERR: Cannot stat %s: %s", ARGV0, f_name, strerror(errno));
            printf("Can not stat '%s'. \n", f_name);
        } else {
            switch (recurse_sb.st_mode & S_IFMT) {
                case S_IFDIR:
                    read_dir(f_name);
                    continue;
                    break;
            }
        }

        /* Check integrity of the file */
        //printf("file name = %s\n", f_name);
        read_file(f_name);
    }

    closedir(dp);
    return (0);
}

void run_dir_check(char *path)
{
    read_dir(path);
}

void run_db_check(OSHash *self)
{
    unsigned int i = 0;
    OSHashNode *curr_node;
    OSHashNode *next_node;

    /* Free each entry */
    while (i <= self->rows) {
        curr_node = self->table[i];
        next_node = curr_node;
        while (next_node) {
            next_node = next_node->next;
            if(access(curr_node->key, F_OK) != 0)
            {
                printf("***** '%s' file removed *****\n", curr_node->key);
                OSHash_Delete(syscheck.fp, curr_node->key);
            }
            
            curr_node = next_node;
        }
        i++;
    }
    return;
}

void main()
{
    syscheck.fp = OSHash_Create();
    syscheck.create_db_flag = 0;

    char *scan_dir[] = {"/etc", "/usr/sbin", "/usr/bin", NULL};
    //char *scan_dir[] = {"/tmp/test/dir1", "/tmp/test/dir2", NULL};
    int _i = 0;

    printf("Initializing...\n");
    while(scan_dir[_i] != NULL)
    {
        // Create db
        read_dir(scan_dir[_i]);
        _i++;
    }

    syscheck.create_db_flag = 1;

    printf("Intialized. Will scan after a while..\n");
    sleep(10);
    //sleep(3600);
    
    _i = 0;
    while(1)
    {
        printf("Started to scan.\n\n");
        while(scan_dir[_i] != NULL)
        {
            // Check added or modified files
            run_dir_check(scan_dir[_i]);
            _i++;
        }
        _i = 0;

        // Check deleted files
        run_db_check(syscheck.fp);

        printf("End scaning. This will sleep for a while to next scaning...\n\n");
        
        sleep(10);
        //sleep(3600);

    }
}