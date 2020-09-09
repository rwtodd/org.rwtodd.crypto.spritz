// SpritzDecrypt.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <fstream>
#include <cstdlib>

#define N 256
using std::size_t;

struct s_spritz_state
{
    uint8_t i, j, k, z, a, w;
    uint8_t mem[N];
};

typedef struct s_spritz_state* const spritz_state;

/* the main calls ******************************** */
spritz_state create_spritz(void);
void destroy_spritz(spritz_state s);
void spritz_absorb(spritz_state s, const uint8_t b);
void spritz_absorb_many(spritz_state s, const uint8_t* bytes, size_t len);
void spritz_absorb_stop(spritz_state s);
uint8_t spritz_drip(spritz_state s);
void spritz_drip_many(spritz_state s, uint8_t* arr, size_t len);
void spritz_xor_many(spritz_state s, uint8_t* arr, size_t len);


static void
reset_state(spritz_state s)
{
    s->i = s->j = s->k = s->z = s->a = 0;
    s->w = 1;
    for (int idx = 0; idx < N; ++idx)
    {
        s->mem[idx] = idx;
    }
}

/* creates memory that should be destroyed by
 * call to destroy_spritz
 */
spritz_state
create_spritz(void)
{
    spritz_state ans = new s_spritz_state;
    if (ans == NULL)
        return NULL;
    reset_state(ans);
    return ans;
}

void
destroy_spritz(spritz_state s)
{
    delete s;
}

static inline void
swap(uint8_t* const arr, size_t el1, size_t el2)
{
    uint8_t tmp = arr[el1];
    arr[el1] = arr[el2];
    arr[el2] = tmp;
}

/* when adding indices... need them modulus 256 */
#define smem(x)  s->mem[ (x) & 0xff ]

static void
update(spritz_state s, int times)
{
    uint8_t mi = s->i;
    uint8_t mj = s->j;
    uint8_t mk = s->k;
    const uint8_t mw = s->w;

    while (times--)
    {
        mi += mw;
        mj = mk + smem(mj + s->mem[mi]);
        mk = mi + mk + s->mem[mj];
        swap(s->mem, mi, mj);
    }

    s->i = mi;
    s->j = mj;
    s->k = mk;
}


static void
whip(spritz_state s, const int amt)
{
    update(s, amt);
    s->w += 2;
}


static void
crush(spritz_state s)
{
    for (size_t v = 0; v < (N / 2); ++v)
    {
        if (s->mem[v] > s->mem[N - 1 - v])
            swap(s->mem, v, N - 1 - v);
    }
}

static void
shuffle(spritz_state s)
{
    whip(s, N * 2);
    crush(s);
    whip(s, N * 2);
    crush(s);
    whip(s, N * 2);
    s->a = 0;
}

static inline void
absorb_nibble(spritz_state s, uint8_t x)
{
    if (s->a == N / 2)
        shuffle(s);
    swap(s->mem, s->a, (N / 2 + x));
    s->a++;
}

inline void
spritz_absorb(spritz_state s, const uint8_t b)
{
    absorb_nibble(s, b & 0x0f);
    absorb_nibble(s, b >> 4);
}

void
spritz_absorb_many(spritz_state s, const uint8_t* bytes, size_t len)
{
    const uint8_t* const end = bytes + len;
    while (bytes != end)
    {
        spritz_absorb(s, *bytes++);
    }
}

void
spritz_absorb_stop(spritz_state s)
{
    if (s->a == N / 2)
        shuffle(s);
    s->a++;
}

static uint8_t
drip_one(spritz_state s)
{
    update(s, 1);
    s->z = smem(s->j + smem(s->i + smem(s->z + s->k)));
    return s->z;
}

uint8_t
spritz_drip(spritz_state s)
{
    if (s->a > 0)
        shuffle(s);
    return drip_one(s);
}

void
spritz_drip_many(spritz_state s, uint8_t* arr, size_t len)
{
    uint8_t* const end = arr + len;
    if (s->a > 0)
        shuffle(s);
    while (arr != end)
    {
        *arr++ = drip_one(s);
    }
}

/* used for encryption/decryption */
void
spritz_xor_many(spritz_state s, uint8_t* arr, size_t len)
{
    uint8_t* const end = arr + len;
    if (s->a > 0)
        shuffle(s);
    while (arr != end)
    {
        *arr++ ^= drip_one(s);
    }
}

/* absorb_number is a helper function which absorbs the bytes
 * of a number, one at a time.  Used as part of the hashing
 * process for large hash sizes.  Note that there is no
 * practical chance of blowing the stack with this recursive
 * funcion, as any reasonable hash size is 2 bytes or less.
 */
static void
absorb_number(spritz_state s, size_t number)
{
    if (number > 255)
    {
        absorb_number(s, number >> 8);
    }
    spritz_absorb(s, (uint8_t)(number & 0xff));
}

/*
 *  fills user-provided memory with hashed bytes.
 */
void
spritz_mem_hash(const uint8_t* const mem, size_t len, uint8_t* const hash,
    size_t bytes)
{
    struct s_spritz_state s;
    reset_state(&s);

    spritz_absorb_many(&s, mem, len);
    spritz_absorb_stop(&s);
    absorb_number(&s, bytes);

    spritz_drip_many(&s, hash, bytes);
}

/* define the file header offsets */
#define HDR_IV 0
#define HDR_CHECK_INT 4
#define HDR_HASHCHECK_INT 8
#define HDR_KEY 12
#define KEY_LEN 64
#define HDR_LEN (HDR_KEY+KEY_LEN)

/*
 * ************************************************************
 * Utilities Section
 * ************************************************************
 */

 /* our source for keys */
static struct s_spritz_state* random_source;

#if 0
static bool
seed_rand(void)
{
    /*
     * it's possible/likely that dev/urandom doesn't have
     * KEY_LEN bytes of randomness, but we won't do better
     * elsewhere, and maybe one day it might, so...
     */
    uint8_t noise[KEY_LEN];
    int urand = open("/dev/urandom", O_RDONLY);
    if (urand < 0)
    {
        perror("open urandom");
        return false;
    }
    if (read(urand, noise, KEY_LEN) != KEY_LEN)
    {
        fputs("failed to read urandom!", stderr);
        return false;
    }
    close(urand);

    if ((random_source = create_spritz()) == NULL)
    {
        fputs("could not create random source!", stderr);
        return false;
    }
    spritz_absorb_many(random_source, noise, KEY_LEN);
    spritz_absorb_stop(random_source);
    /* add the low byte of the UNIX time stamp for laughs */
    spritz_absorb(random_source, (uint8_t)(time(NULL) & 0xff));
    return true;
}

/* generate bytes of random data */
static void
gen_rdata(uint8_t* buf, size_t len)
{
    spritz_drip_many(random_source, buf, len);
}
#endif

/* xor other into tgt, overwriting tgt */
static void
xor_arrays(uint8_t* tgt, const uint8_t* other, size_t len)
{
    while (len--)
        *tgt++ ^= *other++;
}

static bool
fd_xor_copy(spritz_state s, std::ostream &tgt_fd, std::istream &src_fd)
{
    std::auto_ptr<uint8_t> buffer(new uint8_t[8196]);
    if (buffer.get() == nullptr) {
        return false;
    }

    while (!src_fd.eof()) {
        std::streamsize toread = 8196;
        src_fd.read(reinterpret_cast<char*>(buffer.get()), toread);
        if (!src_fd) {
            toread = src_fd.gcount();
            if (!src_fd.eof()) src_fd.clear();
        }
        spritz_xor_many(s, buffer.get(), toread);
        tgt_fd.write(reinterpret_cast<char *>(buffer.get()), toread);
        if (!tgt_fd) {
            return false;
        }
    }
    return true;
}

/*
 * ************************************************************
 * Headers Section
 * ************************************************************
 */

 /*
  * Keygen is just rounds and rounds of hashing.
  */
static void
keygen(uint8_t* tgt, const uint8_t* hashed_pw, const uint8_t* iv,
    int times)
{
    uint8_t iv_copy[4];
    memcpy(tgt, hashed_pw, KEY_LEN);
    memcpy(iv_copy, iv, 4);

    spritz_state s = create_spritz();
    while (times--)
    {
        size_t bias = iv_copy[0] & 3;
        spritz_absorb_many(s, iv_copy, 4);
        spritz_absorb_stop(s);
        spritz_absorb_many(s, iv + bias, 4 - bias);
        spritz_absorb_stop(s);
        spritz_absorb_many(s, tgt, KEY_LEN);
        spritz_absorb_stop(s);
        spritz_drip_many(s, tgt, KEY_LEN);
        spritz_drip_many(s, iv_copy, 4);
    }
    destroy_spritz(s);
}

/* create a spritz_state ready to go using the key and the iv,
 * skipping some output in case the first few bytes are easy
 * to attack.
 */
static spritz_state
generate_skipped_stream(const uint8_t* key, int skip_amt)
{
    spritz_state stream = create_spritz();
    if (stream == NULL)
        return NULL;

    spritz_absorb_many(stream, key, KEY_LEN);
    int to_skip = 2048 + skip_amt;
    while (to_skip--)
        spritz_drip(stream);
    return stream;
}



/*
 * Take an encrypted header and decrypt it using a provided hashed password.
 */
static bool
decrypt_header(uint8_t* header, const uint8_t* pw_hash)
{
    uint8_t pw_key[KEY_LEN];
    bool result = false;

    /* IV is encrypted with the end of the single pw-hash */
    xor_arrays(header + HDR_IV, pw_hash + KEY_LEN - 4, 4);

    keygen(pw_key, pw_hash, header + HDR_IV,
        20000 + ((int)(header[HDR_IV + 3])));
    std::auto_ptr<s_spritz_state> s(
        generate_skipped_stream(pw_key, (int)(header[HDR_IV + 1])));

    /* Now, decrypt the check integer and its hash against the generated key-stream,
     * and then skip more of the key-stream before decrypting the actual payload key.
     *
     * make the amount of stream to skip dependent on the check int value
     */
    spritz_xor_many(s.get(), header + HDR_CHECK_INT, 8);

    /* now check that the check int hashes to the value that follows it */
    uint8_t rhash[4];
    spritz_mem_hash(header + HDR_CHECK_INT, 4, rhash, 4);
    if (memcmp(rhash, header + HDR_HASHCHECK_INT, 4) != 0)
        return false;

    int extra_skip = 5 + (int)(header[HDR_CHECK_INT]);
    while (extra_skip--)
        spritz_drip(s.get());
    spritz_xor_many(s.get(), header + HDR_KEY, KEY_LEN);
    result = true;                /* success! */

    return result;
}

/*
 * ************************************************************
 * Decrypting Section
 * ************************************************************
 */

/* decrypt_file: decrypt 'src' against password 'pw_hash', writing
 * the output to 'tgt'
 */
static bool
decrypt_file(const uint8_t* const pw_hash, const char* src)
{
    std::ifstream srcfd(src, std::ios::in | std::ios::binary);
    if (!srcfd.good()) {
        std::cerr << "Could not open file!" << std::endl;
        return false;
    }
    std::string ofname(src);
    if (ofname.size() > 4) {
        ofname.resize(ofname.size() - 4);
    }
    else {
        ofname.append(".out");
    }

    std::ofstream tgtfd(ofname, std::ios::out|std::ios::binary);
    bool result = false;

    uint8_t header[HDR_LEN];

    /* read in the header */
    if (!srcfd.read(reinterpret_cast<char*>(header), HDR_LEN)) {
        std::cerr << "File too short!" << std::endl;
        return false;
    }
       
    if (!decrypt_header(header, pw_hash))
    {
        std::cerr << "Bad password or corrupted file?" << std::endl;
        return false;
    }

    std::auto_ptr<s_spritz_state> ss(generate_skipped_stream(header + HDR_KEY,
        (int)(header
            [HDR_CHECK_INT + 1])));
    if (ss.get() == nullptr)
    {
        std::cerr << "could not generate state!" << std::endl;
        return false;
    }

    if (!fd_xor_copy(ss.get(), tgtfd, srcfd))
    {
        std::cerr << "Error during output copy!" << std::endl;
        return false;
    }

    return true;
}



int main(int argc, char**argv)
{
    uint8_t pw_hash[KEY_LEN];     /* the hashed password */

    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " pw filename" << std::endl;
        return 1;
    }
    
    std::cout << "decrypting " << argv[2] << std::endl;
    spritz_mem_hash(reinterpret_cast<uint8_t*>(argv[1]), strlen(argv[1]), pw_hash, KEY_LEN);
    return decrypt_file(pw_hash, argv[2]) ? 0 : 1;
}

