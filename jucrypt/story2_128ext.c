#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <string.h>

/* ── Compiler portability ───────────────────────────────────────────────── */
#if defined(__GNUC__) || defined(__clang__)
#  define FORCE_INLINE  __attribute__((always_inline)) static inline
#  define LIKELY(x)     __builtin_expect(!!(x), 1)
#  define UNLIKELY(x)   __builtin_expect(!!(x), 0)
#  define RESTRICT      __restrict__
#  define ALIGN(n)      __attribute__((aligned(n)))
#else
#  define FORCE_INLINE  static inline
#  define LIKELY(x)     (x)
#  define UNLIKELY(x)   (x)
#  define RESTRICT
#  define ALIGN(n)
#endif

/* ── Constants ──────────────────────────────────────────────────────────── */
#define BLOCK_SIZE    16
#define ROUNDS        5
#define SBOX_POOL_MAX 256

/* ── Module-level tables ────────────────────────────────────────────────── */
static ALIGN(64) uint8_t GF[256][256];

/*
 * MDS_T[j][v][i] = GF[MDS[i][j]][v]
 *
 * Transposed layout: for input byte j with value v, MDS_T[j][v] is a
 * 16-byte array giving every output row's contribution from that one
 * input byte.  One cache line per (j,v) pair — optimal for the XOR loop.
 *
 * Total: 16 × 256 × 16 = 65,536 bytes (fits in L1).
 */
static ALIGN(64) uint8_t MDS_T[16][256][16];

static int tables_ready = 0;

/* ── S-box pool ─────────────────────────────────────────────────────────── */
static ALIGN(64) uint8_t SBOX_POOL[SBOX_POOL_MAX][256];
static int SBOX_COUNT = 0;


/* ═══════════════════════════════════════════════════════════════════════════
 *  Table initialisation
 * ═══════════════════════════════════════════════════════════════════════════ */

static PyObject *
story2_build_tables(PyObject *self, PyObject *args)
{
    const uint8_t *gf_buf, *mds_buf;
    Py_ssize_t     gf_len,  mds_len;

    if (!PyArg_ParseTuple(args, "y#y#",
                          &gf_buf, &gf_len, &mds_buf, &mds_len))
        return NULL;

    if (UNLIKELY(gf_len  != 65536)) { PyErr_SetString(PyExc_ValueError, "GF table must be 65536 bytes");  return NULL; }
    if (UNLIKELY(mds_len != 256))   { PyErr_SetString(PyExc_ValueError, "MDS matrix must be 256 bytes"); return NULL; }

    /* Load raw GF table */
    memcpy(GF, gf_buf, 65536);

    /* Build transposed MDS_T from the raw MDS matrix */
    for (int j = 0; j < 16; j++)
        for (int v = 0; v < 256; v++)
            for (int i = 0; i < 16; i++)
                MDS_T[j][v][i] = GF[ mds_buf[i * 16 + j] ][v];

    tables_ready = 1;
    Py_RETURN_NONE;
}

static PyObject *
story2_load_sbox(PyObject *self, PyObject *args)
{
    int idx;
    const uint8_t *sbox;
    Py_ssize_t     slen;

    if (!PyArg_ParseTuple(args, "iy#", &idx, &sbox, &slen))
        return NULL;

    if (UNLIKELY(slen != 256))
        { PyErr_SetString(PyExc_ValueError, "S-box must be 256 bytes"); return NULL; }
    if (UNLIKELY(idx < 0 || idx >= SBOX_POOL_MAX))
        { PyErr_Format(PyExc_ValueError, "S-box index %d out of range", idx); return NULL; }

    memcpy(SBOX_POOL[idx], sbox, 256);
    if (idx >= SBOX_COUNT) SBOX_COUNT = idx + 1;
    Py_RETURN_NONE;
}

static PyObject *
story2_sbox_count(PyObject *self, PyObject *args)
{
    return PyLong_FromLong(SBOX_COUNT);
}


/* ═══════════════════════════════════════════════════════════════════════════
 *  Round primitives
 * ═══════════════════════════════════════════════════════════════════════════ */

/* AddRoundKey — unrolled, compiler can emit SIMD XOR */
FORCE_INLINE void
ark(uint8_t state[16], const uint8_t * RESTRICT rk)
{
    state[0]^=rk[0];  state[1]^=rk[1];  state[2]^=rk[2];  state[3]^=rk[3];
    state[4]^=rk[4];  state[5]^=rk[5];  state[6]^=rk[6];  state[7]^=rk[7];
    state[8]^=rk[8];  state[9]^=rk[9];  state[10]^=rk[10];state[11]^=rk[11];
    state[12]^=rk[12];state[13]^=rk[13];state[14]^=rk[14];state[15]^=rk[15];
}

/* SubBytes — separate input/output breaks write-after-read stall */
FORCE_INLINE void
sub_bytes(const uint8_t in[16], const uint8_t sbox[256], uint8_t out[16])
{
    out[0] =sbox[in[0]];  out[1] =sbox[in[1]];
    out[2] =sbox[in[2]];  out[3] =sbox[in[3]];
    out[4] =sbox[in[4]];  out[5] =sbox[in[5]];
    out[6] =sbox[in[6]];  out[7] =sbox[in[7]];
    out[8] =sbox[in[8]];  out[9] =sbox[in[9]];
    out[10]=sbox[in[10]]; out[11]=sbox[in[11]];
    out[12]=sbox[in[12]]; out[13]=sbox[in[13]];
    out[14]=sbox[in[14]]; out[15]=sbox[in[15]];
}

/*
 * MDS Mix — 16×16 Cauchy, BN=17.
 *
 * FIX vs v2.1: 16 INDEPENDENT acc variables instead of result[] array.
 *
 * v2.1 bug: result[k] ^= row0[k] ^ row1[k] ^ ...
 *   Every loop iteration reads result[k] written by the previous iteration.
 *   READ-AFTER-WRITE hazard — CPU must stall until the store drains.
 *   The "4-way parallel" claim was false: accumulation serialised everything.
 *
 * v2.2 fix: each acc variable is written only ONCE before being stored.
 *   a0..a15 are independent — the CPU can compute all 16 simultaneously
 *   across different execution ports.  Zero pipeline stalls.
 *
 * Access pattern with MDS_T:
 *   row = MDS_T[j][input[j]]  — one 16-byte cache line
 *   a0 ^= row[0], a1 ^= row[1], ... a15 ^= row[15]
 *   16 iterations × 16-byte row = 256 XORs, all on independent operands.
 */
FORCE_INLINE void
mix(const uint8_t in[16], uint8_t out[16])
{
    /* Load all 16 MDS rows first — gives the CPU maximum scheduling freedom */
    const uint8_t *r0  = MDS_T[0][in[0]];
    const uint8_t *r1  = MDS_T[1][in[1]];
    const uint8_t *r2  = MDS_T[2][in[2]];
    const uint8_t *r3  = MDS_T[3][in[3]];
    const uint8_t *r4  = MDS_T[4][in[4]];
    const uint8_t *r5  = MDS_T[5][in[5]];
    const uint8_t *r6  = MDS_T[6][in[6]];
    const uint8_t *r7  = MDS_T[7][in[7]];
    const uint8_t *r8  = MDS_T[8][in[8]];
    const uint8_t *r9  = MDS_T[9][in[9]];
    const uint8_t *r10 = MDS_T[10][in[10]];
    const uint8_t *r11 = MDS_T[11][in[11]];
    const uint8_t *r12 = MDS_T[12][in[12]];
    const uint8_t *r13 = MDS_T[13][in[13]];
    const uint8_t *r14 = MDS_T[14][in[14]];
    const uint8_t *r15 = MDS_T[15][in[15]];

    /*
     * 16 independent accumulations — one per output byte.
     * Each a_k depends only on r0[k]..r15[k], not on any other a_j.
     * The compiler (and CPU) can issue all 16 chains in parallel.
     */
#define XR(k) \
    (r0[k]^r1[k]^r2[k]^r3[k]^r4[k]^r5[k]^r6[k]^r7[k] \
    ^r8[k]^r9[k]^r10[k]^r11[k]^r12[k]^r13[k]^r14[k]^r15[k])

    out[0] =XR(0);  out[1] =XR(1);  out[2] =XR(2);  out[3] =XR(3);
    out[4] =XR(4);  out[5] =XR(5);  out[6] =XR(6);  out[7] =XR(7);
    out[8] =XR(8);  out[9] =XR(9);  out[10]=XR(10); out[11]=XR(11);
    out[12]=XR(12); out[13]=XR(13); out[14]=XR(14); out[15]=XR(15);
#undef XR
}


/* ═══════════════════════════════════════════════════════════════════════════
 *  Block encryption
 *
 *  Round structure: (ARK → SubBytes → Mix) × ROUNDS → final ARK (whitening)
 *
 *  FIX vs v2.1: rk_flat is 80 bytes (5 × 16), wk is a separate 16-byte
 *  whitening key.  Previously rk_flat was 96 bytes with the whitening key
 *  concatenated — that clashed with story2.py which derives them separately.
 *
 *  Dual-buffer ping-pong (state ↔ temp) eliminates in-place write hazards.
 * ═══════════════════════════════════════════════════════════════════════════ */

FORCE_INLINE void
encrypt_block(const uint8_t  in[16],
              const uint8_t  sbox[256],
              const uint8_t * RESTRICT rk_flat,   /* 5 × 16 = 80 bytes */
              const uint8_t  wk[16],              /* whitening key, 16 bytes */
              uint8_t        out[16])
{
    ALIGN(16) uint8_t state[16];
    ALIGN(16) uint8_t temp[16];

    memcpy(state, in, 16);

    for (int r = 0; r < ROUNDS; r++) {
        ark(state, rk_flat + r * 16);   /* ARK: state ^= round_key[r]  */
        sub_bytes(state, sbox, temp);   /* Sub: temp  = sbox[state]    */
        mix(temp, state);               /* Mix: state = MDS(temp)      */
    }

    /* Final whitening — independently derived key closes last-round peel */
    ark(state, wk);

    memcpy(out, state, 16);
}


/* ── Counter block ─────────────────────────────────────────────────────── */

FORCE_INLINE void
build_counter_block(const uint8_t nonce[8], uint64_t ctr, uint8_t out[16])
{
    memcpy(out, nonce, 8);
    out[8]  = (uint8_t)(ctr >> 56); out[9]  = (uint8_t)(ctr >> 48);
    out[10] = (uint8_t)(ctr >> 40); out[11] = (uint8_t)(ctr >> 32);
    out[12] = (uint8_t)(ctr >> 24); out[13] = (uint8_t)(ctr >> 16);
    out[14] = (uint8_t)(ctr >>  8); out[15] = (uint8_t)(ctr);
}


/* ═══════════════════════════════════════════════════════════════════════════
 *  CTR loop — quad-block interleaving for bulk throughput
 *
 *  Four blocks in flight: while one waits on a cache miss, the others
 *  can progress through ARK/Sub.  Effective for messages >= 64 bytes.
 * ═══════════════════════════════════════════════════════════════════════════ */

static void
ctr_loop(const uint8_t * RESTRICT data,
         Py_ssize_t                dlen,
         const uint8_t             nonce[8],
         const uint8_t             sbox[256],
         const uint8_t * RESTRICT  rk_flat,
         const uint8_t             wk[16],
         uint64_t                  ctr,
         uint8_t       * RESTRICT  out)
{
    ALIGN(16) uint8_t cb0[16], cb1[16], cb2[16], cb3[16];
    ALIGN(16) uint8_t ks0[16], ks1[16], ks2[16], ks3[16];
    Py_ssize_t offset = 0;

    /* ── Quad-block (64 bytes / iter) ── */
    while (offset + 64 <= dlen) {
        build_counter_block(nonce, ctr,   cb0);
        build_counter_block(nonce, ctr+1, cb1);
        build_counter_block(nonce, ctr+2, cb2);
        build_counter_block(nonce, ctr+3, cb3);
        ctr += 4;

        encrypt_block(cb0, sbox, rk_flat, wk, ks0);
        encrypt_block(cb1, sbox, rk_flat, wk, ks1);
        encrypt_block(cb2, sbox, rk_flat, wk, ks2);
        encrypt_block(cb3, sbox, rk_flat, wk, ks3);

        for (int k = 0; k < 16; k++) {
            out[offset   +k] = data[offset   +k] ^ ks0[k];
            out[offset+16+k] = data[offset+16+k] ^ ks1[k];
            out[offset+32+k] = data[offset+32+k] ^ ks2[k];
            out[offset+48+k] = data[offset+48+k] ^ ks3[k];
        }
        offset += 64;
    }

    /* ── Dual-block (32 bytes / iter) ── */
    while (offset + 32 <= dlen) {
        build_counter_block(nonce, ctr,   cb0);
        build_counter_block(nonce, ctr+1, cb1);
        ctr += 2;

        encrypt_block(cb0, sbox, rk_flat, wk, ks0);
        encrypt_block(cb1, sbox, rk_flat, wk, ks1);

        for (int k = 0; k < 16; k++) {
            out[offset   +k] = data[offset   +k] ^ ks0[k];
            out[offset+16+k] = data[offset+16+k] ^ ks1[k];
        }
        offset += 32;
    }

    /* ── Single-block tail ── */
    while (offset < dlen) {
        ALIGN(16) uint8_t cb[16], ks[16];
        build_counter_block(nonce, ctr++, cb);
        encrypt_block(cb, sbox, rk_flat, wk, ks);

        Py_ssize_t chunk = dlen - offset;
        if (chunk > 16) chunk = 16;
        for (Py_ssize_t k = 0; k < chunk; k++)
            out[offset + k] = data[offset + k] ^ ks[k];
        offset += chunk;
    }
}


/* ═══════════════════════════════════════════════════════════════════════════
 *  Python API
 * ═══════════════════════════════════════════════════════════════════════════ */

static PyObject *
py_story2_encrypt_block(PyObject *self, PyObject *args)
{
    const uint8_t *block, *sbox, *rk_flat, *wk;
    Py_ssize_t     blen,  slen,  rklen,    wklen;

    if (!PyArg_ParseTuple(args, "y#y#y#y#",
                          &block,  &blen,
                          &sbox,   &slen,
                          &rk_flat, &rklen,
                          &wk,     &wklen))
        return NULL;

    if (UNLIKELY(!tables_ready))
        { PyErr_SetString(PyExc_RuntimeError, "Call story2_build_tables() first"); return NULL; }
    if (UNLIKELY(blen != 16 || slen != 256 || rklen != ROUNDS * 16 || wklen != 16))
        { PyErr_Format(PyExc_ValueError,
            "Wrong sizes: block=%zd(16) sbox=%zd(256) rk=%zd(%d) wk=%zd(16)",
            blen, slen, rklen, ROUNDS*16, wklen);
          return NULL; }

    uint8_t out[16];
    encrypt_block(block, sbox, rk_flat, wk, out);
    return PyBytes_FromStringAndSize((const char *)out, 16);
}

/* CTR with explicit sbox bytes */
static PyObject *
py_story2_ctr_crypt(PyObject *self, PyObject *args)
{
    const uint8_t *data, *nonce, *sbox, *rk_flat, *wk;
    Py_ssize_t     dlen,  nlen,  slen,  rklen,    wklen;
    unsigned long long start_ctr = 0;

    if (!PyArg_ParseTuple(args, "y#y#y#y#y#|K",
                          &data, &dlen, &nonce, &nlen,
                          &sbox, &slen, &rk_flat, &rklen,
                          &wk,   &wklen, &start_ctr))
        return NULL;

    if (UNLIKELY(!tables_ready))
        { PyErr_SetString(PyExc_RuntimeError, "Call story2_build_tables() first"); return NULL; }
    if (UNLIKELY(nlen != 8 || slen != 256 || rklen != ROUNDS * 16 || wklen != 16))
        { PyErr_Format(PyExc_ValueError,
            "Wrong sizes: nonce=%zd(8) sbox=%zd(256) rk=%zd(%d) wk=%zd(16)",
            nlen, slen, rklen, ROUNDS*16, wklen);
          return NULL; }

    PyObject *result = PyBytes_FromStringAndSize(NULL, dlen);
    if (UNLIKELY(!result)) return NULL;

    ctr_loop(data, dlen, nonce, sbox, rk_flat, wk,
             (uint64_t)start_ctr,
             (uint8_t *)PyBytes_AS_STRING(result));
    return result;
}

/* CTR with sbox index into pool */
static PyObject *
py_story2_ctr_crypt_idx(PyObject *self, PyObject *args)
{
    const uint8_t *data, *nonce, *rk_flat, *wk;
    Py_ssize_t     dlen,  nlen,  rklen,    wklen;
    int            sbox_idx;
    unsigned long long start_ctr = 0;

    if (!PyArg_ParseTuple(args, "y#y#iy#y#|K",
                          &data, &dlen, &nonce, &nlen,
                          &sbox_idx,
                          &rk_flat, &rklen,
                          &wk,      &wklen,
                          &start_ctr))
        return NULL;

    if (UNLIKELY(!tables_ready))
        { PyErr_SetString(PyExc_RuntimeError, "Call story2_build_tables() first"); return NULL; }
    if (UNLIKELY(sbox_idx < 0 || sbox_idx >= SBOX_COUNT))
        { PyErr_Format(PyExc_ValueError, "S-box index %d not loaded", sbox_idx); return NULL; }
    if (UNLIKELY(nlen != 8 || rklen != ROUNDS * 16 || wklen != 16))
        { PyErr_Format(PyExc_ValueError,
            "Wrong sizes: nonce=%zd(8) rk=%zd(%d) wk=%zd(16)",
            nlen, rklen, ROUNDS*16, wklen);
          return NULL; }

    PyObject *result = PyBytes_FromStringAndSize(NULL, dlen);
    if (UNLIKELY(!result)) return NULL;

    ctr_loop(data, dlen, nonce, SBOX_POOL[sbox_idx], rk_flat, wk,
             (uint64_t)start_ctr,
             (uint8_t *)PyBytes_AS_STRING(result));
    return result;
}

/* ── Method table ───────────────────────────────────────────────────────── */

static PyMethodDef Story2Methods[] = {
    {"story2_build_tables",   story2_build_tables,     METH_VARARGS,
     "story2_build_tables(gf_flat, mds_flat) — init tables once at import."},
    {"story2_load_sbox",      story2_load_sbox,        METH_VARARGS,
     "story2_load_sbox(idx, sbox256) — load S-box into pool."},
    {"story2_sbox_count",     story2_sbox_count,       METH_NOARGS,
     "story2_sbox_count() -> int — number of loaded S-boxes."},
    {"story2_encrypt_block",  py_story2_encrypt_block, METH_VARARGS,
     "story2_encrypt_block(block16, sbox256, rk80, wk16) -> bytes16"},
    {"story2_ctr_crypt",      py_story2_ctr_crypt,     METH_VARARGS,
     "story2_ctr_crypt(data, nonce8, sbox256, rk80, wk16[, ctr]) -> bytes"},
    {"story2_ctr_crypt_idx",  py_story2_ctr_crypt_idx, METH_VARARGS,
     "story2_ctr_crypt_idx(data, nonce8, sbox_idx, rk80, wk16[, ctr]) -> bytes"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef story2module = {
    PyModuleDef_HEAD_INIT, "story2_128ext",
    "STORY2 v2.2 — fixed mix, fixed round-key API", -1, Story2Methods
};

PyMODINIT_FUNC PyInit_story2_128ext(void) {
    return PyModule_Create(&story2module);
}