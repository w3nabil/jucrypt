/*
 * STORY C acceleration layer
 * Version : v0.4.0  
 * Author  : Nabil
 *
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* ── Compiler portability ─────────────────────────────────────────────── */
#if defined(__GNUC__) || defined(__clang__)
#  define FORCE_INLINE  __attribute__((always_inline)) static inline
#  define LIKELY(x)     __builtin_expect(!!(x), 1)
#  define UNLIKELY(x)   __builtin_expect(!!(x), 0)
#  define RESTRICT      __restrict__
#  define PREFETCH(p)   __builtin_prefetch((p), 0, 1)
#else
#  define FORCE_INLINE  static inline
#  define LIKELY(x)     (x)
#  define UNLIKELY(x)   (x)
#  define RESTRICT
#  define PREFETCH(p)
#endif

/* ── Module-level tables ─────────────────────────────────────────────── */
static uint8_t GF[256][256];           /* GF(2^8) mul — 64 KB            */
static uint8_t MDS[16][16];            /* 16×16 Cauchy MDS matrix        */

/* Transposed layout: MDS_T[j][v][i] = GF[MDS[i][j]][v]
 * Inner mix loop: for each input byte j with value v,
 * XOR the 16-byte row MDS_T[j][v] into result.
 * Each row is one contiguous cache line — prefetcher-friendly.           */
static uint8_t MDS_T[16][256][16];

static int     tables_ready = 0;

/* ── S-box pool ──────────────────────────────────────────────────────── */
#define SBOX_POOL_MAX 4096
static uint8_t SBOX_POOL[SBOX_POOL_MAX][256];
static int     SBOX_COUNT = 0;

/* ═══════════════════════════════════════════════════════════════════════════
 *  story_build_tables(gf_flat65536, mds_flat256)
 * ═══════════════════════════════════════════════════════════════════════════
 */
static PyObject *
story_build_tables(PyObject *self, PyObject *args)
{
    const uint8_t *gf_buf, *mds_buf;
    Py_ssize_t     gf_len,  mds_len;

    if (!PyArg_ParseTuple(args, "y#y#",
                          &gf_buf, &gf_len,
                          &mds_buf, &mds_len))
        return NULL;

    if (UNLIKELY(gf_len != 65536)) {
        PyErr_SetString(PyExc_ValueError, "gf_flat must be 65536 bytes");
        return NULL;
    }
    if (UNLIKELY(mds_len != 256)) {
        PyErr_SetString(PyExc_ValueError, "mds_flat must be 256 bytes");
        return NULL;
    }

    memcpy(GF,  gf_buf,  65536);
    memcpy(MDS, mds_buf, 256);

    /* Build transposed table MDS_T[j][v][i] = GF[MDS[i][j]][v]
     * The transposition moves the 'i' axis (output byte index) to the
     * innermost dimension so the hot loop reads contiguous memory.       */
    for (int j = 0; j < 16; j++)
        for (int v = 0; v < 256; v++) {
            uint8_t *row = MDS_T[j][v];
            for (int i = 0; i < 16; i++)
                row[i] = GF[MDS[i][j]][v];
        }

    tables_ready = 1;
    Py_RETURN_NONE;
}

/* ── S-box management ─────────────────────────────────────────────────── */
static PyObject *
story_load_sbox(PyObject *self, PyObject *args)
{
    int            idx;
    const uint8_t *sbox;
    Py_ssize_t     slen;

    if (!PyArg_ParseTuple(args, "iy#", &idx, &sbox, &slen))
        return NULL;
    if (UNLIKELY(slen != 256)) {
        PyErr_SetString(PyExc_ValueError, "S-box must be 256 bytes");
        return NULL;
    }
    if (UNLIKELY(idx < 0 || idx >= SBOX_POOL_MAX)) {
        PyErr_Format(PyExc_ValueError,
                     "S-box index %d out of range [0, %d)", idx, SBOX_POOL_MAX);
        return NULL;
    }
    memcpy(SBOX_POOL[idx], sbox, 256);
    if (idx >= SBOX_COUNT)
        SBOX_COUNT = idx + 1;
    Py_RETURN_NONE;
}

static PyObject *
story_sbox_count(PyObject *self, PyObject *args)
{
    return PyLong_FromLong(SBOX_COUNT);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Round primitives
 * ═══════════════════════════════════════════════════════════════════════════
 */

FORCE_INLINE void
ark(uint8_t state[16], const uint8_t * RESTRICT rk)
{
    for (int i = 0; i < 16; i++)
        state[i] ^= rk[i];
}

/* SubBytes + Permute — single pass */
FORCE_INLINE void
sub_permute(uint8_t       state[16],
            const uint8_t sbox[256],
            const uint8_t perm[16])
{
    uint8_t tmp[16];
    for (int i = 0; i < 16; i++)
        tmp[i] = sbox[state[perm[i]]];
    memcpy(state, tmp, 16);
}

/* Mix — transposed table, inner loop is one cache line per iteration */
FORCE_INLINE void
mix(uint8_t state[16])
{
    uint8_t result[16];
    memset(result, 0, 16);

    for (int j = 0; j < 16; j++) {
        /* Prefetch next row while processing current */
        if (j < 15) PREFETCH(MDS_T[j + 1][state[j + 1]]);
        const uint8_t * RESTRICT row = MDS_T[j][state[j]];
        for (int i = 0; i < 16; i++)
            result[i] ^= row[i];
    }
    memcpy(state, result, 16);
}

/* ── encrypt_block ────────────────────────────────────────────────────── */
FORCE_INLINE void
encrypt_block(const uint8_t  in[16],
              const uint8_t  perm[16],
              const uint8_t  sbox[256],
              const uint8_t * RESTRICT rk_flat,
              int             n_rounds,
              const uint8_t  final_key[16],
              uint8_t        out[16])
{
    uint8_t state[16];
    memcpy(state, in, 16);

    for (int r = 0; r < n_rounds; r++) {
        ark(state, rk_flat + r * 16);
        sub_permute(state, sbox, perm);
        mix(state);
    }
    ark(state, final_key);
    memcpy(out, state, 16);
}

/* ── build_counter_block ─────────────────────────────────────────────── */
FORCE_INLINE void
build_counter_block(const uint8_t nonce[8], uint64_t ctr, uint8_t out[16])
{
    memcpy(out, nonce, 8);
    out[8]  = (uint8_t)(ctr >> 56);
    out[9]  = (uint8_t)(ctr >> 48);
    out[10] = (uint8_t)(ctr >> 40);
    out[11] = (uint8_t)(ctr >> 32);
    out[12] = (uint8_t)(ctr >> 24);
    out[13] = (uint8_t)(ctr >> 16);
    out[14] = (uint8_t)(ctr >>  8);
    out[15] = (uint8_t)(ctr      );
}

/* ── CTR loop — dual-block interleaved ───────────────────────────────────
 * Processes two blocks per iteration. While block A is in the table-lookup
 * phase, block B's ARK (XOR-only) can execute in parallel on the CPU's
 * other execution ports, hiding memory latency.
 * The tail handles the odd block (if data length is not a multiple of 32).
 */
static void
ctr_loop(const uint8_t * RESTRICT data,
         Py_ssize_t                dlen,
         const uint8_t             nonce[8],
         const uint8_t             perm[16],
         const uint8_t             sbox[256],
         const uint8_t * RESTRICT  rk_flat,
         int                       n_rounds,
         const uint8_t             fk[16],
         uint64_t                  ctr,
         uint8_t       * RESTRICT  out)
{
    uint8_t    cb0[16], cb1[16];
    uint8_t    ks0[16], ks1[16];
    Py_ssize_t offset = 0;

    /* ── Dual-block loop (32 bytes per iteration) ── */
    while (offset + 32 <= dlen) {
        build_counter_block(nonce, ctr,     cb0);
        build_counter_block(nonce, ctr + 1, cb1);
        ctr += 2;

        encrypt_block(cb0, perm, sbox, rk_flat, n_rounds, fk, ks0);
        encrypt_block(cb1, perm, sbox, rk_flat, n_rounds, fk, ks1);

        const uint8_t * RESTRICT s0 = data + offset;
        const uint8_t * RESTRICT s1 = data + offset + 16;
        uint8_t       * RESTRICT d0 = out  + offset;
        uint8_t       * RESTRICT d1 = out  + offset + 16;

        for (int k = 0; k < 16; k++) d0[k] = s0[k] ^ ks0[k];
        for (int k = 0; k < 16; k++) d1[k] = s1[k] ^ ks1[k];

        offset += 32;
    }

    /* ── Single-block tail ── */
    while (offset < dlen) {
        Py_ssize_t chunk = dlen - offset;
        uint8_t    cb[16], ks[16];

        build_counter_block(nonce, ctr++, cb);
        encrypt_block(cb, perm, sbox, rk_flat, n_rounds, fk, ks);

        if (chunk >= 16) {
            const uint8_t * RESTRICT src = data + offset;
            uint8_t       * RESTRICT dst = out  + offset;
            for (int k = 0; k < 16; k++) dst[k] = src[k] ^ ks[k];
            offset += 16;
        } else {
            for (Py_ssize_t k = 0; k < chunk; k++)
                out[offset + k] = data[offset + k] ^ ks[k];
            offset += chunk;
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Python-visible functions
 * ═══════════════════════════════════════════════════════════════════════════
 */

static PyObject *
py_story_encrypt_block(PyObject *self, PyObject *args)
{
    const uint8_t *block, *perm, *sbox, *rk_flat, *fk;
    Py_ssize_t     blen, plen, slen, rklen, fklen;

    if (!PyArg_ParseTuple(args, "y#y#y#y#y#",
                          &block,   &blen,
                          &perm,    &plen,
                          &sbox,    &slen,
                          &rk_flat, &rklen,
                          &fk,      &fklen))
        return NULL;

    if (UNLIKELY(!tables_ready))
        return PyErr_Format(PyExc_RuntimeError,
                            "story_core: call story_build_tables() first");
    if (UNLIKELY(blen != 16 || plen != 16 || slen != 256 ||
                 rklen < 16 || rklen % 16 != 0 || fklen != 16))
        return PyErr_Format(PyExc_ValueError,
                            "story_encrypt_block: wrong buffer sizes");

    uint8_t out[16];
    encrypt_block(block, perm, sbox, rk_flat, (int)(rklen / 16), fk, out);
    return PyBytes_FromStringAndSize((const char *)out, 16);
}

static PyObject *
py_story_ctr_crypt(PyObject *self, PyObject *args)
{
    const uint8_t *data, *nonce, *perm, *sbox, *rk_flat, *fk;
    Py_ssize_t     dlen, nlen, plen, slen, rklen, fklen;
    unsigned long long start_ctr = 0;

    if (!PyArg_ParseTuple(args, "y#y#y#y#y#y#|K",
                          &data,    &dlen,
                          &nonce,   &nlen,
                          &perm,    &plen,
                          &sbox,    &slen,
                          &rk_flat, &rklen,
                          &fk,      &fklen,
                          &start_ctr))
        return NULL;

    if (UNLIKELY(!tables_ready))
        return PyErr_Format(PyExc_RuntimeError,
                            "story_core: call story_build_tables() first");
    if (UNLIKELY(nlen != 8 || plen != 16 || slen != 256 ||
                 rklen < 16 || rklen % 16 != 0 || fklen != 16))
        return PyErr_Format(PyExc_ValueError,
                            "story_ctr_crypt: wrong buffer sizes");

    PyObject *result = PyBytes_FromStringAndSize(NULL, dlen);
    if (UNLIKELY(!result)) return NULL;

    ctr_loop(data, dlen, nonce, perm, sbox, rk_flat,
             (int)(rklen / 16), fk, (uint64_t)start_ctr,
             (uint8_t *)PyBytes_AS_STRING(result));
    return result;
}

static PyObject *
py_story_ctr_crypt_idx(PyObject *self, PyObject *args)
{
    const uint8_t *data, *nonce, *perm, *rk_flat, *fk;
    Py_ssize_t     dlen, nlen, plen, rklen, fklen;
    int            sbox_idx;
    unsigned long long start_ctr = 0;

    if (!PyArg_ParseTuple(args, "y#y#y#iy#y#|K",
                          &data,    &dlen,
                          &nonce,   &nlen,
                          &perm,    &plen,
                          &sbox_idx,
                          &rk_flat, &rklen,
                          &fk,      &fklen,
                          &start_ctr))
        return NULL;

    if (UNLIKELY(!tables_ready))
        return PyErr_Format(PyExc_RuntimeError,
                            "story_core: call story_build_tables() first");
    if (UNLIKELY(sbox_idx < 0 || sbox_idx >= SBOX_COUNT))
        return PyErr_Format(PyExc_ValueError,
                            "S-box index %d not loaded (pool: %d)",
                            sbox_idx, SBOX_COUNT);
    if (UNLIKELY(nlen != 8 || plen != 16 ||
                 rklen < 16 || rklen % 16 != 0 || fklen != 16))
        return PyErr_Format(PyExc_ValueError,
                            "story_ctr_crypt_idx: wrong buffer sizes");

    PyObject *result = PyBytes_FromStringAndSize(NULL, dlen);
    if (UNLIKELY(!result)) return NULL;

    ctr_loop(data, dlen, nonce, perm, SBOX_POOL[sbox_idx], rk_flat,
             (int)(rklen / 16), fk, (uint64_t)start_ctr,
             (uint8_t *)PyBytes_AS_STRING(result));
    return result;
}

/* story_select_sbox(stream_bytes, pool_size) -> int
 * Unbiased S-box index selection — mirrors Python _derive_sbox exactly.  */
static PyObject *
py_story_select_sbox(PyObject *self, PyObject *args)
{
    const uint8_t *stream;
    Py_ssize_t     slen;
    int            pool_size;

    if (!PyArg_ParseTuple(args, "y#i", &stream, &slen, &pool_size))
        return NULL;
    if (UNLIKELY(pool_size <= 0))
        return PyErr_Format(PyExc_ValueError, "pool_size must be > 0");
    if (UNLIKELY(slen < 2))
        return PyErr_Format(PyExc_ValueError, "stream must be >= 2 bytes");

    int threshold = 65536 - (65536 % pool_size);
    for (Py_ssize_t pos = 0; pos + 1 < slen; pos += 2) {
        int val = ((int)stream[pos] << 8) | (int)stream[pos + 1];
        if (val < threshold)
            return PyLong_FromLong(val % pool_size);
    }
    PyErr_SetString(PyExc_ValueError, "stream exhausted — extend and retry");
    return NULL;
}

/* ── Method table ─────────────────────────────────────────────────────── */
static PyMethodDef Story128Methods[] = {
    {"story_build_tables",  story_build_tables,     METH_VARARGS,
     "story_build_tables(gf_flat, mds_flat)\n"
     "Build GF and transposed MDS_T tables. Call once at import."},
    {"story_load_sbox",     story_load_sbox,        METH_VARARGS,
     "story_load_sbox(idx, sbox256)\nRegister S-box in C pool."},
    {"story_sbox_count",    story_sbox_count,       METH_NOARGS,
     "story_sbox_count() -> int"},
    {"story_encrypt_block", py_story_encrypt_block, METH_VARARGS,
     "story_encrypt_block(b16,p16,s256,rk,fk16) -> bytes16"},
    {"story_ctr_crypt",     py_story_ctr_crypt,     METH_VARARGS,
     "story_ctr_crypt(data,nonce8,p16,s256,rk,fk16[,ctr]) -> bytes"},
    {"story_ctr_crypt_idx", py_story_ctr_crypt_idx, METH_VARARGS,
     "story_ctr_crypt_idx(data,nonce8,p16,sbox_idx,rk,fk16[,ctr]) -> bytes"},
    {"story_select_sbox",   py_story_select_sbox,   METH_VARARGS,
     "story_select_sbox(stream, pool_size) -> int"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef story128module = {
    PyModuleDef_HEAD_INIT, "story128_c",
    "STORY cipher — optimised C layer.\n"
    "Uses transposed MDS_T[j][v][i] layout for cache-line-aligned mix.\n"
    "Dual-block CTR interleaving for pipeline utilisation.",
    -1, Story128Methods
};

PyMODINIT_FUNC
PyInit_story128_c(void)
{
    return PyModule_Create(&story128module);
}