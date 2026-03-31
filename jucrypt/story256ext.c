#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <string.h>

/* ── Cipher constants ────────────────────────────────────────────────────── */

#define ST_BLOCK      32                      /* bytes per block / state     */
#define ST_ROUNDS      5                      /* fixed round count           */
#define ST_RK_BYTES   (ST_ROUNDS * ST_BLOCK)  /* C-FIX-01: 6*32 = 192 bytes */

/* ── Static tables (module-global, initialised once) ────────────────────── */

static uint8_t GF[256][256];                         /* GF(2^8) multiply    */
static uint8_t MDS[ST_BLOCK][ST_BLOCK];              /* C-FIX-02: 32x32     */
static uint8_t MDS_FLAT[ST_BLOCK][ST_BLOCK][256];    /* C-FIX-02: 32x32x256 */
static int     tables_ready = 0;

/* ── Portable big-endian writes ─────────────────────────────────────────── */

static inline void
write_be64(uint8_t *dst, uint64_t v)
{
    dst[0] = (uint8_t)(v >> 56);
    dst[1] = (uint8_t)(v >> 48);
    dst[2] = (uint8_t)(v >> 40);
    dst[3] = (uint8_t)(v >> 32);
    dst[4] = (uint8_t)(v >> 24);
    dst[5] = (uint8_t)(v >> 16);
    dst[6] = (uint8_t)(v >>  8);
    dst[7] = (uint8_t)(v      );
}

/*
 * write_be128: Write a uint64_t counter as a zero-padded 16-byte
 * big-endian integer.  C-FIX-05: matches Python counter.to_bytes(16,'big').
 *
 * The upper 8 bytes are always zero because the counter is uint64_t;
 * in practice this is sufficient for any realistic message length.
 */
static inline void
write_be128(uint8_t *dst, uint64_t v)
{
    /* upper 8 bytes: always zero */
    dst[0] = 0; dst[1] = 0; dst[2] = 0; dst[3] = 0;
    dst[4] = 0; dst[5] = 0; dst[6] = 0; dst[7] = 0;
    /* lower 8 bytes: big-endian counter value */
    write_be64(dst + 8, v);
}

/* ── SPN primitives ──────────────────────────────────────────────────────── */

/*
 * ark_c: AddRoundKey — XOR state with round key in-place.
 */
static inline void
ark_c(uint8_t state[ST_BLOCK], const uint8_t rk[ST_BLOCK])
{
    for (int i = 0; i < ST_BLOCK; i++)
        state[i] ^= rk[i];
}

static inline void
sub_perm_c(uint8_t       state[ST_BLOCK],
           const uint8_t sbox[256],
           const uint8_t perm[ST_BLOCK])
{
    uint8_t out[ST_BLOCK];
    for (int i = 0; i < ST_BLOCK; i++)
        out[i] = sbox[state[perm[i]]];
    memcpy(state, out, ST_BLOCK);
}

/*
 * mix_c: Full-state MDS mix over GF(2^8).
 * C-FIX-02: loops run over ST_BLOCK=32; result buffer is 32 bytes.
 * result[i] = XOR_j( MDS_FLAT[i][j][state[j]] )
 */
static inline void
mix_c(uint8_t state[ST_BLOCK])
{
    uint8_t result[ST_BLOCK];
    for (int i = 0; i < ST_BLOCK; i++) {
        uint8_t acc = 0;
        for (int j = 0; j < ST_BLOCK; j++)
            acc ^= MDS_FLAT[i][j][state[j]];
        result[i] = acc;
    }
    memcpy(state, result, ST_BLOCK);
}

/*
 * encrypt_block_st: Encrypt one ST_BLOCK-byte block.
 *
 * Round structure (identical to st.py._encrypt_block):
 *   for r in 0..ST_ROUNDS-1:
 *     ARK(state, rk[r])
 *     SubBytes+Permute(state)   <- combined in sub_perm_c
 *     Mix(state)
 *   ARK(state, final_key)       <- final whitening
 */
static inline void
encrypt_block_st(const uint8_t  block[ST_BLOCK],
                 const uint8_t  perm[ST_BLOCK],
                 const uint8_t  sbox[256],
                 const uint8_t  rk_flat[ST_RK_BYTES],
                 const uint8_t  final_key[ST_BLOCK],
                 uint8_t        out[ST_BLOCK])
{
    uint8_t state[ST_BLOCK];
    memcpy(state, block, ST_BLOCK);

    for (int r = 0; r < ST_ROUNDS; r++) {
        ark_c(state, rk_flat + r * ST_BLOCK);   /* C-FIX-01/02: stride=32 */
        sub_perm_c(state, sbox, perm);
        mix_c(state);
    }

    /* Final whitening */
    ark_c(state, final_key);
    memcpy(out, state, ST_BLOCK);
}

/* ── Python-callable: st_build_tables ───────────────────────────────────── */

static PyObject *
st_build_tables(PyObject *Py_UNUSED(self), PyObject *args)
{
    const uint8_t *gf_buf, *mds_buf;
    Py_ssize_t     gf_len,  mds_len;

    if (!PyArg_ParseTuple(args, "y#y#",
                          &gf_buf, &gf_len,
                          &mds_buf, &mds_len))
        return NULL;

    if (gf_len != 65536) {
        PyErr_SetString(PyExc_ValueError,
            "st_build_tables: gf_flat must be 65536 bytes (256x256)");
        return NULL;
    }
    /* C-FIX-03: 32x32 MDS matrix = 1024 bytes (was 256 / 16x16) */
    if (mds_len != 1024) {
        PyErr_SetString(PyExc_ValueError,
            "st_build_tables: mds_flat must be 1024 bytes (32x32)");
        return NULL;
    }

    /* Copy GF table */
    for (int a = 0; a < 256; a++)
        for (int b = 0; b < 256; b++)
            GF[a][b] = gf_buf[a * 256 + b];

    /* Copy MDS matrix — C-FIX-02: 32x32 */
    for (int i = 0; i < ST_BLOCK; i++)
        for (int j = 0; j < ST_BLOCK; j++)
            MDS[i][j] = mds_buf[i * ST_BLOCK + j];

    /*
     * Precompute MDS_FLAT[i][j][v] = GF[MDS[i][j]][v].
     * Converts the inner GF multiply in mix_c into a single table lookup.
     */
    for (int i = 0; i < ST_BLOCK; i++)
        for (int j = 0; j < ST_BLOCK; j++)
            for (int v = 0; v < 256; v++)
                MDS_FLAT[i][j][v] = GF[MDS[i][j]][v];

    tables_ready = 1;
    Py_RETURN_NONE;
}

/* ── Python-callable: st_encrypt_block ──────────────────────────────────── */

static PyObject *
st_encrypt_block(PyObject *Py_UNUSED(self), PyObject *args)
{
    const uint8_t *block, *perm, *sbox, *rk_flat, *fk;
    Py_ssize_t     block_len, perm_len, sbox_len, rk_len, fk_len;

    if (!PyArg_ParseTuple(args, "y#y#y#y#y#",
                          &block,   &block_len,
                          &perm,    &perm_len,
                          &sbox,    &sbox_len,
                          &rk_flat, &rk_len,
                          &fk,      &fk_len))
        return NULL;

    if (!tables_ready) {
        PyErr_SetString(PyExc_RuntimeError,
            "st_core: tables not initialised -- call st_build_tables() first");
        return NULL;
    }

    if (block_len != ST_BLOCK  || perm_len != ST_BLOCK  ||
        sbox_len  != 256       || rk_len   != ST_RK_BYTES ||
        fk_len    != ST_BLOCK) {
        PyErr_Format(PyExc_ValueError,
            "st_encrypt_block: expected block=%d, perm=%d, sbox=256, "
            "rk_flat=%d (ST_ROUNDS=%d x %d), fk=%d; "
            "got block=%zd perm=%zd sbox=%zd rk=%zd fk=%zd",
            ST_BLOCK, ST_BLOCK,
            ST_RK_BYTES, ST_ROUNDS, ST_BLOCK, ST_BLOCK,
            block_len, perm_len, sbox_len, rk_len, fk_len);
        return NULL;
    }

    uint8_t out[ST_BLOCK];
    encrypt_block_st(block, perm, sbox, rk_flat, fk, out);
    return PyBytes_FromStringAndSize((const char *)out, ST_BLOCK);
}

/* ── Python-callable: st_ctr_crypt ──────────────────────────────────────── */

static PyObject *
st_ctr_crypt(PyObject *Py_UNUSED(self), PyObject *args)
{
    const uint8_t *data, *nonce, *perm, *sbox, *rk_flat, *fk;
    Py_ssize_t     data_len, nonce_len, perm_len, sbox_len, rk_len, fk_len;

    if (!PyArg_ParseTuple(args, "y#y#y#y#y#y#",
                          &data,    &data_len,
                          &nonce,   &nonce_len,
                          &perm,    &perm_len,
                          &sbox,    &sbox_len,
                          &rk_flat, &rk_len,
                          &fk,      &fk_len))
        return NULL;

    if (!tables_ready) {
        PyErr_SetString(PyExc_RuntimeError,
            "st_core: tables not initialised -- call st_build_tables() first");
        return NULL;
    }

    if (nonce_len != 16       || perm_len != ST_BLOCK  ||
        sbox_len  != 256      || rk_len   != ST_RK_BYTES ||
        fk_len    != ST_BLOCK) {
        PyErr_Format(PyExc_ValueError,
            "st_ctr_crypt: expected nonce=16, perm=%d, sbox=256, "
            "rk_flat=%d, fk=%d; "
            "got nonce=%zd perm=%zd sbox=%zd rk=%zd fk=%zd",
            ST_BLOCK, ST_RK_BYTES, ST_BLOCK,
            nonce_len, perm_len, sbox_len, rk_len, fk_len);
        return NULL;
    }

    /* Allocate output buffer */
    PyObject *result = PyBytes_FromStringAndSize(NULL, data_len);
    if (!result)
        return NULL;
    uint8_t *out = (uint8_t *)PyBytes_AS_STRING(result);


    uint8_t  counter_block[ST_BLOCK];  /* 32 bytes total  */
    uint8_t  keystream[ST_BLOCK];
    uint64_t ctr = 0;

    memcpy(counter_block, nonce, 16);  /* nonce half: 16 bytes, written once */

    Py_ssize_t offset = 0;
    while (offset < data_len) {

        write_be128(counter_block + 16, ctr);
        ctr++;

        encrypt_block_st(counter_block, perm, sbox, rk_flat, fk, keystream);

        /* XOR keystream into output */
        Py_ssize_t chunk = data_len - offset;
        if (chunk > ST_BLOCK) chunk = ST_BLOCK;
        for (Py_ssize_t k = 0; k < chunk; k++)
            out[offset + k] = data[offset + k] ^ keystream[k];
        offset += chunk;
    }

    return result;
}

/* ── Module definition ───────────────────────────────────────────────────── */

static PyMethodDef Story256Methods[] = {
    {
        "st_build_tables",
        st_build_tables,
        METH_VARARGS,
        "st_build_tables(gf_flat, mds_flat) -> None\n"
        "Initialise GF(2^8) and MDS_FLAT tables from Python-side data.\n"
        "Must be called once before any encryption.\n"
        "gf_flat : bytes[65536]   (256x256 GF table, row-major)\n"
        "mds_flat: bytes[1024]    (32x32 MDS matrix, row-major)"  /* C-FIX-07 */
    },
    {
        "st_encrypt_block",
        st_encrypt_block,
        METH_VARARGS,
        "st_encrypt_block(block, perm, sbox, rk_flat, fk) -> bytes[32]\n"  /* C-FIX-07 */
        "Encrypt one 32-byte block with ST_ROUNDS=6 fixed rounds.\n"
        "rk_flat must be exactly 192 bytes (6 x 32)."             /* C-FIX-07 */
    },
    {
        "st_ctr_crypt",
        st_ctr_crypt,
        METH_VARARGS,
        "st_ctr_crypt(data, nonce, perm, sbox, rk_flat, fk) -> bytes\n"
        "CTR-mode encrypt/decrypt. nonce=16 bytes, rk_flat=192 bytes.\n"  /* C-FIX-07 */
        "Returns bytes of same length as data."
    },
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef story256_c_module = {
    PyModuleDef_HEAD_INIT,
    "stroy256_c",                         /* module name                       */
    "STORY-Raw C acceleration layer",  /* docstring                         */
    -1,                                /* per-interpreter state (-1 = none) */
    Story256Methods,
    NULL,                              /* m_slots   (not used)              */
    NULL,                              /* m_traverse                        */
    NULL,                              /* m_clear                           */
    NULL                               /* m_free                            */
};

PyMODINIT_FUNC
PyInit_story256_c(void)
{
    return PyModule_Create(&story256_c_module);
}