#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ================= Internal SHA256 (Stage-0 only) ================= */
typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

#define ROTRIGHT(a, b) (((a) >> (b)) | ((a) << (32 - (b))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))
#define EP1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))
#define SIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10))

static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
    0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
    0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4) {
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) |
               ((uint32_t)data[j + 2] << 8) | ((uint32_t)data[j + 3]);
    }
    for (; i < 64; ++i) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

static void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(SHA256_CTX *ctx, uint8_t hash[]) {
    uint32_t i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) {
            ctx->data[i++] = 0x00;
        }
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) {
            ctx->data[i++] = 0x00;
        }
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += (uint64_t)ctx->datalen * 8;
    ctx->data[63] = (uint8_t)(ctx->bitlen);
    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        hash[i] = (uint8_t)((ctx->state[0] >> (24 - i * 8)) & 0x000000ff);
        hash[i + 4] = (uint8_t)((ctx->state[1] >> (24 - i * 8)) & 0x000000ff);
        hash[i + 8] = (uint8_t)((ctx->state[2] >> (24 - i * 8)) & 0x000000ff);
        hash[i + 12] = (uint8_t)((ctx->state[3] >> (24 - i * 8)) & 0x000000ff);
        hash[i + 16] = (uint8_t)((ctx->state[4] >> (24 - i * 8)) & 0x000000ff);
        hash[i + 20] = (uint8_t)((ctx->state[5] >> (24 - i * 8)) & 0x000000ff);
        hash[i + 24] = (uint8_t)((ctx->state[6] >> (24 - i * 8)) & 0x000000ff);
        hash[i + 28] = (uint8_t)((ctx->state[7] >> (24 - i * 8)) & 0x000000ff);
    }
}

/* ================= Embedded source templates ================= */

static const char *sha256_h_content =
    "#ifndef SHA256_H\n"
    "#define SHA256_H\n"
    "\n"
    "#include <stddef.h>\n"
    "#include <stdint.h>\n"
    "\n"
    "typedef struct {\n"
    "    uint8_t data[64];\n"
    "    uint32_t datalen;\n"
    "    uint64_t bitlen;\n"
    "    uint32_t state[8];\n"
    "} SHA256_CTX;\n"
    "\n"
    "void sha256_init(SHA256_CTX *ctx);\n"
    "void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len);\n"
    "void sha256_final(SHA256_CTX *ctx, uint8_t hash[32]);\n"
    "\n"
    "#endif\n";

static const char *sha256_c_content =
    "#include \"sha256.h\"\n"
    "\n"
    "#include <string.h>\n"
    "\n"
    "#define ROTRIGHT(a, b) (((a) >> (b)) | ((a) << (32 - (b))))\n"
    "#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))\n"
    "#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))\n"
    "#define EP0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))\n"
    "#define EP1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))\n"
    "#define SIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))\n"
    "#define SIG1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10))\n"
    "\n"
    "static const uint32_t k[64] = {\n"
    "    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,\n"
    "    0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,\n"
    "    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,\n"
    "    0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,\n"
    "    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,\n"
    "    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,\n"
    "    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,\n"
    "    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,\n"
    "    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,\n"
    "    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,\n"
    "    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,\n"
    "    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,\n"
    "    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,\n"
    "};\n"
    "\n"
    "static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {\n"
    "    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];\n"
    "\n"
    "    for (i = 0, j = 0; i < 16; ++i, j += 4) {\n"
    "        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) |\n"
    "               ((uint32_t)data[j + 2] << 8) | ((uint32_t)data[j + 3]);\n"
    "    }\n"
    "    for (; i < 64; ++i) {\n"
    "        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];\n"
    "    }\n"
    "\n"
    "    a = ctx->state[0];\n"
    "    b = ctx->state[1];\n"
    "    c = ctx->state[2];\n"
    "    d = ctx->state[3];\n"
    "    e = ctx->state[4];\n"
    "    f = ctx->state[5];\n"
    "    g = ctx->state[6];\n"
    "    h = ctx->state[7];\n"
    "\n"
    "    for (i = 0; i < 64; ++i) {\n"
    "        t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];\n"
    "        t2 = EP0(a) + MAJ(a, b, c);\n"
    "        h = g;\n"
    "        g = f;\n"
    "        f = e;\n"
    "        e = d + t1;\n"
    "        d = c;\n"
    "        c = b;\n"
    "        b = a;\n"
    "        a = t1 + t2;\n"
    "    }\n"
    "\n"
    "    ctx->state[0] += a;\n"
    "    ctx->state[1] += b;\n"
    "    ctx->state[2] += c;\n"
    "    ctx->state[3] += d;\n"
    "    ctx->state[4] += e;\n"
    "    ctx->state[5] += f;\n"
    "    ctx->state[6] += g;\n"
    "    ctx->state[7] += h;\n"
    "}\n"
    "\n"
    "void sha256_init(SHA256_CTX *ctx) {\n"
    "    ctx->datalen = 0;\n"
    "    ctx->bitlen = 0;\n"
    "    ctx->state[0] = 0x6a09e667;\n"
    "    ctx->state[1] = 0xbb67ae85;\n"
    "    ctx->state[2] = 0x3c6ef372;\n"
    "    ctx->state[3] = 0xa54ff53a;\n"
    "    ctx->state[4] = 0x510e527f;\n"
    "    ctx->state[5] = 0x9b05688c;\n"
    "    ctx->state[6] = 0x1f83d9ab;\n"
    "    ctx->state[7] = 0x5be0cd19;\n"
    "}\n"
    "\n"
    "void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {\n"
    "    for (size_t i = 0; i < len; ++i) {\n"
    "        ctx->data[ctx->datalen] = data[i];\n"
    "        ctx->datalen++;\n"
    "        if (ctx->datalen == 64) {\n"
    "            sha256_transform(ctx, ctx->data);\n"
    "            ctx->bitlen += 512;\n"
    "            ctx->datalen = 0;\n"
    "        }\n"
    "    }\n"
    "}\n"
    "\n"
    "void sha256_final(SHA256_CTX *ctx, uint8_t hash[]) {\n"
    "    uint32_t i = ctx->datalen;\n"
    "\n"
    "    if (ctx->datalen < 56) {\n"
    "        ctx->data[i++] = 0x80;\n"
    "        while (i < 56) {\n"
    "            ctx->data[i++] = 0x00;\n"
    "        }\n"
    "    } else {\n"
    "        ctx->data[i++] = 0x80;\n"
    "        while (i < 64) {\n"
    "            ctx->data[i++] = 0x00;\n"
    "        }\n"
    "        sha256_transform(ctx, ctx->data);\n"
    "        memset(ctx->data, 0, 56);\n"
    "    }\n"
    "\n"
    "    ctx->bitlen += (uint64_t)ctx->datalen * 8;\n"
    "    ctx->data[63] = (uint8_t)(ctx->bitlen);\n"
    "    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);\n"
    "    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);\n"
    "    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);\n"
    "    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);\n"
    "    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);\n"
    "    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);\n"
    "    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);\n"
    "    sha256_transform(ctx, ctx->data);\n"
    "\n"
    "    for (i = 0; i < 4; ++i) {\n"
    "        hash[i] = (uint8_t)((ctx->state[0] >> (24 - i * 8)) & 0x000000ff);\n"
    "        hash[i + 4] = (uint8_t)((ctx->state[1] >> (24 - i * 8)) & 0x000000ff);\n"
    "        hash[i + 8] = (uint8_t)((ctx->state[2] >> (24 - i * 8)) & 0x000000ff);\n"
    "        hash[i + 12] = (uint8_t)((ctx->state[3] >> (24 - i * 8)) & 0x000000ff);\n"
    "        hash[i + 16] = (uint8_t)((ctx->state[4] >> (24 - i * 8)) & 0x000000ff);\n"
    "        hash[i + 20] = (uint8_t)((ctx->state[5] >> (24 - i * 8)) & 0x000000ff);\n"
    "        hash[i + 24] = (uint8_t)((ctx->state[6] >> (24 - i * 8)) & 0x000000ff);\n"
    "        hash[i + 28] = (uint8_t)((ctx->state[7] >> (24 - i * 8)) & 0x000000ff);\n"
    "    }\n"
    "}\n";

static const char *verifier_template_content =
    "#include \"sha256.h\"\n"
    "\n"
    "#include <stdio.h>\n"
    "#include <stdlib.h>\n"
    "#include <string.h>\n"
    "\n"
    "#define PROJECT_ROOT \"K-UX/\\xCF\\x80 Bootstrap\"\n"
    "#define LAYOUT_MODE \"deterministic\"\n"
    "#define EMBEDDED_COLLAPSE_HASH \"{{COLLAPSE_HASH}}\"\n"
    "\n"
    "static void print_hash(const uint8_t hash[32]) {\n"
    "    for (int i = 0; i < 32; ++i) printf(\"%02x\", hash[i]);\n"
    "}\n"
    "\n"
    "static int hash_file(const char *path, uint8_t hash[32]) {\n"
    "    FILE *f = fopen(path, \"rb\");\n"
    "    if (!f) return -1;\n"
    "\n"
    "    SHA256_CTX ctx;\n"
    "    sha256_init(&ctx);\n"
    "\n"
    "    uint8_t buf[4096];\n"
    "    size_t n = 0;\n"
    "    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {\n"
    "        sha256_update(&ctx, buf, n);\n"
    "    }\n"
    "\n"
    "    if (ferror(f)) {\n"
    "        fclose(f);\n"
    "        return -1;\n"
    "    }\n"
    "\n"
    "    fclose(f);\n"
    "    sha256_final(&ctx, hash);\n"
    "    return 0;\n"
    "}\n"
    "\n"
    "static int compute_project_hash(uint8_t out[32]) {\n"
    "    static const char *files[] = {\n"
    "        \"sha256.h\",\n"
    "        \"sha256.c\",\n"
    "        \"kux_verifier.c\",\n"
    "        \"build.bat\",\n"
    "    };\n"
    "\n"
    "    SHA256_CTX ctx;\n"
    "    sha256_init(&ctx);\n"
    "\n"
    "    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); ++i) {\n"
    "        uint8_t file_hash[32];\n"
    "        if (hash_file(files[i], file_hash) != 0) {\n"
    "            printf(\"FAIL: could not hash %s\\n\", files[i]);\n"
    "            return -1;\n"
    "        }\n"
    "        sha256_update(&ctx, file_hash, sizeof(file_hash));\n"
    "    }\n"
    "\n"
    "    sha256_final(&ctx, out);\n"
    "    return 0;\n"
    "}\n"
    "\n"
    "int main(int argc, char *argv[]) {\n"
    "    if (argc != 4) {\n"
    "        printf(\"Usage: kux_verifier <expected_hash> <mode> <layout>\\n\");\n"
    "        return 1;\n"
    "    }\n"
    "\n"
    "    if (strcmp(argv[2], \"collapse_only\") != 0) {\n"
    "        printf(\"FAIL: mode must be collapse_only, got %s\\n\", argv[2]);\n"
    "        return 1;\n"
    "    }\n"
    "\n"
    "    if (strcmp(argv[3], LAYOUT_MODE) != 0) {\n"
    "        printf(\"FAIL: layout must be %s, got %s\\n\", LAYOUT_MODE, argv[3]);\n"
    "        return 1;\n"
    "    }\n"
    "\n"
    "    uint8_t computed[32];\n"
    "    if (compute_project_hash(computed) != 0) return 1;\n"
    "\n"
    "    char computed_hex[65];\n"
    "    for (int i = 0; i < 32; ++i) sprintf(&computed_hex[i * 2], \"%02x\", computed[i]);\n"
    "    computed_hex[64] = '\\0';\n"
    "\n"
    "    printf(\"PROJECT: %s\\n\", PROJECT_ROOT);\n"
    "    printf(\"MODE: %s\\n\", argv[2]);\n"
    "    printf(\"LAYOUT: %s\\n\", argv[3]);\n"
    "    printf(\"EMBEDDED: %s\\n\", EMBEDDED_COLLAPSE_HASH);\n"
    "    printf(\"COMPUTED: \" );\n"
    "    print_hash(computed);\n"
    "    printf(\"\\n\");\n"
    "\n"
    "    if (strcmp(argv[1], computed_hex) != 0) {\n"
    "        printf(\"FAIL: expected argument does not match computed hash\\n\");\n"
    "        return 1;\n"
    "    }\n"
    "\n"
    "    printf(\"PASS: deterministic projection verified\\n\");\n"
    "    return 0;\n"
    "}\n";

static const char *build_bat_content =
    "@echo off\n"
    "setlocal\n"
    "echo Building K-UX Verifier...\n"
    "gcc -O2 -static -o kux_verifier.exe sha256.c kux_verifier.c\n"
    "if %ERRORLEVEL% NEQ 0 (\n"
    "  echo Build failed\n"
    "  exit /b 1\n"
    ")\n"
    "echo Build complete: kux_verifier.exe\n"
    "endlocal\n";

/* ================= codegen helpers ================= */
static void hash_string(const char *content, uint8_t hash[32]) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)content, strlen(content));
    sha256_final(&ctx, hash);
}

static void print_hash_line(const char *label, const uint8_t hash[32]) {
    printf("%-24s", label);
    for (int i = 0; i < 32; ++i) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

static int write_file(const char *path, const char *content) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        printf("ERROR: unable to write %s\n", path);
        return -1;
    }
    if (fputs(content, f) == EOF) {
        fclose(f);
        printf("ERROR: unable to write bytes to %s\n", path);
        return -1;
    }
    fclose(f);
    printf("  [WRITE] %s (%zu bytes)\n", path, strlen(content));
    return 0;
}

static void compute_template_hash(uint8_t out[32]) {
    SHA256_CTX ctx;
    sha256_init(&ctx);

    uint8_t file_hash[32];

    hash_string(sha256_h_content, file_hash);
    sha256_update(&ctx, file_hash, sizeof(file_hash));

    hash_string(sha256_c_content, file_hash);
    sha256_update(&ctx, file_hash, sizeof(file_hash));

    hash_string(verifier_template_content, file_hash);
    sha256_update(&ctx, file_hash, sizeof(file_hash));

    hash_string(build_bat_content, file_hash);
    sha256_update(&ctx, file_hash, sizeof(file_hash));

    sha256_final(&ctx, out);
}

static void compute_emitted_hash(const char *verifier_content, uint8_t out[32]) {
    SHA256_CTX ctx;
    sha256_init(&ctx);

    uint8_t file_hash[32];

    hash_string(sha256_h_content, file_hash);
    sha256_update(&ctx, file_hash, sizeof(file_hash));

    hash_string(sha256_c_content, file_hash);
    sha256_update(&ctx, file_hash, sizeof(file_hash));

    hash_string(verifier_content, file_hash);
    sha256_update(&ctx, file_hash, sizeof(file_hash));

    hash_string(build_bat_content, file_hash);
    sha256_update(&ctx, file_hash, sizeof(file_hash));

    sha256_final(&ctx, out);
}

static char *render_verifier(const char *template_text, const char *hash_hex) {
    const char *needle = "{{COLLAPSE_HASH}}";
    char *pos = strstr(template_text, needle);
    if (!pos) {
        return NULL;
    }

    size_t prefix_len = (size_t)(pos - template_text);
    size_t suffix_len = strlen(pos + strlen(needle));
    size_t total = prefix_len + strlen(hash_hex) + suffix_len;

    char *out = (char *)malloc(total + 1);
    if (!out) {
        return NULL;
    }

    memcpy(out, template_text, prefix_len);
    memcpy(out + prefix_len, hash_hex, strlen(hash_hex));
    memcpy(out + prefix_len + strlen(hash_hex), pos + strlen(needle), suffix_len);
    out[total] = '\0';
    return out;
}

int main(void) {
    uint8_t template_hash[32];
    compute_template_hash(template_hash);

    char template_hash_hex[65];
    for (int i = 0; i < 32; ++i) {
        sprintf(&template_hash_hex[i * 2], "%02x", template_hash[i]);
    }
    template_hash_hex[64] = '\0';

    char *verifier_content = render_verifier(verifier_template_content, template_hash_hex);
    if (!verifier_content) {
        printf("ERROR: failed to render verifier template\n");
        return 1;
    }

    printf("\n");
    printf("K-UX/\xCF\x80 Bootstrap Stage-0 Generator\n");
    printf("========================================\n");
    printf("Emitting deterministic files:\n");

    if (write_file("sha256.h", sha256_h_content) != 0 ||
        write_file("sha256.c", sha256_c_content) != 0 ||
        write_file("kux_verifier.c", verifier_content) != 0 ||
        write_file("build.bat", build_bat_content) != 0) {
        free(verifier_content);
        return 1;
    }

    printf("\nFile hashes (template set):\n");
    uint8_t h[32];
    hash_string(sha256_h_content, h);
    print_hash_line("sha256.h", h);
    hash_string(sha256_c_content, h);
    print_hash_line("sha256.c", h);
    hash_string(verifier_template_content, h);
    print_hash_line("kux_verifier.c.tmpl", h);
    hash_string(build_bat_content, h);
    print_hash_line("build.bat", h);

    uint8_t emitted_hash[32];
    compute_emitted_hash(verifier_content, emitted_hash);
    char emitted_hash_hex[65];
    for (int i = 0; i < 32; ++i) {
        sprintf(&emitted_hash_hex[i * 2], "%02x", emitted_hash[i]);
    }
    emitted_hash_hex[64] = '\0';

    printf("\nTemplate Merkle Root: %s\n", template_hash_hex);
    printf("Emitted Tree Root:    %s\n", emitted_hash_hex);
    printf("Stage-0 bootstrap complete.\n\n");

    free(verifier_content);
    return 0;
}
