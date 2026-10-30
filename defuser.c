#include "defuser.h"

#include <inttypes.h>
#include <stdio.h>

#define MAX_FIELDS 8

/*
 * 把 values 中的 count 个整数写成一行“空格分隔的无符号十进制整数”，存入 out。
 * 成功返回 0；count 为 0（还没有实现）、snprintf 出错或结果被截断时返回非零。
 */
static int write_answer(char *out, size_t cap, const uint32_t *values, size_t count) {
    size_t used = 0;
    for (size_t i = 0; i < count; ++i) {
        int size = snprintf(out + used, cap - used, "%s%" PRIu32, i ? " " : "", values[i]);
        if (size < 0 || (size_t)size >= cap - used) return 1;
        used += (size_t)size;
    }
    return count == 0;
}

/* =====================================================================
 * challenge -> 口令
 *
 * 下面的 helper 由 bomb 的 phase_01..phase_06 反汇编逐条恢复。要点：
 *   * 全程只用 uint32_t 运算，让结果按 2^32 回绕；换成 int/uint64 做
 *     中间量会在高位处悄悄改变结果。
 *   * 右移一律对 uint32_t 做（逻辑右移），不要先提升到有符号类型。
 *   * 各关拿到的是同一个 64 位 challenge，只是取它的不同位段。
 * ===================================================================== */

/* --- 第 1 关：三步线性变换（bomb: p1_compute 0x402050，phase_01 0x402090） --- */
static uint32_t p1_step0(uint32_t a, uint32_t b) { return (a - b) * 5u + 0xb564u; }
static uint32_t p1_step1(uint32_t a, uint32_t b) { return (a * 3u + b) ^ 0x2ec7u; }
static uint32_t p1_step2(uint32_t a, uint32_t b) { return (b + 0x63f2u) ^ a; }

static uint32_t p1_compute(uint64_t ch) {
    uint32_t lo = (uint32_t)ch;
    uint32_t hi = (uint32_t)(ch >> 32);
    uint32_t s1 = p1_step1(hi, (uint32_t)(ch >> 16));
    uint32_t s0 = p1_step0(lo, hi);
    return p1_step2(s0, s1);
}

/* --- 第 2 关：逐项依赖（bomb: phase_02 0x4020f0）
 * f[0] 取 ch 的 17..21 位；f[i] 取 ch 的 (25+4(i-1)).. 起 6 位，并与前一项耦合。 --- */
static uint32_t p2_field(uint64_t ch, unsigned i, uint32_t prev) {
    uint32_t bits = (uint32_t)((ch >> (25 + 4 * (i - 1))) & 0x3fu);
    return (bits + i) ^ (5u * prev);
}

/* --- 第 3 关：跳转表分派（bomb: p3_dispatch 0x402250，表 0x405820，
 *     phase_03 0x4022b0） --- */
static uint32_t p3_case_0(uint32_t x) { return x * 4u ^ 0xf2a9u; }
static uint32_t p3_case_1(uint32_t x) { return x * 3u + 0x4185u; }
static uint32_t p3_case_2(uint32_t x) { return (x ^ 0xdd63u) + (x >> 1); }
static uint32_t p3_case_3(uint32_t x) { return x * 5u + 0xc468u; }
static uint32_t p3_case_4(uint32_t x) { return (x * 2u) ^ 0xa383u; }
static uint32_t p3_case_5(uint32_t x) { return x * 3u + 0xdaa5u; }
static uint32_t p3_case_6(uint32_t x) { return (x ^ 0x12e9u) + (x >> 2); }
static uint32_t p3_case_7(uint32_t x) { return x * 5u + 0x1743fu; }

/* 表序不是 0..7 对应 case_0..case_7，必须照抄原表：
 * 0x405820: case_1, case_0, case_5, case_4, case_2, case_3, case_6, case_7 */
static uint32_t p3_dispatch(uint32_t idx, uint32_t arg) {
    static uint32_t (*const tab[8])(uint32_t) = {
        p3_case_1, p3_case_0, p3_case_5, p3_case_4,
        p3_case_2, p3_case_3, p3_case_6, p3_case_7,
    };
    if (idx > 7) return 0;
    return tab[idx](arg);
}

/* --- 第 4 关：递归二分（bomb: p4_walk 0x402330，phase_04 0x4023a0）
 * 目标 a = ch & 0x7f，在 [0,0x7f] 上二分；命中点返回 (mid+0x13)^rc，
 * 回溯时每层乘 5 再异或 mix 与该层方向常量（下区 0x0a / 上区 0x1d）。 --- */
static uint32_t p4_walk(uint32_t a, uint32_t lo, uint32_t hi, uint32_t rc) {
    uint32_t mid = lo + ((hi - lo) >> 1);

    if (mid == a) return (mid + 0x13u) ^ rc;

    uint32_t mix = mid + rc;
    if (a < mid) return (p4_walk(a, lo, mid - 1, rc) * 5u) ^ mix ^ 0x0au;
    return (p4_walk(a, mid + 1, hi, rc) * 5u) ^ mix ^ 0x1du;
}

/* --- 第 5 关：索引单链表（bomb: p5_traverse 0x402420，表头 0x405b60，
 *     节点 0x405ba0，phase_05 0x402480）
 * 起点 heads[ch & 7]，再沿链多走 (ch>>3)&3 步；累加过程按原码逐站更新。 --- */
static const signed char p5_next[12] = {
    10, -1, 6, 1, 11, 9, 0, 8, 3, 2, 4, 7
};
static const signed char p5_heads[8] = { 5, 9, 2, 6, 0, 10, 4, 11 };

static const uint32_t p5_val[12] = {
    39602, 52032, 38070, 7364, 49848, 45133,
    56605, 29799, 19129, 6983, 4163, 61662,
};
static const uint32_t p5_tag[12] = {
    2606, 1128, 40, 1313, 788, 1879,
    2360, 605, 297, 1619, 2841, 2169,
};

static uint32_t p5_traverse(uint64_t ch, uint32_t *out) {
    int idx = p5_heads[ch & 7];

    uint32_t acc = (((uint32_t)(ch >> 6) ^ (uint32_t)(ch >> 32)) ^ p5_val[idx]) ^ 0xba92u;
    acc += p5_tag[idx];
    *out = p5_tag[idx];

    unsigned hops = (unsigned)((ch >> 3) & 3);
    for (unsigned i = 1; i <= hops; i++) {
        idx = (int)p5_next[idx];
        acc ^= p5_val[idx];
        acc += p5_tag[idx];
        *out = p5_tag[idx];
    }
    return acc;
}

/* --- 第 6 关：两次算子分派（bomb: p6_dispatch 0x402580，表 0x405e00，
 *     phase_06 0x4025d0） --- */
static uint32_t p6_op_0(uint32_t x) { return (x >> 5) | (x << 27); }              /* ror 5 */
static uint32_t p6_op_1(uint32_t x) { return ((x << 3) | (x >> 29)) ^ 0x338au; }  /* rol 3 */
static uint32_t p6_op_2(uint32_t x) { return (x ^ (x >> 3)) + 0x8c7eu; }
static uint32_t p6_op_3(uint32_t x) { return (x + 0x9030u) ^ (x >> 1); }
static uint32_t p6_op_4(uint32_t x) { return (x * 2u + 0x56b9u) ^ (x * 7u); }
static uint32_t p6_op_5(uint32_t x) { return (x ^ 0xe897u) + (x << 7); }

/* 表内 op_1 与 op_5 各出现两次，是原始数据如此。 */
static uint32_t p6_dispatch(uint64_t ch) {
    static uint32_t (*const tab[8])(uint32_t) = {
        p6_op_1, p6_op_0, p6_op_5, p6_op_3,
        p6_op_1, p6_op_4, p6_op_2, p6_op_5,
    };
    uint32_t arg = (uint32_t)(ch >> 6) ^ (uint32_t)(ch >> 32);

    uint32_t v = tab[ch & 7](arg);
    v = tab[(ch & 0x38) >> 3](v ^ 0x6faau);
    return v + 0x72au;
}

/* =====================================================================
 * 六个 solve_phase_*
 *
 * 每关的返回值就是 bomb 在该关等待的那一行输入：字段之间用单个空格分隔，
 * 值为无符号十进制 uint32。字段个数由 bomb 的 valid_u32_fields 决定，
 * 多一个、少一个或混入非数字都会导致引爆。
 * ===================================================================== */

/* 第 1 关（bomb phase_01 0x402090）：1 个字段，即 p1_compute 的三步
 * 线性变换结果。 */
int solve_phase_1(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS];
    values[0] = p1_compute(challenge);
    return write_answer(out, cap, values, 1);
}

/* 第 2 关（bomb phase_02 0x4020f0）：6 个字段。f[0] 取 challenge 的
 * 17..21 位；f[i] 用「challenge 下一段 6 位 + 序号」异或「f[i-1] * 5」，
 * 必须按顺序逐个算，后一项依赖前一项。 */
int solve_phase_2(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS];
    values[0] = ((uint32_t)(challenge >> 17) & 0x1fu) ^ 0x19u;
    for (size_t i = 1; i < 6; ++i)
        values[i] = p2_field(challenge, (unsigned)i, values[i - 1]);
    return write_answer(out, cap, values, 6);
}

/* 第 3 关（bomb phase_03 0x4022b0）：2 个字段。先给分派下标
 * (challenge & 7)，再给该分支作用在 (ch>>32)^(ch>>3) 上的结果。
 * 注意分支序号与 p3_case_* 的对应关系在 p3_dispatch 的表里另有排列。 */
int solve_phase_3(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS];
    values[0] = (uint32_t)(challenge & 7u);
    values[1] = p3_dispatch(values[0], (uint32_t)(challenge >> 32) ^ (uint32_t)(challenge >> 3));
    return write_answer(out, cap, values, 2);
}

/* 第 4 关（bomb phase_04 0x4023a0）：1 个字段。以 (challenge & 0x7f)
 * 为目标在 [0,0x7f] 上二分，命中后沿递归返回路径逐层「乘 5 再异或」，
 * 方向不同异或的常量不同（下区 0x0a，上区 0x1d）。 */
int solve_phase_4(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS];
    values[0] = p4_walk((uint32_t)(challenge & 0x7fu), 0u, 0x7fu,
                        (uint32_t)(challenge >> 7) ^ (uint32_t)(challenge >> 32));
    return write_answer(out, cap, values, 1);
}

/* 第 5 关（bomb phase_05 0x402480，表头 0x405b60 / 节点 0x405ba0）：2 个字段。
 * 从 heads[challenge & 7] 进环，再沿 next 多走 (challenge >> 3) & 3 步；
 * 第一个字段是累加值 acc，第二个是最后访问节点的 tag（p5_traverse）。 */
int solve_phase_5(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS];
    uint32_t tag = 0;
    values[0] = p5_traverse(challenge, &tag);
    values[1] = tag;
    return write_answer(out, cap, values, 2);
}

/* 第 6 关（bomb phase_06 0x4025d0）：1 个字段，即 p6_dispatch 的结果。
 * 两次查表：表项分别由 challenge 的低 3 位和 3..5 位选出，第一次的结果
 * 异或 0x6faa 后再进第二次。 */
int solve_phase_6(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS];
    values[0] = p6_dispatch(challenge);
    return write_answer(out, cap, values, 1);
}

/* =====================================================================
 * 隐藏关（honor / 观测台）
 *
 * 输入布局（bomb: secret_gate 0x402720）：
 *   [0x00..0x20)  32 字节前缀，只用来撑长度，内容不参与校验，但不能含 NUL
 *   [0x20..0x24)  "OPEN"
 *   [0x24..)      3 个十进制数，交给 secret_phase 校验
 * 整行长度必须落在 [36, 163]（strlen-0x24 > 0x7f 直接失败）。
 *
 * 三个数（bomb: secret_phase 0x402640）：
 *   k  = hash & 3
 *   t  = (k * 0x1b74) ^ (uint32)(hash >> 16)
 *   x  = (uint32)(hash >> 32) ^ (uint32)hash        // 来自 transcript 哈希
 *   y  = (uint32)(ch >> 32)   ^ (uint32)ch          // 来自第 7 个 challenge
 *   f1 = secret_mix(x ^ y) ^ t
 *   f2 = f1 ^ (x + k + 0xf74b + (y >> 3))
 * 其中 secret_mix(u) = ((u >> 3) | (u << 29)) ^ 0xec3f。
 * ===================================================================== */

static uint32_t secret_mix(uint32_t x) { return ((x >> 3) | (x << 29)) ^ 0xec3fu; }

/* 拼出整行第七关输入；成功返回 0，容量不足返回非零。 */
int solve_secret(uint64_t challenge, uint64_t context, char *out, size_t cap) {
    /* 32 字节占位前缀；内容任意，只要不含 NUL 就不影响校验。 */
    static const char prefix[] = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

    uint32_t k  = (uint32_t)context & 3u;
    uint32_t t  = (k * 0x1b74u) ^ (uint32_t)(context >> 16);
    uint32_t x  = (uint32_t)(context >> 32) ^ (uint32_t)context;
    uint32_t y  = (uint32_t)(challenge >> 32) ^ (uint32_t)challenge;
    uint32_t f1 = secret_mix(x ^ y) ^ t;
    uint32_t f2 = f1 ^ (x + k + 0xf74bu + (y >> 3));

    int size = snprintf(out, cap, "%sOPEN %" PRIu32 " %" PRIu32 " %" PRIu32,
                        prefix, k, f1, f2);
    if (size < 0 || (size_t)size >= cap) return 1;
    return 0;
}
