// And64InlineHook — minimal ARM64 inline hook, header-only
// Handles the most common first-instruction patterns (stack frame setup,
// simple MOV/NOP etc). For ADRP-heavy prologues shadowhook is better,
// but Unity IL2CPP AOT functions almost always start with STP X29,X30,[SP,#-N]!
// which is position-independent and safe to copy verbatim.
//
// Usage:
//   void* orig = nullptr;
//   A64HookFunction(target, hook, &orig);

#pragma once
#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

// Trampoline pool — static so it lives in our .so's data segment (always executable after mprotect)
static uint8_t  _a64_pool[4096] __attribute__((aligned(4096)));
static uint32_t _a64_pool_off = 0;

// Make a memory range RWX
static inline void _a64_mprotect_rwx(void* addr, size_t len) {
    uintptr_t page = (uintptr_t)addr & ~(uintptr_t)(getpagesize()-1);
    mprotect((void*)page, len + getpagesize(), PROT_READ|PROT_WRITE|PROT_EXEC);
}

// ARM64 absolute jump: LDR X16, #8; BR X16; .quad <addr>  — 16 bytes
static inline void _a64_write_jump(void* where, uintptr_t target) {
    uint32_t* p = (uint32_t*)where;
    p[0] = 0x58000050u; // LDR X16, #8
    p[1] = 0xD61F0200u; // BR X16
    *(uintptr_t*)(p+2) = target;
}

// Check if an ARM64 instruction is position-independent (safe to copy to trampoline)
static inline bool _a64_is_safe(uint32_t insn) {
    // ADRP: bits[31:24] = 1001 0000 .. 1001 1111  -> NOT safe
    if ((insn & 0x9F000000u) == 0x90000000u) return false;
    // B / BL unconditional: bits[31:26] = 000101 / 100101 -> NOT safe
    if ((insn & 0xFC000000u) == 0x14000000u) return false; // B
    if ((insn & 0xFC000000u) == 0x94000000u) return false; // BL
    // B.cond: bits[31:24] = 01010100 -> NOT safe
    if ((insn & 0xFF000010u) == 0x54000000u) return false;
    // CBZ/CBNZ: bits[30:25] = 011010 -> NOT safe
    if ((insn & 0x7E000000u) == 0x34000000u) return false;
    // TBZ/TBNZ: bits[30:25] = 011011 -> NOT safe
    if ((insn & 0x7E000000u) == 0x36000000u) return false;
    // LDR (literal): bits[31:27]=00011, bit[26]=x, bits[25:24]=00 -> NOT safe
    if ((insn & 0x3B000000u) == 0x18000000u) return false;
    return true;
}

static bool A64HookFunction(void* target, void* hook, void** orig) {
    uintptr_t tgt = (uintptr_t)target;
    uint32_t* insns = (uint32_t*)tgt;

    // We need 16 bytes (4 instructions) to write the jump patch.
    // Collect safe instructions to copy into trampoline.
    int copy_count = 0;
    uint32_t to_copy[8];
    for (int i = 0; i < 8 && copy_count < 4; i++) {
        uint32_t in = insns[i];
        if (!_a64_is_safe(in)) {
            // Can't safely relocate — bail out
            // (in practice Unity IL2CPP Awake/OnEnable always start with STP which is safe)
            return false;
        }
        to_copy[copy_count++] = in;
    }
    if (copy_count < 4) return false;

    // Allocate trampoline from pool
    if (_a64_pool_off + 64 > sizeof(_a64_pool)) return false;
    uint8_t* tramp = _a64_pool + _a64_pool_off;
    _a64_pool_off += 64;

    // Make pool RWX once
    static bool pool_ready = false;
    if (!pool_ready) {
        _a64_mprotect_rwx(_a64_pool, sizeof(_a64_pool));
        pool_ready = true;
    }

    // Write: copied instructions + jump back to target+16
    memcpy(tramp, to_copy, 16);
    _a64_write_jump(tramp + 16, tgt + 16);
    __builtin___clear_cache((char*)tramp, (char*)tramp + 32);

    if (orig) *orig = tramp;

    // Patch target: write jump to hook
    _a64_mprotect_rwx((void*)tgt, 32);
    _a64_write_jump((void*)tgt, (uintptr_t)hook);
    __builtin___clear_cache((char*)tgt, (char*)(tgt + 16));

    return true;
}
