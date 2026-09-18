// And64InlineHook v3 — ARM64, header-only
// Стратегия "restore-call-repatch":
// 1. Сохраняем оригинальные 16 байт функции
// 2. Пишем наш jump патч
// 3. orig = специальный трамплин который:
//    a) убирает патч (восстанавливает оригинальные байты)
//    b) вызывает оригинальную функцию
//    c) ставит патч обратно
// Это работает с ЛЮБЫМИ инструкциями включая ADRP.
// Недостаток: не thread-safe при одновременных вызовах.
// Для Unity single-thread lifecycle методов (Awake/OnEnable/OnDisable) — ОК.

#pragma once
#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

struct A64HookEntry {
    void*   target;
    uint8_t orig_bytes[16];   // оригинальные инструкции
    uint8_t patch_bytes[16];  // наш jump патч
    bool    patched;
};

static A64HookEntry _a64_entries[16];
static int          _a64_entry_count = 0;

// Трамплин-функции (по одной на каждый хук, до 8 штук)
// Каждый трамплин: снимает патч → вызывает orig → ставит патч обратно
// Генерируем их динамически в пуле

static uint8_t  _a64_pool[4096] __attribute__((aligned(4096)));
static uint32_t _a64_pool_off = 0;
static bool     _a64_pool_ready = false;

static inline void _a64_mprotect(void* addr, size_t len, int prot) {
    long pgsz = getpagesize();
    uintptr_t start = (uintptr_t)addr & ~(uintptr_t)(pgsz - 1);
    mprotect((void*)start, (size_t)((uintptr_t)addr - start) + len + (size_t)pgsz, prot);
}

static inline void _a64_write_abs_jump(void* where, uintptr_t target_addr) {
    uint32_t* p = (uint32_t*)where;
    p[0] = 0x58000051u; // LDR X17, #8
    p[1] = 0xD61F0220u; // BR X17
    *(uintptr_t*)(p + 2) = target_addr;
}

// C-функция которую вызывает каждый трамплин
// Снимает патч, вызывает оригинал, ставит патч обратно
// entry_idx — индекс в _a64_entries
extern "C" void _a64_restore_call(int entry_idx, void* __this, void* method) {
    A64HookEntry& e = _a64_entries[entry_idx];
    // снять патч
    _a64_mprotect(e.target, 16, PROT_READ | PROT_WRITE | PROT_EXEC);
    memcpy(e.target, e.orig_bytes, 16);
    __builtin___clear_cache((char*)e.target, (char*)e.target + 16);
    // вызвать оригинал
    using fn_t = void(*)(void*, void*);
    ((fn_t)e.target)(__this, method);
    // поставить патч обратно
    memcpy(e.target, e.patch_bytes, 16);
    __builtin___clear_cache((char*)e.target, (char*)e.target + 16);
    _a64_mprotect(e.target, 16, PROT_READ | PROT_EXEC);
}

// Трамплин-stub для каждого хука (ARM64 asm)
// Вызывает _a64_restore_call(idx, x0, x1)
// x0 и x1 уже содержат __this и method (первые два аргумента функции)
static void* _a64_make_trampoline(int idx) {
    if (!_a64_pool_ready) {
        _a64_mprotect(_a64_pool, sizeof(_a64_pool), PROT_READ | PROT_WRITE | PROT_EXEC);
        _a64_pool_ready = true;
    }
    if (_a64_pool_off + 64 > sizeof(_a64_pool)) return nullptr;
    uint32_t* t = (uint32_t*)(_a64_pool + _a64_pool_off);
    _a64_pool_off += 64;

    // ARM64:
    // STP X0, X1, [SP, #-32]!   ; сохраняем x0 (this) и x1 (method)
    // STP X29, X30, [SP, #16]   ; сохраняем fp и lr
    // MOV W0, #idx              ; первый аргумент = idx
    // LDP X1, X2, [SP]          ; восстанавливаем __this в x1, method в x2
    //   (но _a64_restore_call принимает int, void*, void*)
    // нет, проще:
    // сохраняем x0,x1,x29,x30
    // x2 = x1 (method), x1 = x0 (__this), x0 = idx
    // вызываем _a64_restore_call
    // восстанавливаем x29,x30
    // RET

    // STP X29, X30, [SP, #-32]!
    t[0]  = 0xA9BE7BFDU;
    // STP X0, X1, [SP, #16]
    t[1]  = 0xA9010FE0U;
    // MOV X2, X1  (method → x2)
    t[2]  = 0xAA0103E2U;
    // MOV X1, X0  (__this → x1)
    t[3]  = 0xAA0003E1U;
    // MOV W0, #idx
    t[4]  = 0x52800000U | ((uint32_t)(idx & 0xFFFF) << 5);
    // LDR X16, #24  (загружаем адрес _a64_restore_call из literal pool)
    t[5]  = 0x58000190U;
    // BLR X16
    t[6]  = 0xD63F0200U;
    // LDP X0, X1, [SP, #16]  (не нужно восстанавливать x0/x1 — void return)
    // LDP X29, X30, [SP], #32
    t[7]  = 0xA8C27BFDU;
    // RET
    t[8]  = 0xD65F03C0U;
    // literal: адрес _a64_restore_call (8 байт)
    *(uintptr_t*)(t + 9) = (uintptr_t)_a64_restore_call;

    __builtin___clear_cache((char*)t, (char*)t + 64);
    return (void*)t;
}

static bool A64HookFunction(void* target, void* hook, void** orig) {
    if (!target || !hook) return false;
    if (_a64_entry_count >= 16) return false;

    int idx = _a64_entry_count++;
    A64HookEntry& e = _a64_entries[idx];
    e.target  = target;
    e.patched = false;

    // сохраняем оригинальные 16 байт
    memcpy(e.orig_bytes, target, 16);

    // строим патч (jump к hook)
    _a64_write_abs_jump(e.patch_bytes, (uintptr_t)hook);

    // ставим патч
    _a64_mprotect(target, 16, PROT_READ | PROT_WRITE | PROT_EXEC);
    memcpy(target, e.patch_bytes, 16);
    __builtin___clear_cache((char*)target, (char*)target + 16);
    _a64_mprotect(target, 16, PROT_READ | PROT_EXEC);
    e.patched = true;

    // создаём трамплин для вызова оригинала
    if (orig) {
        void* tramp = _a64_make_trampoline(idx);
        *orig = tramp;
    }

    return true;
}
