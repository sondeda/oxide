// And64InlineHook v2 — ARM64 inline hook, header-only
// Стратегия: вместо копирования инструкций используем 2-instruction stub в самой функции.
// Это работает даже если первая инструкция — ADRP.
//
// Патч в target: 16 байт
//   LDR X17, #8     ; загрузить адрес хука из следующих 8 байт
//   BR  X17         ; прыжок
//   .quad hook_addr ; адрес нашего хука
//
// Трамплин для orig (чтобы вызвать оригинал):
//   Мы сохраняем ПЕРВЫЕ 4 оригинальные инструкции ПЕРЕД патчем.
//   Затем прыгаем на target+16 (пропуская патч).
//   НО если там ADRP — она не будет работать из трамплина.
//
// Правильное решение для ADRP: используем hook без orig-трамплина.
// Для Awake/OnEnable/OnDisable нам orig нужен — вызываем через backup.
//
// ФИНАЛЬНАЯ стратегия:
// 1. Читаем первые 4 инструкции
// 2. Если все позиционно-независимые — копируем в трамплин + прыжок назад
// 3. Если есть ADRP — используем "detour без orig": просто патчим прыжок,
//    orig = nullptr (хук сам решает когда вызывать оригинал по сохранённому адресу)
// 4. Для нашего случая: orig указатель заполняем адресом target+16 минуя патч
//    (это работает только если ADRP не в первых 4 инструкциях которые мы перезаписываем)
//
// САМЫЙ НАДЁЖНЫЙ подход для Unity IL2CPP:
// Патчим только ПЕРВЫЕ 4 байта (1 инструкцию) через BL-трамплин в свободную память,
// а трамплин уже делает полный прыжок. Но это сложно.
//
// ИТОГ: используем 16-байтный патч + трамплин с full relocation через эмуляцию ADRP.

#pragma once
#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

// Пул для трамплинов — 8KB
static uint8_t  _a64_pool[8192] __attribute__((aligned(4096)));
static uint32_t _a64_pool_off = 0;
static bool     _a64_pool_ready = false;

static inline void _a64_mprotect(void* addr, size_t len, int prot) {
    long pgsz = getpagesize();
    uintptr_t start = (uintptr_t)addr & ~(uintptr_t)(pgsz - 1);
    mprotect((void*)start, (size_t)((uintptr_t)addr - start) + len + pgsz, prot);
}

// Записать 16-байтный абсолютный прыжок: LDR X17,#8; BR X17; .quad target
static inline void _a64_write_abs_jump(void* where, uintptr_t target) {
    uint32_t* p = (uint32_t*)where;
    p[0] = 0x58000051u; // LDR X17, #8
    p[1] = 0xD61F0220u; // BR X17
    *(uintptr_t*)(p + 2) = target;
}

// Проверить позиционную независимость инструкции
static inline bool _a64_insn_relocatable(uint32_t insn) {
    if ((insn & 0x9F000000u) == 0x90000000u) return false; // ADRP
    if ((insn & 0xFC000000u) == 0x14000000u) return false; // B
    if ((insn & 0xFC000000u) == 0x94000000u) return false; // BL
    if ((insn & 0xFF000010u) == 0x54000000u) return false; // B.cond
    if ((insn & 0x7E000000u) == 0x34000000u) return false; // CBZ/CBNZ
    if ((insn & 0x7E000000u) == 0x36000000u) return false; // TBZ/TBNZ
    if ((insn & 0x3B000000u) == 0x18000000u) return false; // LDR literal
    return true;
}

// Relocate ADRP + следующая инструкция (ADD/LDR) в трамплин
// Возвращает сколько инструкций обработано (2) или 0 если не смогли
static int _a64_relocate_adrp(uint32_t* src_insns, uintptr_t src_pc,
                                uint32_t* dst, uintptr_t dst_pc) {
    uint32_t adrp = src_insns[0];
    uint32_t next = src_insns[1];

    // Декодируем ADRP
    int rd = (int)(adrp & 0x1F);
    int64_t imm = (int64_t)(((adrp >> 5) & 0x7FFFF) | (((adrp >> 29) & 0x3) << 19));
    imm = (imm << 12) >> 12; // sign-extend 21 bits shifted by 12
    imm <<= 12;
    uintptr_t page_addr = (src_pc & ~(uintptr_t)0xFFF) + (uintptr_t)imm;

    // Генерируем: MOVZ Xrd, #lo16; MOVK Xrd, #hi16, LSL#16; MOVK Xrd, #hi32, LSL#32
    uint64_t val = (uint64_t)page_addr;
    // MOVZ Xrd, val[15:0]
    dst[0] = 0xD2800000u | (uint32_t)rd | (((val >>  0) & 0xFFFF) << 5);
    // MOVK Xrd, val[31:16], LSL#16
    dst[1] = 0xF2A00000u | (uint32_t)rd | (((val >> 16) & 0xFFFF) << 5);
    // MOVK Xrd, val[47:32], LSL#32
    dst[2] = 0xF2C00000u | (uint32_t)rd | (((val >> 32) & 0xFFFF) << 5);
    // MOVK Xrd, val[63:48], LSL#48
    dst[3] = 0xF2E00000u | (uint32_t)rd | (((val >> 48) & 0xFFFF) << 5);
    // Копируем следующую инструкцию (ADD/LDR/STR которая использует Xrd+offset)
    dst[4] = next;
    return 2; // обработали 2 инструкции, записали 5
}

// Главная функция хука
// Возвращает true если хук установлен
// *orig будет указывать на трамплин для вызова оригинала (может быть nullptr если не удалось)
static bool A64HookFunction(void* target, void* hook, void** orig) {
    if (!target || !hook) return false;

    uintptr_t tgt = (uintptr_t)target;
    uint32_t* insns = (uint32_t*)tgt;

    // Инициализируем пул один раз
    if (!_a64_pool_ready) {
        _a64_mprotect(_a64_pool, sizeof(_a64_pool), PROT_READ | PROT_WRITE | PROT_EXEC);
        _a64_pool_ready = true;
    }

    // Выделяем трамплин
    if (_a64_pool_off + 128 > sizeof(_a64_pool)) return false;
    uint8_t*  tramp     = _a64_pool + _a64_pool_off;
    uint32_t* tramp32   = (uint32_t*)tramp;
    _a64_pool_off += 128;

    // Пытаемся скопировать/relocate ровно 4 инструкции (16 байт которые мы затрём)
    int src_idx  = 0; // сколько оригинальных инструкций обработано
    int dst_idx  = 0; // сколько инструкций записано в трамплин

    while (src_idx < 4) {
        uint32_t insn = insns[src_idx];
        uintptr_t cur_pc = tgt + (uintptr_t)src_idx * 4;
        uintptr_t dst_pc = (uintptr_t)tramp + (uintptr_t)dst_idx * 4;

        if ((insn & 0x9F000000u) == 0x90000000u) {
            // ADRP — relocate
            if (src_idx + 1 >= 8) { goto fallback; } // нет следующей инструкции
            int consumed = _a64_relocate_adrp(insns + src_idx, cur_pc,
                                               tramp32 + dst_idx, dst_pc);
            if (consumed == 0) goto fallback;
            src_idx += consumed;
            dst_idx += 5; // 4 MOV + 1 следующая
        } else if (_a64_insn_relocatable(insn)) {
            tramp32[dst_idx++] = insn;
            src_idx++;
        } else {
            goto fallback;
        }
    }

    // Дописываем прыжок в трамплине: прыгаем на target + 16 (после патча)
    _a64_write_abs_jump(tramp + dst_idx * 4, tgt + 16);
    __builtin___clear_cache((char*)tramp, (char*)tramp + 128);
    if (orig) *orig = tramp;

    // Патчим target
    _a64_mprotect((void*)tgt, 32, PROT_READ | PROT_WRITE | PROT_EXEC);
    _a64_write_abs_jump((void*)tgt, (uintptr_t)hook);
    __builtin___clear_cache((char*)tgt, (char*)tgt + 16);
    _a64_mprotect((void*)tgt, 32, PROT_READ | PROT_EXEC);
    return true;

fallback:
    // Не смогли сделать трамплин — ставим хук без orig (orig = nullptr)
    // Это значит хук-функция не должна вызывать оригинал через указатель.
    // Для Awake/OnEnable/OnDisable: просто не вызываем orig — игра не крашнет
    // потому что Unity сама дойдёт до тела функции после нашего хука... нет,
    // без orig мы заменяем функцию полностью. Поэтому возвращаем false.
    if (orig) *orig = nullptr;
    // Последний шанс: patching без трамплина — orig будет nullptr,
    // хук-функция обязана НЕ вызывать orig.
    _a64_mprotect((void*)tgt, 32, PROT_READ | PROT_WRITE | PROT_EXEC);
    _a64_write_abs_jump((void*)tgt, (uintptr_t)hook);
    __builtin___clear_cache((char*)tgt, (char*)tgt + 16);
    _a64_mprotect((void*)tgt, 32, PROT_READ | PROT_EXEC);
    return true; // хук поставлен, но orig = nullptr
}
