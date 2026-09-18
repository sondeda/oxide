// And64InlineHook v4 — без ручного ARM64 asm, без трамплинов
// Стратегия: храним оригинальные байты и вызываем оригинал через
// временный unmap/remap. Orig-указатель это просто структура с callback.
// Для вызова оригинала из хука используем глобальный массив.
//
// КАК РАБОТАЕТ:
// - A64HookFunction(target, hook, &orig_fn_ptr)
// - orig_fn_ptr = специальная функция-обёртка которая:
//     1. снимает патч с target (восстанавливает оригинальные байты)
//     2. вызывает target напрямую
//     3. возвращает патч обратно
// - Всё через C++ function pointers — никакого ручного ASM

#pragma once
#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>

#define A64_MAX_HOOKS 8

struct _A64Entry {
    uint8_t* target;
    uint8_t  orig[16];
    uint8_t  patch[16];
    pthread_mutex_t mtx;
    bool active;
};

static _A64Entry _a64_tbl[A64_MAX_HOOKS];
static int       _a64_cnt = 0;

static void _a64_protect(void* p, int prot) {
    uintptr_t pg = (uintptr_t)p & ~(uintptr_t)(getpagesize()-1);
    mprotect((void*)pg, (size_t)getpagesize() * 2, prot);
}

// Вызов оригинальной функции по индексу
// Используется как: ((fn_t)_a64_call_orig)(idx, __this, method)
// idx передаётся через глобальную переменную перед вызовом (см. ниже)
// 
// Нет — проще: делаем 8 отдельных C++ функций, по одной на каждый хук.
// Каждая знает свой индекс через замыкание.

typedef void(*_a64_void_fn)(void*, void*);

static void _a64_call(int idx, void* a, void* b) {
    _A64Entry& e = _a64_tbl[idx];
    pthread_mutex_lock(&e.mtx);
    _a64_protect(e.target, PROT_READ|PROT_WRITE|PROT_EXEC);
    memcpy(e.target, e.orig, 16);
    __builtin___clear_cache((char*)e.target, (char*)e.target+16);
    ((_a64_void_fn)e.target)(a, b);
    memcpy(e.target, e.patch, 16);
    __builtin___clear_cache((char*)e.target, (char*)e.target+16);
    _a64_protect(e.target, PROT_READ|PROT_EXEC);
    pthread_mutex_unlock(&e.mtx);
}

// 8 статических обёрток — каждая для своего слота
static void _a64_orig0(void* a,void* b){_a64_call(0,a,b);}
static void _a64_orig1(void* a,void* b){_a64_call(1,a,b);}
static void _a64_orig2(void* a,void* b){_a64_call(2,a,b);}
static void _a64_orig3(void* a,void* b){_a64_call(3,a,b);}
static void _a64_orig4(void* a,void* b){_a64_call(4,a,b);}
static void _a64_orig5(void* a,void* b){_a64_call(5,a,b);}
static void _a64_orig6(void* a,void* b){_a64_call(6,a,b);}
static void _a64_orig7(void* a,void* b){_a64_call(7,a,b);}

static _a64_void_fn _a64_origs[A64_MAX_HOOKS] = {
    _a64_orig0,_a64_orig1,_a64_orig2,_a64_orig3,
    _a64_orig4,_a64_orig5,_a64_orig6,_a64_orig7
};

static bool A64HookFunction(void* target, void* hook, void** orig) {
    if (!target || !hook) return false;
    if (_a64_cnt >= A64_MAX_HOOKS) return false;

    int idx = _a64_cnt++;
    _A64Entry& e = _a64_tbl[idx];
    e.target = (uint8_t*)target;
    e.active = true;
    pthread_mutex_init(&e.mtx, nullptr);

    // сохраняем оригинальные 16 байт
    memcpy(e.orig, target, 16);

    // строим патч: LDR X17, #8; BR X17; .quad hook
    uint32_t* p = (uint32_t*)e.patch;
    p[0] = 0x58000051u; // LDR X17, #8
    p[1] = 0xD61F0220u; // BR X17
    *(uint64_t*)(p+2) = (uint64_t)(uintptr_t)hook;

    // ставим патч
    _a64_protect(target, PROT_READ|PROT_WRITE|PROT_EXEC);
    memcpy(target, e.patch, 16);
    __builtin___clear_cache((char*)target, (char*)target+16);
    _a64_protect(target, PROT_READ|PROT_EXEC);

    // orig указывает на статическую обёртку
    if (orig) *orig = (void*)_a64_origs[idx];

    return true;
}
