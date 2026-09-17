#include <sys/types.h>
#include <sys/stat.h>
#include <jni.h>
#include <android/log.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string>
#include <thread>
#include <fstream>
#include <cstring>
#include <elf.h>
#include <vector>
#include "zygisk.hpp"

#define TAG "OxideCheat"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ── Mono API types (only what's available in this build) ─────────────────────

using fn_domain_get            = void*(*)();
using fn_thread_attach         = void*(*)(void*);
using fn_domain_foreach        = void(*)(void(*)(void*,void*), void*);
using fn_image_get_assembly    = void*(*)(void*);
using fn_image_get_name        = const char*(*)(void*);
using fn_assembly_get_image    = void*(*)(void*);
using fn_class_get_name        = const char*(*)(void*);
using fn_class_get_namespace   = const char*(*)(void*);
using fn_class_get_image       = void*(*)(void*);
using fn_class_num_fields      = int(*)(void*);
using fn_class_get_methods     = void*(*)(void*, void**);
using fn_field_get_name        = const char*(*)(void*);
using fn_field_get_offset      = int(*)(void*);
using fn_field_set_value       = void(*)(void*,void*,void*);
using fn_get_root_domain       = void*(*)();
using fn_image_is_dynamic      = bool(*)(void*);

static fn_domain_get            mono_domain_get_fn;
static fn_thread_attach         mono_thread_attach_fn;
static fn_domain_foreach        mono_domain_foreach_fn;
static fn_image_get_assembly    mono_image_get_assembly_fn;
static fn_image_get_name        mono_image_get_name_fn;
static fn_assembly_get_image    mono_assembly_get_image_fn;
static fn_class_get_name        mono_class_get_name_fn;
static fn_class_get_namespace   mono_class_get_namespace_fn;
static fn_class_get_image       mono_class_get_image_fn;
static fn_class_num_fields      mono_class_num_fields_fn;
static fn_field_get_name        mono_field_get_name_fn;
static fn_field_get_offset      mono_field_get_offset_fn;
static fn_field_set_value       mono_field_set_value_fn;
static fn_get_root_domain       mono_get_root_domain_fn;
static fn_image_is_dynamic      mono_image_is_dynamic_fn;

// ── ELF resolver ─────────────────────────────────────────────────────────────

static uintptr_t find_lib_base(const char* name) {
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        if (line.find(name) == std::string::npos) continue;
        if (line.find("r--p") == std::string::npos &&
            line.find("r-xp") == std::string::npos) continue;
        uintptr_t start = (uintptr_t)strtoull(line.c_str(), nullptr, 16);
        if (*(uint32_t*)start == 0x464C457F) return start;
    }
    return 0;
}

static void* elf_find_symbol(uintptr_t base, const char* sym_name) {
    auto* ehdr = (Elf64_Ehdr*)base;
    if (ehdr->e_ident[0] != 0x7F) return nullptr;

    auto* phdr = (Elf64_Phdr*)(base + ehdr->e_phoff);
    uintptr_t load_bias = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD && phdr[i].p_offset == 0) {
            load_bias = base - phdr[i].p_vaddr;
            break;
        }
    }

    Elf64_Dyn* dyn = nullptr;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = (Elf64_Dyn*)(load_bias + phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return nullptr;

    Elf64_Sym*  symtab = nullptr;
    const char* strtab = nullptr;
    size_t      symcnt = 0;

    for (auto* d = dyn; d->d_tag != DT_NULL; d++) {
        if (d->d_tag == DT_SYMTAB) symtab = (Elf64_Sym*)(load_bias + d->d_un.d_ptr);
        if (d->d_tag == DT_STRTAB) strtab = (const char*)(load_bias + d->d_un.d_ptr);
        if (d->d_tag == DT_HASH) {
            uint32_t* ht = (uint32_t*)(load_bias + d->d_un.d_ptr);
            symcnt = ht[1];
        }
    }

    if (!symtab || !strtab || symcnt == 0) return nullptr;

    for (size_t i = 0; i < symcnt; i++) {
        auto* sym = &symtab[i];
        if (!sym->st_name || !sym->st_value) continue;
        if (strcmp(strtab + sym->st_name, sym_name) == 0)
            return (void*)(load_bias + sym->st_value);
    }
    return nullptr;
}

static uintptr_t g_il2cpp_base = 0;

static bool load_mono() {
    g_il2cpp_base = find_lib_base("libil2cpp.so");
    if (!g_il2cpp_base) { LOGE("libil2cpp.so not found"); return false; }
    LOGI("base: 0x%lx", g_il2cpp_base);

#define SYM(var, name) \
    var = (decltype(var))elf_find_symbol(g_il2cpp_base, name); \
    if (!var) { LOGE("not found: %s", name); return false; } \
    LOGI("OK: %s", name);

    SYM(mono_domain_get_fn,          "mono_domain_get")
    SYM(mono_thread_attach_fn,       "mono_thread_attach")
    SYM(mono_domain_foreach_fn,      "mono_domain_foreach")
    SYM(mono_image_get_name_fn,      "mono_image_get_name")
    SYM(mono_image_get_assembly_fn,  "mono_image_get_assembly")
    SYM(mono_assembly_get_image_fn,  "mono_assembly_get_image")
    SYM(mono_class_get_name_fn,      "mono_class_get_name")
    SYM(mono_class_get_namespace_fn, "mono_class_get_namespace")
    SYM(mono_class_num_fields_fn,    "mono_class_num_fields")
    SYM(mono_field_get_name_fn,      "mono_field_get_name")
    SYM(mono_field_get_offset_fn,    "mono_field_get_offset")
    SYM(mono_field_set_value_fn,     "mono_field_set_value")
    SYM(mono_get_root_domain_fn,     "mono_get_root_domain")
    SYM(mono_image_is_dynamic_fn,    "mono_image_is_dynamic")
#undef SYM

    return true;
}

// ── domain foreach callback ───────────────────────────────────────────────────

static void* g_csharp_image = nullptr;

static void domain_cb(void* domain, void*) {
    if (g_csharp_image) return;
    // domain has a list of assemblies — use mono_domain_get_assemblies_iter
    // Since we don't have it, use domain_foreach trick:
    // Each domain has loaded_assemblies list at known offset
    // Instead, log the domain and try to get image another way
    LOGI("domain: %p", domain);
}

// ── read memory safely ────────────────────────────────────────────────────────

// use mono_domain_get_assemblies_iter via hardcoded RVA from readelf

using fn_assemblies_iter = void*(*)(void*, void**);

static void* find_csharp_image(void* domain) {
    // Try calling mono_domain_get_assemblies_iter via hardcoded RVA
    uintptr_t rva = 0x574ae54;
    auto iter_fn = (fn_assemblies_iter)(g_il2cpp_base + rva);
    
    void* iter = nullptr;
    for (int i = 0; i < 512; i++) {
        void* asm_ptr = iter_fn(domain, &iter);
        if (!asm_ptr) break;
        void* img = mono_assembly_get_image_fn(asm_ptr);
        if (!img) continue;
        const char* name = mono_image_get_name_fn(img);
        LOGI("assembly: %s", name ? name : "null");
        if (name && strstr(name,"Assembly-CSharp") && !strstr(name,"firstpass"))
            return img;
    }
    return nullptr;
}

// ── cheat thread ──────────────────────────────────────────────────────────────

static void cheat_main() {
    sleep(5);
    LOGI("Starting");
    if (!load_mono()) return;

    void* domain = mono_domain_get_fn();
    if (!domain) {
        domain = mono_get_root_domain_fn();
        LOGI("using root domain: %p", domain);
    } else {
        LOGI("domain: %p", domain);
    }

    mono_thread_attach_fn(domain);

    void* img = find_csharp_image(domain);
    if (!img) {
        LOGE("Assembly-CSharp not found");
        return;
    }
    LOGI("Assembly-CSharp found: %p — ESP ready", img);

    // ESP loop — reading players via direct memory offsets from dump
    // activePlayerList static field offset will be added in v0.2
    // For now confirm successful load
    int tick = 0;
    while (true) {
        sleep(1);
        if (tick++ % 5 == 0)
            LOGI("cheat running tick=%d", tick);
    }
}

// ── Zygisk ────────────────────────────────────────────────────────────────────

class OxideModule : public zygisk::ModuleBase {
    zygisk::Api* api_ = nullptr;
    JNIEnv*      env_ = nullptr;
    bool         target_ = false;
public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override { api_=api; env_=env; }

    void preAppSpecialize(zygisk::AppSpecializeArgs* args) override {
        if (!args->nice_name) { api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY); return; }
        const char* pkg = env_->GetStringUTFChars(args->nice_name, nullptr);
        if (pkg) {
            if (strstr(pkg,"catsbit")||strstr(pkg,"oxidesurvival")) target_=true;
            env_->ReleaseStringUTFChars(args->nice_name, pkg);
        }
        if (!target_) api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs*) override {
        if (!target_) return;
        LOGI("Injected — launching cheat");
        std::thread(cheat_main).detach();
    }
};

REGISTER_ZYGISK_MODULE(OxideModule)
extern "C" __attribute__((visibility("default"))) int zygisk_module_abi_version() { return 4; }
