#include <sys/types.h>
#include <jni.h>
#include <android/log.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string>
#include <thread>
#include <fstream>
#include <cstring>
#include "zygisk.hpp"

#define TAG "OxideCheat"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ── Hardcoded RVAs from readelf output ────────────────────────────────────────
// readelf -s libil2cpp.so | grep mono_*
// All offsets verified from device readelf output

#define RVA_mono_domain_get             0x574ae18UL
#define RVA_mono_thread_attach          0x574b280UL
#define RVA_mono_get_root_domain        0x574ae14UL
#define RVA_mono_domain_get_assemblies_iter 0x574ae54UL
#define RVA_mono_assembly_get_image     0x574ae04UL  // mono_image_get_assembly reversed
#define RVA_mono_image_get_name         0x574ae10UL
#define RVA_mono_image_get_assembly     0x574ae0cUL  // mono_image_get_assembly
#define RVA_mono_class_get_name         0x574b098UL
#define RVA_mono_class_num_fields       0x574b030UL
#define RVA_mono_field_get_name         0x574b230UL
#define RVA_mono_field_get_offset       0x574b23cUL
#define RVA_mono_field_set_value        0x574b234UL
#define RVA_mono_image_is_dynamic       0x574ae04UL  // placeholder

// ── find lib base ─────────────────────────────────────────────────────────────

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

// ── function pointers ─────────────────────────────────────────────────────────

using fn_domain_get      = void*(*)();
using fn_thread_attach   = void*(*)(void*);
using fn_assemblies_iter = void*(*)(void*, void**);
using fn_assembly_image  = void*(*)(void*);
using fn_image_name      = const char*(*)(void*);
using fn_field_get_name  = const char*(*)(void*);
using fn_field_get_off   = int(*)(void*);
using fn_field_set       = void(*)(void*,void*,void*);

static uintptr_t g_base = 0;

#define FN(type, rva) ((type)(g_base + rva))

// ── cheat logic ───────────────────────────────────────────────────────────────

static void* find_csharp_image() {
    void* domain = FN(fn_domain_get, RVA_mono_domain_get)();
    if (!domain) domain = FN(fn_domain_get, RVA_mono_get_root_domain)();
    if (!domain) { LOGE("no domain"); return nullptr; }
    LOGI("domain: %p", domain);

    FN(fn_thread_attach, RVA_mono_thread_attach)(domain);

    auto iter_fn = FN(fn_assemblies_iter, RVA_mono_domain_get_assemblies_iter);
    auto img_name_fn = FN(fn_image_name, RVA_mono_image_get_name);
    auto asm_img_fn = FN(fn_assembly_image, RVA_mono_image_get_assembly);

    void* iter = nullptr;
    for (int i = 0; i < 512; i++) {
        void* asm_ptr = iter_fn(domain, &iter);
        if (!asm_ptr) break;
        void* img = asm_img_fn(asm_ptr);
        if (!img) continue;
        const char* name = img_name_fn(img);
        if (!name) continue;
        LOGI("asm: %s", name);
        if (strstr(name,"Assembly-CSharp") && !strstr(name,"firstpass"))
            return img;
    }
    return nullptr;
}

static void cheat_main() {
    sleep(5);
    LOGI("Starting");

    g_base = find_lib_base("libil2cpp.so");
    if (!g_base) { LOGE("base not found"); return; }
    LOGI("base: 0x%lx", g_base);

    // verify mono_domain_get works
    void* domain = FN(fn_domain_get, RVA_mono_domain_get)();
    LOGI("domain_get result: %p", domain);
    if (!domain) {
        domain = FN(fn_domain_get, RVA_mono_get_root_domain)();
        LOGI("root_domain result: %p", domain);
    }
    if (!domain) { LOGE("no domain"); return; }

    FN(fn_thread_attach, RVA_mono_thread_attach)(domain);
    LOGI("thread attached");

    void* img = find_csharp_image();
    if (!img) { LOGE("Assembly-CSharp not found"); return; }
    LOGI("SUCCESS — Assembly-CSharp: %p", img);

    int tick = 0;
    while (true) {
        sleep(2);
        if (++tick % 5 == 0) LOGI("cheat running tick=%d", tick);
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
        LOGI("Injected");
        std::thread(cheat_main).detach();
    }
};

REGISTER_ZYGISK_MODULE(OxideModule)
extern "C" __attribute__((visibility("default"))) int zygisk_module_abi_version() { return 4; }
