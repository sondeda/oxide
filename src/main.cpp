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

// ── RVAs from readelf ─────────────────────────────────────────────────────────
#define RVA_domain_get          0x574ae18UL
#define RVA_root_domain         0x574ae14UL
#define RVA_thread_attach       0x574b280UL
#define RVA_assemblies_iter     0x574ae54UL
#define RVA_assembly_get_image  0x574ae0cUL
#define RVA_image_get_name      0x574ae10UL
#define RVA_image_get_entry     0x574adddcUL
#define RVA_class_get_checked   0x574b440UL
#define RVA_class_get_name      0x574b098UL
#define RVA_class_get_namespace 0x574b094UL
#define RVA_class_num_fields    0x574b030UL
#define RVA_field_get_name      0x574b230UL
#define RVA_field_get_offset    0x574b23cUL
#define RVA_field_set_value     0x574b234UL
#define RVA_class_instance_size 0x574b00cUL

// TypeDefIndex from dump: PlayerManager = 9223 → token = 0x02002409
// GenericVitals = 8856 → 0x02002298
// PlayerVitals = 8867 → 0x020022A3
#define TOKEN_PlayerManager     0x02002409U
#define TOKEN_GenericVitals     0x02002298U

// ── function types ────────────────────────────────────────────────────────────
using fn_v_v   = void*(*)();
using fn_v_p   = void*(*)(void*);
using fn_iter  = void*(*)(void*, void**);
using fn_name  = const char*(*)(void*);
using fn_class_checked = void*(*)(void*, uint32_t, int*); // image, token, error
using fn_num_f = int(*)(void*);
using fn_fname = const char*(*)(void*);
using fn_foff  = int(*)(void*);
using fn_fset  = void(*)(void*, void*, void*);
using fn_isize = int(*)(void*);

static uintptr_t g_base = 0;
#define FN(type, rva) ((type)(g_base + (rva)))

// ── Vec3 ──────────────────────────────────────────────────────────────────────
struct Vec3 { float x, y, z; };

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

// ── safe read ─────────────────────────────────────────────────────────────────
template<typename T>
static T rd(uintptr_t addr) {
    if (addr < 0x10000) return T{};
    T v{};
    memcpy(&v, (void*)addr, sizeof(T));
    return v;
}

// ── find Assembly-CSharp ──────────────────────────────────────────────────────
static void* g_image = nullptr;

static void* find_csharp_image(void* domain) {
    auto iter_fn = FN(fn_iter, RVA_assemblies_iter);
    auto img_fn  = FN(fn_v_p,  RVA_assembly_get_image);
    auto name_fn = FN(fn_name, RVA_image_get_name);

    void* iter = nullptr;
    for (int i = 0; i < 512; i++) {
        void* asm_ptr = iter_fn(domain, &iter);
        if (!asm_ptr) break;
        void* img = img_fn(asm_ptr);
        if (!img) continue;
        const char* name = name_fn(img);
        if (!name) continue;
        LOGI("img: %s", name);
        if (strstr(name,"Assembly-CSharp") && !strstr(name,"firstpass"))
            return img;
    }
    return nullptr;
}

// ── find PlayerManager class via token ───────────────────────────────────────
static void* find_class_by_token(void* image, uint32_t token) {
    auto fn = FN(fn_class_checked, RVA_class_get_checked);
    int err = 0;
    void* klass = fn(image, token, &err);
    if (!klass || err) {
        LOGE("class token 0x%x failed err=%d", token, err);
        return nullptr;
    }
    auto name_fn = FN(fn_name, RVA_class_get_name);
    LOGI("class: %s", name_fn(klass));
    return klass;
}

// ── find field offset by name ─────────────────────────────────────────────────
static int find_field_offset(void* klass, const char* fname) {
    auto num_fn  = FN(fn_num_f, RVA_class_num_fields);
    auto name_fn = FN(fn_fname, RVA_field_get_name);
    auto off_fn  = FN(fn_foff,  RVA_field_get_offset);

    // mono_class_get_fields iterator: pass void* iter starting at nullptr
    // We don't have mono_class_get_fields directly — use num_fields + offset walk
    // mono_class stores fields in klass->fields array at known offset
    // In Mono: MonoClassField* fields at klass+0x98 (typical)
    // Each MonoClassField: type(0x0), name(0x8), parent(0x10), offset(0x18)
    struct MonoField { void* type; const char* name; void* parent; int32_t offset; int32_t extra; };

    int num = num_fn(klass);
    LOGI("class has %d fields", num);

    // fields ptr at klass+0x98 in typical Mono layout
    for (int field_off = 0x80; field_off <= 0xC0; field_off += 8) {
        void* fields_ptr = rd<void*>((uintptr_t)klass + field_off);
        if (!fields_ptr || (uintptr_t)fields_ptr < 0x10000) continue;

        for (int i = 0; i < num && i < 200; i++) {
            auto* f = (MonoField*)((uintptr_t)fields_ptr + i * sizeof(MonoField));
            if (!f->name || (uintptr_t)f->name < 0x10000) continue;
            char name_buf[64] = {};
            memcpy(name_buf, f->name, 63);
            if (strcmp(name_buf, fname) == 0) {
                LOGI("field %s offset=0x%x", fname, f->offset);
                return f->offset;
            }
        }
    }
    LOGE("field %s not found", fname);
    return -1;
}

// ── ESP tick ──────────────────────────────────────────────────────────────────
static int g_apl_offset = -1;   // activePlayerList static field offset
static int g_peh_offset = -1;   // playerEventHandler field offset
static int g_vit_offset = -1;   // vitals field offset

static void esp_tick(void* klass_pm) {
    if (g_peh_offset < 0) {
        g_peh_offset = find_field_offset(klass_pm, "playerEventHandler");
        g_vit_offset = find_field_offset(klass_pm, "vitals");
        if (g_peh_offset < 0) return;
    }

    // read activePlayerList static — it's at known offset from the class static data
    // For now log that we're scanning
    LOGI("ESP: peh_off=0x%x vit_off=0x%x", g_peh_offset, g_vit_offset);
}

// ── main cheat thread ─────────────────────────────────────────────────────────
static void cheat_main() {
    sleep(5);
    LOGI("Starting");

    g_base = find_lib_base("libil2cpp.so");
    if (!g_base) { LOGE("base not found"); return; }
    LOGI("base: 0x%lx", g_base);

    void* domain = FN(fn_v_v, RVA_domain_get)();
    if (!domain) domain = FN(fn_v_v, RVA_root_domain)();
    if (!domain) { LOGE("no domain"); return; }
    LOGI("domain: %p", domain);

    FN(fn_v_p, RVA_thread_attach)(domain);
    LOGI("thread attached");

    void* img = find_csharp_image(domain);
    if (!img) { LOGE("image not found"); return; }
    LOGI("Assembly-CSharp: %p", img);

    void* klass_pm = find_class_by_token(img, TOKEN_PlayerManager);
    if (!klass_pm) { LOGE("PlayerManager not found"); return; }
    LOGI("PlayerManager: %p", klass_pm);

    LOGI("SUCCESS — all classes resolved");

    int tick = 0;
    while (true) {
        sleep(1);
        if (++tick % 10 == 0) esp_tick(klass_pm);
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
