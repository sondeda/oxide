#include <sys/types.h>
#include <sys/uio.h>
#include <sys/prctl.h>
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

// ── RVAs verified from readelf ─────────────────────────────────────────────────
// readelf -s libil2cpp.so | grep GLOBAL
#define RVA_domain_get     0x574ae18UL  // mono_domain_get
#define RVA_root_domain    0x574ae14UL  // mono_get_root_domain  
#define RVA_thread_attach  0x574b280UL  // mono_thread_attach
#define RVA_corlib         0x574ae44UL  // mono_domain_get_corlib(domain)
#define RVA_assembly_img   0x574ae0cUL  // mono_image_get_assembly
#define RVA_image_name     0x574ae10UL  // mono_image_get_name

using fn_vv = void*(*)();
using fn_vp = void*(*)(void*);
using fn_nm = const char*(*)(void*);
using fn_ta = void*(*)(void*);

static uintptr_t g_bias = 0;
#define FN(type, rva) ((type)(g_bias + (rva)))

// ── safe read via process_vm_readv (never crashes on bad ptr) ─────────────────
template<typename T>
static bool sr(uintptr_t addr, T& out) {
    if (addr < 0x10000 || addr > 0x7fffffffffff) return false;
    struct iovec l = { &out, sizeof(T) };
    struct iovec r = { (void*)addr, sizeof(T) };
    return process_vm_readv(getpid(), &l, 1, &r, 1, 0) == (ssize_t)sizeof(T);
}

static bool vp(uintptr_t v) { return v > 0x10000 && v < 0x7fffffffffff; }

// ── find load_bias (r-xp segment start - file offset) ────────────────────────
static uintptr_t find_bias(const char* lib) {
    std::ifstream f("/proc/self/maps");
    std::string line;
    while (std::getline(f, line)) {
        if (line.find(lib) == std::string::npos) continue;
        if (line.find("r-xp") == std::string::npos) continue;
        uintptr_t start  = strtoull(line.c_str(), nullptr, 16);
        // offset field is 4th space-separated token
        const char* p = line.c_str();
        for (int i = 0; i < 3; i++) { while (*p && *p != ' ') p++; while (*p == ' ') p++; }
        uintptr_t offset = strtoull(p, nullptr, 16);
        uintptr_t bias   = start - offset;
        LOGI("bias=0x%lx start=0x%lx off=0x%lx", bias, start, offset);
        return bias;
    }
    return 0;
}

struct GSList { void* data; void* next; };

// ── find Assembly-CSharp image ────────────────────────────────────────────────
static void* find_csharp(void* domain) {
    // First verify corlib works — this confirms domain is valid
    auto corlib = FN(fn_vp, RVA_corlib)(domain);
    LOGI("corlib=%p", corlib);
    if (!vp((uintptr_t)corlib)) { LOGE("corlib null"); return nullptr; }

    auto img_fn  = FN(fn_vp, RVA_assembly_img);
    auto name_fn = FN(fn_nm, RVA_image_name);

    // MonoDomain in Unity Mono has loaded_assemblies (GSList*) 
    // Scan offsets 0x40-0xB8 safely
    for (int off = 0x40; off <= 0xB8; off += 8) {
        uintptr_t list = 0;
        if (!sr((uintptr_t)domain + off, list) || !vp(list)) continue;

        // Read first node data to test
        uintptr_t data0 = 0;
        if (!sr(list, data0) || !vp(data0)) continue;

        // Try img_fn on first data — if it returns valid ptr, this is assembly list
        void* img0 = img_fn((void*)data0);
        if (!vp((uintptr_t)img0)) continue;

        // Walk the list
        uintptr_t node = list;
        for (int i = 0; i < 256 && vp(node); i++) {
            uintptr_t data = 0, next = 0;
            if (!sr(node, data) || !sr(node + 8, next)) break;

            if (vp(data)) {
                void* img = img_fn((void*)data);
                if (vp((uintptr_t)img)) {
                    const char* name = name_fn(img);
                    if (name && vp((uintptr_t)name)) {
                        // validate string with safe read
                        char buf[64] = {};
                        uintptr_t nb = (uintptr_t)name;
                        struct iovec l2 = { buf, 63 };
                        struct iovec r2 = { (void*)nb, 63 };
                        if (process_vm_readv(getpid(), &l2, 1, &r2, 1, 0) > 0) {
                            LOGI("off=0x%x [%d] %s", off, i, buf);
                            if (strstr(buf, "Assembly-CSharp") && !strstr(buf, "firstpass"))
                                return img;
                        }
                    }
                }
            }
            node = next;
        }
    }
    LOGE("Assembly-CSharp not found");
    return nullptr;
}

// ── cheat thread ──────────────────────────────────────────────────────────────
static void cheat_main() {
    // Mask thread name to look like Unity internal
    prctl(PR_SET_NAME, "UnityGfxDevice");
    
    sleep(20); // wait for Unity + Mono fully loaded
    LOGI("Starting");

    g_bias = find_bias("libil2cpp.so");
    if (!g_bias) { LOGE("bias not found"); return; }
    LOGI("bias: 0x%lx", g_bias);

    // Get domain
    void* domain = FN(fn_vv, RVA_domain_get)();
    LOGI("domain_get: %p", domain);
    if (!vp((uintptr_t)domain)) {
        domain = FN(fn_vv, RVA_root_domain)();
        LOGI("root_domain: %p", domain);
    }
    if (!vp((uintptr_t)domain)) { LOGE("no domain"); return; }

    // Attach thread to Mono runtime
    FN(fn_ta, RVA_thread_attach)(domain);
    LOGI("thread attached");

    // Find Assembly-CSharp
    void* img = find_csharp(domain);
    if (!img) return;
    LOGI("SUCCESS img=%p", img);

    int tick = 0;
    while (true) {
        sleep(2);
        if (++tick % 10 == 0) LOGI("tick=%d", tick);
    }
}

// ── Zygisk ────────────────────────────────────────────────────────────────────
class OxideModule : public zygisk::ModuleBase {
    zygisk::Api* api_ = nullptr;
    JNIEnv*      env_ = nullptr;
    bool         ok_  = false;
public:
    void onLoad(zygisk::Api* a, JNIEnv* e) override { api_=a; env_=e; }
    void preAppSpecialize(zygisk::AppSpecializeArgs* args) override {
        if (!args->nice_name) { api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY); return; }
        const char* p = env_->GetStringUTFChars(args->nice_name, nullptr);
        if (p) { if (strstr(p,"catsbit")||strstr(p,"oxidesurvival")) ok_=true; env_->ReleaseStringUTFChars(args->nice_name,p); }
        if (!ok_) api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }
    void postAppSpecialize(const zygisk::AppSpecializeArgs*) override {
        if (!ok_) return;
        LOGI("Injected");
        std::thread(cheat_main).detach();
    }
};

REGISTER_ZYGISK_MODULE(OxideModule)
extern "C" __attribute__((visibility("default"))) int zygisk_module_abi_version() { return 4; }
