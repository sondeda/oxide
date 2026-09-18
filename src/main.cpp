#include <sys/types.h>
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

// Function types
using fn_vv = void*(*)();
using fn_vp = void*(*)(void*);
using fn_nm = const char*(*)(void*);
using fn_ta = void*(*)(void*);

static fn_vv g_domain_get    = nullptr;
static fn_vv g_root_domain   = nullptr;
static fn_ta g_thread_attach = nullptr;
static fn_vp g_corlib        = nullptr;
static fn_vp g_asm_image     = nullptr;
static fn_nm g_img_name      = nullptr;

// Find full path to libil2cpp.so from /proc/self/maps
static std::string find_il2cpp_path() {
    std::ifstream f("/proc/self/maps");
    std::string line;
    while (std::getline(f, line)) {
        if (line.find("libil2cpp.so") == std::string::npos) continue;
        if (line.find("r-xp") == std::string::npos) continue;
        auto pos = line.rfind(' ');
        if (pos == std::string::npos) continue;
        std::string path = line.substr(pos + 1);
        // trim newline
        while (!path.empty() && (path.back() == '\n' || path.back() == '\r'))
            path.pop_back();
        return path;
    }
    return "";
}

static bool load_symbols() {
    std::string path = find_il2cpp_path();
    if (path.empty()) { LOGE("il2cpp path not found"); return false; }
    LOGI("path: %s", path.c_str());

    // Open with RTLD_NOLOAD first (already loaded), then with RTLD_NOW|RTLD_GLOBAL
    void* h = dlopen(path.c_str(), RTLD_NOW | RTLD_GLOBAL | RTLD_NODELETE);
    if (!h) {
        LOGE("dlopen failed: %s", dlerror());
        return false;
    }
    LOGI("handle: %p", h);

    g_domain_get    = (fn_vv)dlsym(h, "mono_domain_get");
    g_root_domain   = (fn_vv)dlsym(h, "mono_get_root_domain");
    g_thread_attach = (fn_ta)dlsym(h, "mono_thread_attach");
    g_corlib        = (fn_vp)dlsym(h, "mono_domain_get_corlib");
    g_asm_image     = (fn_vp)dlsym(h, "mono_image_get_assembly");
    g_img_name      = (fn_nm)dlsym(h, "mono_image_get_name");

    LOGI("domain_get=%p root=%p attach=%p corlib=%p",
         (void*)g_domain_get, (void*)g_root_domain,
         (void*)g_thread_attach, (void*)g_corlib);

    if (!g_domain_get && !g_root_domain) {
        LOGE("critical symbols missing");
        return false;
    }
    return true;
}

struct GSList { void* data; void* next; };

static void* find_csharp(void* domain) {
    if (!g_corlib || !g_asm_image || !g_img_name) return nullptr;

    void* corlib = g_corlib(domain);
    LOGI("corlib=%p", corlib);

    // Scan domain for assembly list
    for (int off = 0x40; off <= 0xC0; off += 8) {
        uintptr_t list = 0;
        memcpy(&list, (char*)domain + off, sizeof(list));
        if (list < 0x10000 || list > 0x7fffffffffff) continue;

        uintptr_t data0 = 0;
        memcpy(&data0, (void*)list, sizeof(data0));
        if (data0 < 0x10000) continue;

        void* img0 = g_asm_image((void*)data0);
        if (!img0 || (uintptr_t)img0 < 0x10000) continue;

        // Walk list
        uintptr_t node = list;
        for (int i = 0; i < 256 && node > 0x10000; i++) {
            uintptr_t data = 0, next = 0;
            memcpy(&data, (void*)node,     sizeof(data));
            memcpy(&next, (char*)node + 8, sizeof(next));

            if (data > 0x10000) {
                void* img = g_asm_image((void*)data);
                if (img && (uintptr_t)img > 0x10000) {
                    const char* name = g_img_name(img);
                    if (name && (uintptr_t)name > 0x10000) {
                        LOGI("off=0x%x [%d] %s", off, i, name);
                        if (strstr(name,"Assembly-CSharp") && !strstr(name,"firstpass"))
                            return img;
                    }
                }
            }
            node = next;
        }
    }
    return nullptr;
}

static void cheat_main() {
    prctl(PR_SET_NAME, "UnityGfxDevice");
    sleep(20);
    LOGI("Starting");

    if (!load_symbols()) return;

    void* domain = g_domain_get ? g_domain_get() : nullptr;
    if (!domain && g_root_domain) domain = g_root_domain();
    if (!domain) { LOGE("no domain"); return; }
    LOGI("domain=%p", domain);

    if (g_thread_attach) g_thread_attach(domain);
    LOGI("attached");

    void* img = find_csharp(domain);
    if (!img) { LOGE("Assembly-CSharp not found"); return; }
    LOGI("SUCCESS img=%p", img);

    int tick = 0;
    while (true) {
        sleep(2);
        if (++tick % 10 == 0) LOGI("tick=%d", tick);
    }
}

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
