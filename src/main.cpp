#include <sys/types.h>
#include <sys/uio.h>
#include <jni.h>
#include <android/log.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string>
#include <thread>
#include <fstream>
#include <cstring>
#include <signal.h>
#include <setjmp.h>
#include "zygisk.hpp"

#define TAG "OxideCheat"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ── RVAs from readelf ─────────────────────────────────────────────────────────
#define RVA_domain_get      0x574ae18UL
#define RVA_root_domain     0x574ae14UL
#define RVA_thread_attach   0x574b280UL
#define RVA_corlib          0x574ae44UL
#define RVA_assembly_image  0x574ae0cUL
#define RVA_image_name      0x574ae10UL
#define RVA_class_checked   0x574b440UL
#define RVA_class_name      0x574b098UL
#define RVA_class_namespace 0x574b094UL
#define RVA_num_fields      0x574b030UL
#define RVA_field_name      0x574b230UL
#define RVA_field_offset    0x574b23cUL
#define RVA_field_set       0x574b234UL

using fn_vv   = void*(*)();
using fn_vp   = void*(*)(void*);
using fn_name = const char*(*)(void*);
using fn_cc   = void*(*)(void*, uint32_t, int*);
using fn_nf   = int(*)(void*);
using fn_fn   = const char*(*)(void*);
using fn_fo   = int(*)(void*);
using fn_fs   = void(*)(void*,void*,void*);
using fn_ta   = void*(*)(void*);

static uintptr_t g_base = 0;
#define FN(type, rva) ((type)(g_base + (rva)))

// ── safe memory read via process_vm_readv ─────────────────────────────────────
template<typename T>
static bool safe_read(uintptr_t addr, T& out) {
    if (addr < 0x10000 || addr > 0x7fffffffffff) return false;
    struct iovec local  = { &out,    sizeof(T) };
    struct iovec remote = { (void*)addr, sizeof(T) };
    return process_vm_readv(getpid(), &local, 1, &remote, 1, 0) == (ssize_t)sizeof(T);
}

// ── find lib base ─────────────────────────────────────────────────────────────
static uintptr_t find_lib_base(const char* name) {
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        if (line.find(name) == std::string::npos) continue;
        if (line.find("r--p") == std::string::npos &&
            line.find("r-xp") == std::string::npos) continue;
        uintptr_t start = (uintptr_t)strtoull(line.c_str(), nullptr, 16);
        uint32_t magic = 0;
        if (safe_read(start, magic) && magic == 0x464C457F) return start;
    }
    return 0;
}

// ── valid pointer check ───────────────────────────────────────────────────────
static bool vptr(uintptr_t v) {
    return v > 0x10000 && v < 0x7fffffffffff;
}

// ── valid string check ────────────────────────────────────────────────────────
static bool valid_str(uintptr_t addr) {
    if (!vptr(addr)) return false;
    char buf[128];
    struct iovec l = { buf, 128 };
    struct iovec r = { (void*)addr, 128 };
    if (process_vm_readv(getpid(), &l, 1, &r, 1, 0) <= 0) return false;
    for (int i = 0; i < 127; i++) {
        if (buf[i] == 0) return i > 0;
        if ((unsigned char)buf[i] > 127) return false;
    }
    return false;
}

struct GSList { void* data; GSList* next; };

// ── find Assembly-CSharp ──────────────────────────────────────────────────────
static void* find_csharp_image(void* domain) {
    auto img_fn  = FN(fn_vp,   RVA_assembly_image);
    auto name_fn = FN(fn_name, RVA_image_name);

    // Try corlib to confirm domain works
    auto corlib_fn = FN(fn_vv, RVA_corlib);
    void* corlib = corlib_fn();
    LOGI("corlib: %p", corlib);

    // Scan domain offsets 0x40..0xC0 for GSList of assemblies
    for (int off = 0x40; off <= 0xC0; off += 8) {
        uintptr_t list_addr = 0;
        if (!safe_read((uintptr_t)domain + off, list_addr)) continue;
        if (!vptr(list_addr)) continue;

        // Check if this looks like a GSList by reading first node
        uintptr_t first_data = 0;
        if (!safe_read(list_addr, first_data)) continue;
        if (!vptr(first_data)) continue;

        // Try calling img_fn on first_data
        void* test_img = img_fn((void*)first_data);
        uintptr_t test_img_v = (uintptr_t)test_img;
        if (!vptr(test_img_v)) continue;

        // Looks like a valid assembly list — walk it
        uintptr_t node_addr = list_addr;
        for (int i = 0; i < 128; i++) {
            uintptr_t data = 0, next = 0;
            if (!safe_read(node_addr, data)) break;
            if (!safe_read(node_addr + 8, next)) break;
            if (!vptr(data)) { if (!vptr(next)) break; node_addr = next; continue; }

            void* img = img_fn((void*)data);
            if (!img || !vptr((uintptr_t)img)) { node_addr = next; continue; }

            uintptr_t name_ptr = 0;
            if (!safe_read((uintptr_t)img + 0x10, name_ptr) || !valid_str(name_ptr)) {
                // try calling name_fn
                const char* name = name_fn(img);
                if (name && valid_str((uintptr_t)name)) {
                    LOGI("off=0x%x [%d] %s", off, i, name);
                    if (strstr(name,"Assembly-CSharp") && !strstr(name,"firstpass"))
                        return img;
                }
                node_addr = next;
                continue;
            }

            LOGI("off=0x%x [%d] ptr=0x%lx", off, i, name_ptr);
            node_addr = next;
            if (!vptr(next)) break;
        }
    }
    LOGE("Assembly-CSharp not found");
    return nullptr;
}

// ── main thread ───────────────────────────────────────────────────────────────
static void cheat_main() {
    sleep(15);
    LOGI("Starting");

    g_base = find_lib_base("libil2cpp.so");
    if (!g_base) { LOGE("base not found"); return; }
    LOGI("base: 0x%lx", g_base);

    void* domain = FN(fn_vv, RVA_domain_get)();
    if (!domain) domain = FN(fn_vv, RVA_root_domain)();
    if (!domain) { LOGE("no domain"); return; }
    LOGI("domain: %p", domain);

    FN(fn_ta, RVA_thread_attach)(domain);
    LOGI("thread attached");

    void* img = find_csharp_image(domain);
    if (!img) { LOGE("image not found"); return; }
    LOGI("SUCCESS Assembly-CSharp: %p", img);

    int tick = 0;
    while (true) {
        sleep(2);
        if (++tick % 5 == 0) LOGI("running tick=%d", tick);
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
