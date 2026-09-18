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

using fn_vv = void*(*)();
using fn_vp = void*(*)(void*);
using fn_nm = const char*(*)(void*);
using fn_ta = void*(*)(void*);

static fn_ta g_thread_attach = nullptr;
static fn_vp g_corlib        = nullptr;
static fn_vp g_asm_image     = nullptr;
static fn_nm g_img_name      = nullptr;

static std::string find_il2cpp_path() {
    std::ifstream f("/proc/self/maps");
    std::string line;
    while (std::getline(f, line)) {
        if (line.find("libil2cpp.so") == std::string::npos) continue;
        if (line.find("r-xp") == std::string::npos) continue;
        auto pos = line.rfind(' ');
        if (pos == std::string::npos) continue;
        std::string path = line.substr(pos + 1);
        while (!path.empty() && (path.back() == '\n' || path.back() == '\r'))
            path.pop_back();
        return path;
    }
    return "";
}

// Read domain pointer directly from mono_root_domain global var
// mono_get_root_domain (RVA 0x574ae14, size 4) is:
//   adrp x0, <page>
//   ldr x0, [x0, #offset]  (or similar)
//   ret
// We disassemble it to find where the global var lives
static void* read_root_domain_var(void* h) {
    // Get address of mono_get_root_domain function
    void* fn_ptr = dlsym(h, "mono_get_root_domain");
    if (!fn_ptr) { LOGE("mono_get_root_domain not found"); return nullptr; }
    LOGI("mono_get_root_domain @ %p", fn_ptr);
    
    // Read first 8 bytes (2 ARM64 instructions)
    uint32_t insns[2] = {};
    memcpy(insns, fn_ptr, 8);
    LOGI("insn0=0x%08x insn1=0x%08x", insns[0], insns[1]);
    
    // Follow B (branch) instruction if present
    uintptr_t cur = (uintptr_t)fn_ptr;
    for (int depth = 0; depth < 32; depth++) {
        uint32_t in0 = 0, in1 = 0;
        memcpy(&in0, (void*)cur, 4);
        memcpy(&in1, (void*)(cur+4), 4);
        LOGI("depth=%d @ 0x%lx insn0=0x%08x insn1=0x%08x", depth, cur, in0, in1);

        // B unconditional: 0x14000000 mask
        if ((in0 & 0xFC000000) == 0x14000000) {
            int32_t imm26 = (int32_t)(in0 << 6) >> 6;
            cur = cur + (int64_t)imm26 * 4;
            LOGI("B -> 0x%lx", cur);
            continue;
        }
        // BL: 0x94000000 — skip
        if ((in0 & 0xFC000000) == 0x94000000) {
            cur += 4; continue;
        }
        // LDR Xn, label (0x58000000)
        if ((in0 & 0xFF000000) == 0x58000000) {
            int32_t imm19 = (int32_t)(in0 << 8) >> 13;  // bits[23:5], *4
            uintptr_t var_addr = cur + (int64_t)imm19 * 4;
            LOGI("LDR literal: var=0x%lx", var_addr);
            void* domain = nullptr;
            memcpy(&domain, (void*)var_addr, 8);
            return domain;
        }
        // ADRP (0x90000000)
        if ((in0 & 0x9F000000) == 0x90000000) {
            int64_t immhi = (int32_t)(in0 & 0x00FFFFE0) >> 3;
            int64_t immlo = (in0 >> 29) & 3;
            uintptr_t page = (cur & ~0xFFFULL) + ((immhi | immlo) << 12);
            // next: LDR Xm, [Xn, #imm12*8]
            uint32_t imm12 = (in1 >> 10) & 0xFFF;
            uintptr_t var_addr = page + (uintptr_t)imm12 * 8;
            LOGI("ADRP+LDR: page=0x%lx imm12=%d var=0x%lx", page, imm12, var_addr);
            void* domain = nullptr;
            memcpy(&domain, (void*)var_addr, 8);
            return domain;
        }
        // RET
        if (in0 == 0xD65F03C0) { LOGE("RET without finding var"); return nullptr; }
        // Skip unknown instructions (prologue, STP, MOV etc) — scan forward
        LOGI("skip insn 0x%08x @ 0x%lx", in0, cur);
        cur += 4;
        continue;
    }
    LOGE("too many branches");
    return nullptr;
}

static void* find_csharp(void* domain) {
    if (!g_corlib || !g_asm_image || !g_img_name) return nullptr;

    void* corlib = g_corlib(domain);
    LOGI("corlib=%p", corlib);
    if (!corlib || (uintptr_t)corlib < 0x10000) return nullptr;

    for (int off = 0x40; off <= 0xC0; off += 8) {
        uintptr_t list = 0;
        if ((uintptr_t)domain + off < 0x10000) continue;
        memcpy(&list, (char*)domain + off, sizeof(list));
        if (list < 0x10000 || list > 0x7fffffffffff) continue;

        uintptr_t data0 = 0;
        memcpy(&data0, (void*)list, sizeof(data0));
        if (data0 < 0x10000) continue;

        void* img0 = g_asm_image((void*)data0);
        if (!img0 || (uintptr_t)img0 < 0x10000) continue;

        uintptr_t node = list;
        for (int i = 0; i < 256 && node > 0x10000; i++) {
            uintptr_t data = 0, next = 0;
            memcpy(&data, (void*)node,     8);
            memcpy(&next, (char*)node + 8, 8);
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
    sleep(25);
    LOGI("Starting");

    std::string path = find_il2cpp_path();
    if (path.empty()) { LOGE("path not found"); return; }
    LOGI("path: %s", path.c_str());

    void* h = dlopen(path.c_str(), RTLD_NOW | RTLD_GLOBAL | RTLD_NODELETE);
    if (!h) { LOGE("dlopen: %s", dlerror()); return; }

    g_thread_attach = (fn_ta)dlsym(h, "mono_thread_attach");
    g_corlib        = (fn_vp)dlsym(h, "mono_domain_get_corlib");
    g_asm_image     = (fn_vp)dlsym(h, "mono_image_get_assembly");
    g_img_name      = (fn_nm)dlsym(h, "mono_image_get_name");

    LOGI("attach=%p corlib=%p asm=%p name=%p",
         (void*)g_thread_attach, (void*)g_corlib,
         (void*)g_asm_image, (void*)g_img_name);

    // Find var addr once, then poll it
    uintptr_t domain_var_addr = 0;
    {
        // temp call to get the var address
        // we modify read_root_domain_var to also store the addr
    }
    
    // Use mono_domain_get RVA directly - this worked before (returned 0x7990cbafc0)
    // RVA 0x574ae18 verified from readelf
    // Calculate actual address: attach addr - attach_rva + domain_rva  
    uintptr_t attach_addr = (uintptr_t)g_thread_attach;
    uintptr_t domain_get_addr = attach_addr - 0x574b280UL + 0x574ae18UL;
    LOGI("domain_get_addr=0x%lx", domain_get_addr);
    
    // Read domain directly from memory at domain_get function
    // mono_domain_get is 4 bytes - read what instruction is there
    uint32_t insn = 0;
    memcpy(&insn, (void*)domain_get_addr, 4);
    LOGI("domain_get insn=0x%08x", insn);
    
    // Read 32 bytes around domain_get to find global var
    uint8_t buf[32] = {};
    memcpy(buf, (void*)domain_get_addr, 32);
    LOGI("bytes: %02x %02x %02x %02x %02x %02x %02x %02x",
         buf[0],buf[1],buf[2],buf[3],buf[4],buf[5],buf[6],buf[7]);
    
    // For now just run stable loop
    void* domain = nullptr;
    LOGI("stable — no crash");
    
    int tick = 0;
    while (true) {
        sleep(5);
        if (++tick % 6 == 0) LOGI("stable tick=%d", tick);
    }

    if (g_thread_attach) g_thread_attach(domain);
    LOGI("attached");

    void* img = find_csharp(domain);
    if (!img) { LOGE("Assembly-CSharp not found"); return; }
    LOGI("SUCCESS img=%p", img);

    
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
