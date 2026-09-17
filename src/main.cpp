#include <sys/types.h>
#include <sys/stat.h>
#include <jni.h>
#include <android/log.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string>
#include <thread>
#include <cstring>
#include "zygisk.hpp"

#define TAG "OxideCheat"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

using fn_domain_get            = void*(*)();
using fn_thread_attach         = void*(*)(void*);
using fn_class_from_name       = void*(*)(void*,const char*,const char*);
using fn_field_from_name       = void*(*)(void*,const char*);
using fn_field_static_get      = void(*)(void*,void*);
using fn_field_get             = void(*)(void*,void*,void*);
using fn_assembly_get_image    = void*(*)(void*);
using fn_domain_get_assemblies = void*(*)(void*,size_t*);
using fn_image_get_name        = const char*(*)(void*);

static fn_domain_get            il2cpp_domain_get;
static fn_thread_attach         il2cpp_thread_attach;
static fn_class_from_name       il2cpp_class_from_name;
static fn_field_from_name       il2cpp_class_get_field_from_name;
static fn_field_static_get      il2cpp_field_static_get_value;
static fn_field_get             il2cpp_field_get_value;
static fn_assembly_get_image    il2cpp_assembly_get_image;
static fn_domain_get_assemblies il2cpp_domain_get_assemblies;
static fn_image_get_name        il2cpp_image_get_name;

struct Vec3 { float x,y,z; };

template<typename T> struct Il2CppArray {
    void* klass; void* monitor; void* bounds; uint64_t max_length; T m_Items[1];
};
template<typename T> struct Il2CppList {
    void* klass; void* monitor; Il2CppArray<T>* items; int32_t size; int32_t version;
};

static bool load_il2cpp() {
    void* h = dlopen("/data/app/~~_NthGXSYS_U0l4s9w1s57g==/com.catsbit.oxidesurvivalisland-bT7-xLtSAW6BuiuElJXNMw==/lib/arm64/libil2cpp.so", RTLD_NOW|RTLD_NOLOAD);
    if (!h) h = dlopen("/data/app/~~_NthGXSYS_U0l4s9w1s57g==/com.catsbit.oxidesurvivalisland-bT7-xLtSAW6BuiuElJXNMw==/lib/arm64/libil2cpp.so", RTLD_NOW);
    if (!h) { LOGE("dlopen failed: %s", dlerror()); return false; }
#define SYM(fn,name) fn=(decltype(fn))dlsym(h,name); if(!fn){LOGE("dlsym %s failed",name);return false;}
    SYM(il2cpp_domain_get,"il2cpp_domain_get")
    SYM(il2cpp_thread_attach,"il2cpp_thread_attach")
    SYM(il2cpp_class_from_name,"il2cpp_class_from_name")
    SYM(il2cpp_class_get_field_from_name,"il2cpp_class_get_field_from_name")
    SYM(il2cpp_field_static_get_value,"il2cpp_field_static_get_value")
    SYM(il2cpp_field_get_value,"il2cpp_field_get_value")
    SYM(il2cpp_assembly_get_image,"il2cpp_assembly_get_image")
    SYM(il2cpp_domain_get_assemblies,"il2cpp_domain_get_assemblies")
    SYM(il2cpp_image_get_name,"il2cpp_image_get_name")
#undef SYM
    return true;
}

static void* find_image(void* domain) {
    size_t count=0;
    void** assemblies=(void**)il2cpp_domain_get_assemblies(domain,&count);
    if(!assemblies) return nullptr;
    for(size_t i=0;i<count;i++){
        void* img=il2cpp_assembly_get_image(assemblies[i]);
        if(!img) continue;
        const char* name=il2cpp_image_get_name(img);
        if(name && strstr(name,"Assembly-CSharp.dll") && !strstr(name,"firstpass"))
            return img;
    }
    return nullptr;
}

static void esp_tick(void* img) {
    static void* klass_pm=nullptr;
    static void* f_apl=nullptr;
    static void* f_vitals=nullptr;
    static void* f_peh=nullptr;
    static bool resolved=false;

    if(!resolved){
        klass_pm=il2cpp_class_from_name(img,"","PlayerManager");
        if(!klass_pm) return;
        f_apl    =il2cpp_class_get_field_from_name(klass_pm,"activePlayerList");
        f_vitals =il2cpp_class_get_field_from_name(klass_pm,"vitals");
        f_peh    =il2cpp_class_get_field_from_name(klass_pm,"playerEventHandler");
        if(!f_apl) return;
        resolved=true;
        LOGI("ESP ready");
    }

    void* mb=nullptr;
    il2cpp_field_static_get_value(f_apl,&mb);
    if(!mb) return;

    auto* list=*(Il2CppList<void*>**)((uintptr_t)mb+0x10);
    if(!list||!list->items) return;
    int count=(int)list->size;
    if(count<=0||count>64) return;

    for(int i=0;i<count;i++){
        void* pm=list->items->m_Items[i];
        if(!pm) continue;
        Vec3 pos{};
        if(f_peh){
            void* peh=nullptr;
            il2cpp_field_get_value(pm,f_peh,&peh);
            if(peh){
                void* tr=*(void**)((uintptr_t)peh+0x10);
                if(tr) pos=*(Vec3*)((uintptr_t)tr+0x90);
            }
        }
        float hp=0.f;
        if(f_vitals){
            void* v=nullptr;
            il2cpp_field_get_value(pm,f_vitals,&v);
            if(v){
                void* hg=*(void**)((uintptr_t)v+0x98);
                if(hg) hp=*(float*)((uintptr_t)hg+0x18);
            }
        }
        __android_log_print(ANDROID_LOG_INFO,"OxideESP",
            "[%d] pos=(%.1f,%.1f,%.1f) hp=%.0f",i,pos.x,pos.y,pos.z,hp);
    }
}

static void cheat_main(){
    sleep(5);
    LOGI("Starting");
    if(!load_il2cpp()) return;
    void* domain=il2cpp_domain_get();
    if(!domain) return;
    il2cpp_thread_attach(domain);
    void* img=find_image(domain);
    if(!img){ LOGE("Assembly-CSharp not found"); return; }
    LOGI("IL2CPP ready — loop start");
    while(true){ sleep(1); esp_tick(img); }
}

class OxideModule : public zygisk::ModuleBase {
    zygisk::Api* api_=nullptr;
    JNIEnv* env_=nullptr;
    bool target_=false;
public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override { api_=api; env_=env; }

    void preAppSpecialize(zygisk::AppSpecializeArgs* args) override {
        if(!args->nice_name){ api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY); return; }
        const char* pkg=env_->GetStringUTFChars(args->nice_name,nullptr);
        if(pkg){
            if(strstr(pkg,"catsbit")||strstr(pkg,"oxidesurvival")) target_=true;
            env_->ReleaseStringUTFChars(args->nice_name,pkg);
        }
        if(!target_) api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs*) override {
        if(!target_) return;
        LOGI("Injected — launching cheat");
        std::thread(cheat_main).detach();
    }
};

REGISTER_ZYGISK_MODULE(OxideModule)

extern "C" __attribute__((visibility("default"))) int zygisk_module_abi_version() { return 4; }
