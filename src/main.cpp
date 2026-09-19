// BobaDLC External — Oxide Survival Island
// Author: Lotusor
// Рендер: Android SurfaceFlinger overlay через /dev/graphics/fb0 fallback
// или через JNI Canvas overlay
// Хуки: And64InlineHook (pure C++)

#include <jni.h>
#include <android/log.h>
#include <android/native_window.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string>
#include <thread>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cmath>
#include <mutex>
#include <vector>
#include <algorithm>
#include <atomic>
#include <sys/stat.h>
#include <linux/input.h>
#include <dirent.h>
#include <fcntl.h>
#include <EGL/egl.h>
#include <GLES2/gl2.h>
#include "zygisk.hpp"
#include "And64InlineHook.hpp"

#define TAG  "LotusorCheat"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ── RVAs из дампа ────────────────────────────────────────────────────────────
static constexpr uintptr_t RVA_PM_Awake    = 0x6685fd4UL;
static constexpr uintptr_t RVA_PM_OnEnable = 0x66730a8UL;
static constexpr uintptr_t RVA_PM_OnDis    = 0x667bd7cUL;

// ── Офсеты полей PlayerManager ───────────────────────────────────────────────
static constexpr uintptr_t OFF_PM_peh  = 0x78;   // Gum* playerEventHandler
static constexpr uintptr_t OFF_GuB_Nm  = 0x88;   // Il2CppString* DisplayName
static constexpr uintptr_t OFF_GuB_HP  = 0x98;   // Gun<float>* Health
static constexpr uintptr_t OFF_GUN_Val = 0x18;   // float current value
static constexpr uintptr_t OFF_PM_Pos  = 0x1C8;  // Vector3 lastTickPosition

struct Vec3 { float x, y, z; };

// ── Базовый адрес ─────────────────────────────────────────────────────────────
static uintptr_t g_base = 0;

static uintptr_t find_base(const char* lib) {
    std::ifstream f("/proc/self/maps");
    std::string line;
    while (std::getline(f, line)) {
        if (line.find(lib) == std::string::npos) continue;
        if (line.find("r--p") == std::string::npos &&
            line.find("r-xp") == std::string::npos) continue;
        if (line.find("00000000") == std::string::npos) continue;
        uintptr_t addr = (uintptr_t)strtoull(line.c_str(), nullptr, 16);
        if (*(uint32_t*)addr == 0x464C457F) return addr;
    }
    return 0;
}

static inline void* rva(uintptr_t off) { return (void*)(g_base + off); }

// ── Игроки ───────────────────────────────────────────────────────────────────
static std::mutex        g_mtx;
static std::vector<void*> g_players;
static void*             g_local = nullptr;
static std::atomic<bool> g_ok{false};

static void add_player(void* pm) {
    std::lock_guard<std::mutex> lk(g_mtx);
    for (auto p : g_players) if (p == pm) return;
    g_players.push_back(pm);
    LOGI("player+ %p total=%zu", pm, g_players.size());
}
static void del_player(void* pm) {
    std::lock_guard<std::mutex> lk(g_mtx);
    g_players.erase(std::remove(g_players.begin(), g_players.end(), pm), g_players.end());
    if (g_local == pm) g_local = nullptr;
}

static std::string read_str(void* p) {
    if (!p || (uintptr_t)p < 0x1000) return "";
    int32_t len = *(int32_t*)((uintptr_t)p + 0x10);
    if (len <= 0 || len > 64) return "";
    const uint16_t* ch = (const uint16_t*)((uintptr_t)p + 0x14);
    std::string s; s.reserve(len);
    for (int i = 0; i < len; i++) s += (ch[i] < 128) ? (char)ch[i] : '?';
    return s;
}

static float read_hp(void* pm) {
    if (!pm) return 0;
    void* peh = *(void**)((uintptr_t)pm + OFF_PM_peh);
    if ((uintptr_t)peh < 0x1000) return 0;
    void* gun = *(void**)((uintptr_t)peh + OFF_GuB_HP);
    if ((uintptr_t)gun < 0x1000) return 0;
    float v = *(float*)((uintptr_t)gun + OFF_GUN_Val);
    return (v >= 0 && v <= 1000) ? v : 0;
}

static std::string read_name(void* pm) {
    if (!pm) return "Player";
    void* peh = *(void**)((uintptr_t)pm + OFF_PM_peh);
    if ((uintptr_t)peh < 0x1000) return "Player";
    void* ns = *(void**)((uintptr_t)peh + OFF_GuB_Nm);
    std::string n = read_str(ns);
    return n.empty() ? "Player" : n;
}

// ── Меню состояние ────────────────────────────────────────────────────────────
static std::atomic<bool> g_menu_vis{false};
static bool g_esp_on    = true;
static bool g_box_on    = true;
static bool g_hp_on     = true;
static bool g_name_on   = true;
static int  g_tab       = 1; // 0=Aimbot 1=Visuals 2=Misc 3=Skins

// ── Хуки PlayerManager ────────────────────────────────────────────────────────
using fn_pm = void(*)(void*, void*);
static fn_pm g_orig_aw = nullptr, g_orig_en = nullptr, g_orig_dis = nullptr;

static void hook_Awake(void* th, void* m) {
    if (g_orig_aw) g_orig_aw(th, m);
    LOGI("Awake HIT this=%p", th);
    static bool first = true;
    if (first) { g_local = th; first = false; g_ok = true; }
    add_player(th);
}
static void hook_OnEnable(void* th, void* m) {
    if (g_orig_en) g_orig_en(th, m);
    add_player(th);
}
static void hook_OnDisable(void* th, void* m) {
    if (g_orig_dis) g_orig_dis(th, m);
    del_player(th);
}

// ── EGL/GL рендер ─────────────────────────────────────────────────────────────
static GLuint g_prog = 0, g_vbo = 0;
static GLint  g_uloc_res = -1, g_uloc_col = -1;
static GLint  g_aloc_pos = -1;
static int    g_sw = 1080, g_sh = 1920;
static bool   g_gl_ok = false;

static const char* kVS =
    "attribute vec2 p;\nuniform vec2 r;\n"
    "void main(){vec2 q=p/r*2.-1.;gl_Position=vec4(q.x,-q.y,0,1);}\n";
static const char* kFS =
    "precision mediump float;\nuniform vec4 c;\nvoid main(){gl_FragColor=c;}\n";

static bool gl_init() {
    auto mk = [](GLenum t, const char* s) {
        GLuint x = glCreateShader(t);
        glShaderSource(x, 1, &s, nullptr);
        glCompileShader(x); return x;
    };
    g_prog = glCreateProgram();
    glAttachShader(g_prog, mk(GL_VERTEX_SHADER, kVS));
    glAttachShader(g_prog, mk(GL_FRAGMENT_SHADER, kFS));
    glLinkProgram(g_prog);
    g_uloc_res = glGetUniformLocation(g_prog, "r");
    g_uloc_col = glGetUniformLocation(g_prog, "c");
    g_aloc_pos = glGetAttribLocation(g_prog,  "p");
    GLint ok = 0; glGetProgramiv(g_prog, GL_LINK_STATUS, &ok);
    LOGI("GL link=%d res=%d col=%d pos=%d", ok, g_uloc_res, g_uloc_col, g_aloc_pos);
    return ok == GL_TRUE;
}

static void col(float r,float g,float b,float a){ glUniform4f(g_uloc_col,r,g,b,a); }
static void quad(float x,float y,float w,float h,bool fill,float r,float g,float b,float a){
    col(r,g,b,a);
    float v[] = {x,y, x+w,y, x+w,y+h, x,y+h};
    glVertexAttribPointer(g_aloc_pos,2,GL_FLOAT,GL_FALSE,0,v);
    glEnableVertexAttribArray(g_aloc_pos);
    glDrawArrays(fill?GL_TRIANGLE_FAN:GL_LINE_LOOP,0,4);
}
static void line(float x1,float y1,float x2,float y2,float r,float g,float b,float a){
    col(r,g,b,a);
    float v[]={x1,y1,x2,y2};
    glVertexAttribPointer(g_aloc_pos,2,GL_FLOAT,GL_FALSE,0,v);
    glEnableVertexAttribArray(g_aloc_pos);
    glDrawArrays(GL_LINES,0,2);
}

// ── 5×7 bitmap font ───────────────────────────────────────────────────────────
static const uint8_t kFont[95][5]={
{0,0,0,0,0},{0,0,95,0,0},{0,7,0,7,0},{20,127,20,127,20},{36,42,127,42,18},
{35,19,8,100,98},{54,73,85,34,80},{0,5,3,0,0},{0,28,34,65,0},{0,65,34,28,0},
{20,8,62,8,20},{8,8,62,8,8},{0,80,48,0,0},{8,8,8,8,8},{0,96,96,0,0},
{32,16,8,4,2},{62,81,73,69,62},{0,66,127,64,0},{66,97,81,73,70},{33,65,69,75,49},
{24,20,18,127,16},{39,69,69,69,57},{60,74,73,73,48},{1,113,9,5,3},
{54,73,73,73,54},{6,73,73,41,30},{0,54,54,0,0},{0,86,54,0,0},{8,20,34,65,0},
{20,20,20,20,20},{0,65,34,20,8},{2,1,81,9,6},{50,73,121,65,62},
{126,17,17,17,126},{127,73,73,73,54},{62,65,65,65,34},{127,65,65,34,28},
{127,73,73,73,65},{127,9,9,9,1},{62,65,73,73,122},{127,8,8,8,127},
{0,65,127,65,0},{32,64,65,63,1},{127,8,20,34,65},{127,64,64,64,64},
{127,2,12,2,127},{127,4,8,16,127},{62,65,65,65,62},{127,9,9,9,6},
{62,65,81,33,94},{127,9,25,41,70},{70,73,73,73,49},{1,1,127,1,1},
{63,64,64,64,63},{31,32,64,32,31},{63,64,56,64,63},{99,20,8,20,99},
{7,8,112,8,7},{97,81,73,69,67},{0,127,65,65,0},{2,4,8,16,32},
{0,65,65,127,0},{4,2,1,2,4},{64,64,64,64,64},{0,1,2,4,0},
{32,84,84,84,120},{127,72,68,68,56},{56,68,68,68,32},{56,68,68,72,127},
{56,84,84,84,24},{8,126,9,1,2},{12,82,82,82,62},{127,8,4,4,120},
{0,68,125,64,0},{32,64,68,61,0},{127,16,40,68,0},{0,65,127,64,0},
{124,4,24,4,120},{124,8,4,4,120},{56,68,68,68,56},{124,20,20,20,8},
{8,20,20,24,124},{124,8,4,4,8},{72,84,84,84,32},{4,63,68,64,32},
{60,64,64,32,124},{28,32,64,32,28},{60,64,48,64,60},{68,40,16,40,68},
{12,80,80,80,60},{68,100,84,76,68},{0,8,54,65,0},{0,0,127,0,0},
{0,65,54,8,0},{16,8,8,16,8}
};

static void ch(char c,float px,float py,float sc,float r,float g,float b,float a){
    if(c<32||c>126)return;
    const uint8_t* gl=kFont[(int)c-32];
    col(r,g,b,a);
    for(int col2=0;col2<5;col2++){
        uint8_t bits=gl[col2];
        for(int row=0;row<7;row++){
            if(bits&(1<<row)){
                float x=px+col2*sc,y=py+row*sc;
                float v[]={x,y,x+sc,y,x+sc,y+sc,x,y+sc};
                glVertexAttribPointer(g_aloc_pos,2,GL_FLOAT,GL_FALSE,0,v);
                glEnableVertexAttribArray(g_aloc_pos);
                glDrawArrays(GL_TRIANGLE_FAN,0,4);
            }
        }
    }
}
static float tw(const char* s,float sc){int n=0;for(;*s;s++)n++;return n*6.f*sc;}
static void txt(const char* s,float x,float y,float sc,float r,float g,float b,float a){
    for(;*s;s++){ch(*s,x,y,sc,r,g,b,a);x+=6.f*sc;}
}

// ── Ватермарка ────────────────────────────────────────────────────────────────
static void draw_watermark(){
    float x=8,y=8,w=190,h=24;
    quad(x,y,w,h,true, 0.08f,0.08f,0.08f,0.92f);
    quad(x,y,w,h,false,0.20f,0.20f,0.20f,1.f);
    // красный квадрат с B
    quad(x+3,y+3,18,18,true,0.9f,0.08f,0.08f,1.f);
    txt("B",x+6,y+5,2.f,1,1,1,1);
    txt("BobaDLC External",x+25,y+6,1.5f,0.95f,0.95f,0.95f,1.f);
    // индикатор меню
    float mr=g_menu_vis?0.9f:0.4f,mg=g_menu_vis?0.1f:0.4f,mb=g_menu_vis?0.1f:0.4f;
    txt(g_menu_vis?"[MENU ON]":"[tap here]",x+w+6,y+6,1.3f,mr,mg,mb,1.f);
}

// ── Меню ──────────────────────────────────────────────────────────────────────
static void draw_toggle(float x,float y,bool on,const char* label){
    float tw2=tw(label,1.4f);
    txt(label,x,y+2,1.4f,0.85f,0.85f,0.85f,1.f);
    float tx=x+tw2+6;
    quad(tx,y,26,13,true,on?0.8f:0.15f,on?0.08f:0.15f,on?0.08f:0.15f,1.f);
    quad(tx,y,26,13,false,0.3f,0.3f,0.3f,1.f);
    float kx=on?(tx+14):(tx+1);
    quad(kx,y+1,11,11,true,1,1,1,1.f);
}

static void draw_menu(){
    if(!g_menu_vis)return;
    float W=(float)g_sw,H=(float)g_sh;
    float mw=420,mh=340,mx=(W-mw)/2,my=(H-mh)/2;

    // фон
    quad(mx,my,mw,mh,true,0.07f,0.07f,0.07f,0.97f);
    quad(mx,my,mw,mh,false,0.18f,0.18f,0.18f,1.f);

    // заголовок
    quad(mx,my,mw,34,true,0.11f,0.11f,0.11f,1.f);
    quad(mx+6,my+6,22,22,true,0.9f,0.08f,0.08f,1.f);
    txt("B",mx+9,my+8,2.3f,1,1,1,1);
    txt("BobaDLC External",mx+34,my+9,2.f,1,1,1,1);
    txt("by Lotusor",mx+mw-tw("by Lotusor",1.3f)-6,my+11,1.3f,0.5f,0.5f,0.5f,1);

    // табы внизу
    float tby=my+mh-32;
    quad(mx,tby,mw,32,true,0.1f,0.1f,0.1f,1.f);
    line(mx,tby,mx+mw,tby,0.2f,0.2f,0.2f,1.f);
    const char* tabs[]={"Aimbot","Visuals","Misc","Skins"};
    float tabw=mw/4;
    for(int i=0;i<4;i++){
        float tx2=mx+i*tabw;
        bool act=(g_tab==i);
        if(act){
            quad(tx2,tby,tabw,32,true,0.15f,0.15f,0.15f,1.f);
            quad(tx2,tby,tabw,2,true,0.9f,0.08f,0.08f,1.f);
        }
        float lx=tx2+(tabw-tw(tabs[i],1.4f))/2;
        txt(tabs[i],lx,tby+10,1.4f,act?1.f:0.5f,act?1.f:0.5f,act?1.f:0.5f,1.f);
    }

    // контент
    float cy=my+44,cx=mx+14;
    if(g_tab==1){
        // VISUALS
        txt("Visuals",cx,cy,1.6f,0.5f,0.5f,0.5f,1); cy+=22;
        line(cx,cy,cx+mw-28,cy,0.18f,0.18f,0.18f,1); cy+=10;
        draw_toggle(cx,cy,g_esp_on,   "ESP Enable");   cy+=22;
        draw_toggle(cx,cy,g_box_on,   "Bounding Box"); cy+=22;
        draw_toggle(cx,cy,g_hp_on,    "Health Bar");   cy+=22;
        draw_toggle(cx,cy,g_name_on,  "Name + HP");    cy+=22;
        char pb[32]; snprintf(pb,sizeof(pb),"Players: %zu",(size_t)g_players.size());
        txt(pb,cx,cy+4,1.4f,0.6f,0.6f,0.6f,1);
    } else if(g_tab==0){
        txt("Aimbot",cx,cy,1.6f,0.5f,0.5f,0.5f,1); cy+=22;
        line(cx,cy,cx+mw-28,cy,0.18f,0.18f,0.18f,1); cy+=10;
        txt("Coming soon",cx,cy,1.5f,0.4f,0.4f,0.4f,1);
    } else if(g_tab==2){
        txt("Misc",cx,cy,1.6f,0.5f,0.5f,0.5f,1); cy+=22;
        line(cx,cy,cx+mw-28,cy,0.18f,0.18f,0.18f,1); cy+=10;
        txt("Coming soon",cx,cy,1.5f,0.4f,0.4f,0.4f,1);
    } else {
        txt("Skins",cx,cy,1.6f,0.5f,0.5f,0.5f,1); cy+=22;
        line(cx,cy,cx+mw-28,cy,0.18f,0.18f,0.18f,1); cy+=10;
        txt("Coming soon",cx,cy,1.5f,0.4f,0.4f,0.4f,1);
    }
}

// ── ESP (2D список) ───────────────────────────────────────────────────────────
static void draw_esp(){
    if(!g_esp_on||!g_ok)return;
    static int delay=0; if(delay<180){delay++;return;}

    std::vector<void*> snap;
    void* loc;
    {std::lock_guard<std::mutex> lk(g_mtx); snap=g_players; loc=g_local;}
    if(snap.empty())return;

    float lx=(float)g_sw-210.f, ly=40.f;
    quad(lx-4,ly-4,206,14+(float)snap.size()*22,true,0,0,0,0.55f);
    txt("PLAYERS",lx,ly,1.5f,0.9f,0.1f,0.1f,1); ly+=16;

    int n=0;
    for(void* pm:snap){
        if(n>=12)break;
        if(!pm||(uintptr_t)pm<0x1000)continue;
        void* kp=*(void**)pm; if((uintptr_t)kp<0x1000)continue;

        float hp=read_hp(pm);
        std::string nm=read_name(pm);
        bool is_loc=(pm==loc);

        // полоска hp
        if(g_hp_on){
            float bw=200*(hp/100.f);
            if(bw<0)bw=0; if(bw>200)bw=200;
            quad(lx,ly,200,3,true,0.2f,0,0,0.8f);
            float gr=1-(hp/100.f),gg=hp/100.f;
            quad(lx,ly,bw,3,true,gr,gg,0,0.9f);
        }

        char buf[64];
        if(g_name_on) snprintf(buf,sizeof(buf),"%s %.0fhp",nm.c_str(),hp);
        else          snprintf(buf,sizeof(buf),"%.0fhp",hp);

        float cr=is_loc?0.3f:1, cg=is_loc?0.7f:1, cb=is_loc?1.f:1;
        txt(buf,lx,ly+5,1.4f,cr,cg,cb,1);
        ly+=22; n++;
    }
}

// ── Меню тогл через файл ──────────────────────────────────────────────────────
static void check_toggle(){
    static int t=0; if(++t<30)return; t=0;
    struct stat st{};
    bool ex=(stat("/data/local/tmp/.bobadlc_menu",&st)==0);
    if(ex!=g_menu_vis.load()) {
        g_menu_vis=ex;
        LOGI("menu %s",ex?"OPEN":"CLOSED");
    }
}

// ── EGL hook ──────────────────────────────────────────────────────────────────
using fn_swap=EGLBoolean(*)(EGLDisplay,EGLSurface);
static fn_swap g_orig_swap=nullptr;
static int g_frame=0;

static EGLBoolean hook_swap(EGLDisplay dpy,EGLSurface surf){
    g_frame++;

    if(g_frame==1) LOGI("eglSwapBuffers FIRING frame=1");
    if(g_frame%300==0) LOGI("frame=%d gl=%d",g_frame,(int)g_gl_ok);

    if(g_frame>60 && !g_gl_ok){
        EGLint w=0,h=0;
        eglQuerySurface(dpy,surf,EGL_WIDTH,&w);
        eglQuerySurface(dpy,surf,EGL_HEIGHT,&h);
        if(w>100&&h>100){g_sw=w;g_sh=h;}
        if(gl_init()) g_gl_ok=true;
        LOGI("GL init screen=%dx%d ok=%d",g_sw,g_sh,(int)g_gl_ok);
    }

    if(g_gl_ok){
        glUseProgram(g_prog);
        glUniform2f(g_uloc_res,(float)g_sw,(float)g_sh);
        GLboolean ob,od;
        glGetBooleanv(GL_BLEND,&ob);
        glGetBooleanv(GL_DEPTH_TEST,&od);
        glEnable(GL_BLEND);
        glBlendFunc(GL_SRC_ALPHA,GL_ONE_MINUS_SRC_ALPHA);
        glDisable(GL_DEPTH_TEST);
        draw_watermark();
        check_toggle();
        draw_menu();
        draw_esp();
        if(!ob)glDisable(GL_BLEND);
        if(od)glEnable(GL_DEPTH_TEST);
        glUseProgram(0);
        if(g_aloc_pos>=0)glDisableVertexAttribArray((GLuint)g_aloc_pos);
    }

    return g_orig_swap(dpy,surf);
}

// ── Установка хуков ───────────────────────────────────────────────────────────
// Найти базовый адрес библиотеки в памяти
static uintptr_t find_lib_base_full(const char* name) {
    std::ifstream f("/proc/self/maps");
    std::string line;
    while(std::getline(f, line)) {
        if(line.find(name) == std::string::npos) continue;
        if(line.find("r--p") == std::string::npos &&
           line.find("r-xp") == std::string::npos) continue;
        uintptr_t addr = (uintptr_t)strtoull(line.c_str(), nullptr, 16);
        if(addr > 0x1000) return addr;
    }
    return 0;
}

// Найти символ в ELF по базовому адресу (ручной парсинг)
#include <elf.h>
static void* elf_find_sym(uintptr_t base, const char* symname) {
    if(!base) return nullptr;
    auto* ehdr = (Elf64_Ehdr*)base;
    if(ehdr->e_ident[0] != 0x7f) return nullptr;

    auto* phdr = (Elf64_Phdr*)(base + ehdr->e_phoff);
    uintptr_t load_bias = 0;
    for(int i = 0; i < ehdr->e_phnum; i++) {
        if(phdr[i].p_type == PT_LOAD && phdr[i].p_offset == 0) {
            load_bias = base - phdr[i].p_vaddr;
            break;
        }
    }

    // Ищем dynamic section
    Elf64_Dyn* dyn = nullptr;
    for(int i = 0; i < ehdr->e_phnum; i++) {
        if(phdr[i].p_type == PT_DYNAMIC) {
            dyn = (Elf64_Dyn*)(load_bias + phdr[i].p_vaddr);
            break;
        }
    }
    if(!dyn) return nullptr;

    Elf64_Sym*  symtab = nullptr;
    const char* strtab = nullptr;
    uint32_t*   gnu_hash = nullptr;
    Elf64_Sym*  dynsym = nullptr;
    size_t      dynsym_cnt = 0;

    for(auto* d = dyn; d->d_tag != DT_NULL; d++) {
        if(d->d_tag == DT_SYMTAB) symtab = (Elf64_Sym*)(load_bias + d->d_un.d_ptr);
        if(d->d_tag == DT_STRTAB) strtab = (const char*)(load_bias + d->d_un.d_ptr);
        if(d->d_tag == DT_GNU_HASH) gnu_hash = (uint32_t*)(load_bias + d->d_un.d_ptr);
    }
    if(!symtab || !strtab) return nullptr;

    // Получаем кол-во символов через GNU_HASH
    if(gnu_hash) {
        uint32_t nbuckets = gnu_hash[0];
        uint32_t symoffset = gnu_hash[1];
        uint32_t bloom_size = gnu_hash[2];
        uint32_t* buckets = gnu_hash + 4 + bloom_size * 2;
        uint32_t* chain = buckets + nbuckets;
        uint32_t max_sym = symoffset;
        for(uint32_t i = 0; i < nbuckets; i++) {
            uint32_t b = buckets[i];
            if(b == 0) continue;
            uint32_t idx = b;
            while(!(chain[idx - symoffset] & 1)) idx++;
            if(idx > max_sym) max_sym = idx;
        }
        dynsym_cnt = max_sym + 1;
    } else {
        dynsym_cnt = 4096; // fallback
    }
    dynsym = symtab;

    for(size_t i = 0; i < dynsym_cnt; i++) {
        if(dynsym[i].st_name == 0) continue;
        if(dynsym[i].st_value == 0) continue;
        const char* name = strtab + dynsym[i].st_name;
        if(strcmp(name, symname) == 0) {
            return (void*)(load_bias + dynsym[i].st_value);
        }
    }
    return nullptr;
}

static void install(){
    // PlayerManager хуки
    A64HookFunction(rva(RVA_PM_Awake),    (void*)hook_Awake,     (void**)&g_orig_aw);
    A64HookFunction(rva(RVA_PM_OnEnable), (void*)hook_OnEnable,  (void**)&g_orig_en);
    A64HookFunction(rva(RVA_PM_OnDis),    (void*)hook_OnDisable, (void**)&g_orig_dis);
    LOGI("PlayerManager hooks done");

    bool egl_hooked = false;

    // 1. Хукаем eglSwapBuffers в системном libEGL.so
    uintptr_t egl_base = find_lib_base_full("libEGL.so");
    LOGI("libEGL base: 0x%lx", egl_base);
    if(egl_base) {
        void* fn = elf_find_sym(egl_base, "eglSwapBuffers");
        LOGI("libEGL eglSwapBuffers sym: %p", fn);
        if(fn) {
            bool ok = A64HookFunction(fn, (void*)hook_swap, (void**)&g_orig_swap);
            LOGI("libEGL hook: %s", ok?"OK":"FAIL");
            egl_hooked |= ok;
        }
    }

    // 2. Хукаем eglSwapBuffers в libunity.so (у Unity своя копия)
    uintptr_t unity_base = find_lib_base_full("libunity.so");
    LOGI("libunity base: 0x%lx", unity_base);
    if(unity_base) {
        void* fn = elf_find_sym(unity_base, "eglSwapBuffers");
        LOGI("libunity eglSwapBuffers sym: %p", fn);
        if(fn && fn != elf_find_sym(egl_base, "eglSwapBuffers")) {
            bool ok = A64HookFunction(fn, (void*)hook_swap, (void**)&g_orig_swap);
            LOGI("libunity eglSwap hook: %s", ok?"OK":"FAIL");
            egl_hooked |= ok;
        }
        // Также пробуем ANativeWindow_setBuffersGeometry как fallback
        // (некоторые Unity версии используют его для swap)
    }

    // 3. Хукаем через GOT libunity.so если прямой экспорт не нашёлся
    // GOT-патчинг: находим PLT entry для eglSwapBuffers внутри libunity.so
    if(!egl_hooked && unity_base) {
        // Ищем паттерн вызова eglSwapBuffers в .got.plt секции libunity.so
        auto* ehdr = (Elf64_Ehdr*)unity_base;
        auto* shdr = (Elf64_Shdr*)(unity_base + ehdr->e_shoff);
        // e_shoff может быть 0 в stripped lib — используем dynamic approach
        // Ищем .rela.plt
        uintptr_t load_bias = 0;
        auto* phdr = (Elf64_Phdr*)(unity_base + ehdr->e_phoff);
        for(int i=0;i<ehdr->e_phnum;i++){
            if(phdr[i].p_type==PT_LOAD&&phdr[i].p_offset==0){
                load_bias=unity_base-phdr[i].p_vaddr; break;
            }
        }
        Elf64_Dyn* dyn=nullptr;
        for(int i=0;i<ehdr->e_phnum;i++){
            if(phdr[i].p_type==PT_DYNAMIC){
                dyn=(Elf64_Dyn*)(load_bias+phdr[i].p_vaddr); break;
            }
        }
        if(dyn){
            Elf64_Rela* rela_plt=nullptr; size_t rela_plt_sz=0;
            Elf64_Sym* symtab=nullptr; const char* strtab=nullptr;
            for(auto* d=dyn;d->d_tag!=DT_NULL;d++){
                if(d->d_tag==DT_JMPREL) rela_plt=(Elf64_Rela*)(load_bias+d->d_un.d_ptr);
                if(d->d_tag==DT_PLTRELSZ) rela_plt_sz=d->d_un.d_val/sizeof(Elf64_Rela);
                if(d->d_tag==DT_SYMTAB) symtab=(Elf64_Sym*)(load_bias+d->d_un.d_ptr);
                if(d->d_tag==DT_STRTAB) strtab=(const char*)(load_bias+d->d_un.d_ptr);
            }
            if(rela_plt&&symtab&&strtab){
                for(size_t i=0;i<rela_plt_sz;i++){
                    uint32_t sym_idx=ELF64_R_SYM(rela_plt[i].r_info);
                    const char* name=strtab+symtab[sym_idx].st_name;
                    if(strcmp(name,"eglSwapBuffers")==0){
                        // GOT entry
                        void** got=(void**)(load_bias+rela_plt[i].r_offset);
                        LOGI("libunity GOT eglSwapBuffers: %p -> %p", got, *got);
                        // Сохраняем оригинал из GOT
                        g_orig_swap=(fn_swap)*got;
                        // Патчим GOT
                        _a64_protect(got, PROT_READ|PROT_WRITE|PROT_EXEC);
                        *got=(void*)hook_swap;
                        _a64_protect(got, PROT_READ|PROT_EXEC);
                        LOGI("GOT patch done, orig=%p", g_orig_swap);
                        egl_hooked=true;
                        break;
                    }
                }
            }
        }
    }

    LOGI("all hooks done. egl_hooked=%d", (int)egl_hooked);
}

// ── Zygisk ────────────────────────────────────────────────────────────────────
class LotusorModule : public zygisk::ModuleBase {
    zygisk::Api* api_=nullptr;
    JNIEnv* env_=nullptr;
    bool target_=false;
public:
    void onLoad(zygisk::Api* a,JNIEnv* e)override{api_=a;env_=e;}

    void preAppSpecialize(zygisk::AppSpecializeArgs* args)override{
        if(!args||!args->nice_name){
            api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);return;
        }
        const char* pkg=env_->GetStringUTFChars(args->nice_name,nullptr);
        if(pkg){
            if(strstr(pkg,"com.catsbit.oxidesurvivalisland")||strstr(pkg,"catsbit"))
                target_=true;
            env_->ReleaseStringUTFChars(args->nice_name,pkg);
        }
        if(!target_) api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs*)override{
        if(!target_)return;
        std::thread([](){
            LOGI("waiting for libil2cpp.so...");
            for(int i=0;i<600;i++){
                uintptr_t base=find_base("libil2cpp.so");
                if(base){
                    g_base=base;
                    LOGI("libil2cpp base=0x%lx",base);
                    sleep(2);
                    install();
                    return;
                }
                usleep(200000);
            }
            LOGE("libil2cpp not found");
        }).detach();
    }
};

REGISTER_ZYGISK_MODULE(LotusorModule)
extern "C" __attribute__((visibility("default"))) int zygisk_module_abi_version(){return 4;}
