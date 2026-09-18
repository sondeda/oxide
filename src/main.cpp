// language: C++17, file: src/main.cpp, target: Android arm64-v8a, Unity IL2CPP (Oxide)
// build: CMakeLists.txt (add EGL + GLESv2 to target_link_libraries)
//
// Architecture:
//   1. shadowhook loaded from libshadowhook.so (already in game process)
//   2. Hook PlayerManager::Awake   — inject confirmation
//   3. Hook PlayerManager::OnEnable  — add player to tracked list
//   4. Hook PlayerManager::OnDisable — remove from list
//   5. Hook eglSwapBuffers — render ESP + menu (render thread = Unity's own thread)
//   6. Inside render hook: call Camera::get_main() + WorldToScreenPoint() by RVA (safe — render thread is attached)
//   7. Read player data by direct field offsets (no Mono API, no crash)

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
#include <cstdlib>
#include <cstdio>
#include <cmath>
#include <mutex>
#include <vector>
#include <algorithm>
#include <atomic>
#include <EGL/egl.h>
#include <GLES2/gl2.h>
#include "zygisk.hpp"
#include "And64InlineHook.hpp"

// ─────────────────────────────────────────────────────────────────────────────
// Logging
// ─────────────────────────────────────────────────────────────────────────────
#define TAG  "LotusorCheat"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ─────────────────────────────────────────────────────────────────────────────
// RVAs confirmed from Dump0/script.json + dump.cs (do NOT change)
// ─────────────────────────────────────────────────────────────────────────────
static constexpr uintptr_t RVA_PM_Awake         = 0x6685fd4UL;
static constexpr uintptr_t RVA_PM_OnEnable      = 0x66730a8UL;
static constexpr uintptr_t RVA_PM_OnDisable     = 0x667bd7cUL;
static constexpr uintptr_t RVA_PM_Update        = 0x6684014UL;
static constexpr uintptr_t RVA_Cam_GetMain      = 0xc73b4ecUL; // static, no __this
static constexpr uintptr_t RVA_Cam_W2S          = 0xc73aa40UL; // (Camera*, Vec3, MethodInfo*)->Vec3

// ─────────────────────────────────────────────────────────────────────────────
// PlayerManager field offsets (from dump.cs TypeDefIndex: 9223)
// ─────────────────────────────────────────────────────────────────────────────
static constexpr uintptr_t OFF_PM_playerEventHandler = 0x78;  // Gum*  (extends GuB which has DisplayName+Health)
static constexpr uintptr_t OFF_PM_vitals             = 0xC8;  // PlayerVitals*
static constexpr uintptr_t OFF_PM_lastTickPosition   = 0x1C8; // Vector3 (server position, close enough for ESP)
static constexpr uintptr_t OFF_PM_userID             = 0x278; // Il2CppString*
static constexpr uintptr_t OFF_PM_isImmortal         = 0x2B1; // bool
static constexpr uintptr_t OFF_PM_prime              = 0x254; // bool

// GuB (base of Gum/playerEventHandler) field offsets
static constexpr uintptr_t OFF_GuB_DisplayName = 0x88;  // Il2CppString*
static constexpr uintptr_t OFF_GuB_Health      = 0x98;  // Gun<float,?>* (heap obj)
static constexpr uintptr_t OFF_GUN_float_value = 0x18;  // float LMj inside Gun<float,?> object

// ─────────────────────────────────────────────────────────────────────────────
// IL2CPP struct helpers
// ─────────────────────────────────────────────────────────────────────────────
struct Vec3 { float x, y, z; };
struct Vec2 { float x, y; };

// Il2CppString: [klass 8][monitor 8][length 4][chars ...]
static std::string read_il2cpp_string(void* str_ptr) {
    if (!str_ptr) return "";
    int32_t len = *(int32_t*)((uintptr_t)str_ptr + 0x10);
    if (len <= 0 || len > 128) return "";
    const uint16_t* chars = (const uint16_t*)((uintptr_t)str_ptr + 0x14);
    std::string out;
    out.reserve((size_t)len);
    for (int i = 0; i < len; i++) {
        uint16_t c = chars[i];
        out += (c < 128) ? (char)c : '?';
    }
    return out;
}

// Safe dereference with trivial validity check
static inline void* safe_ptr(void* ptr) {
    // just check non-null and not obviously bad; no SIGSEGV guard here —
    // game objects live in managed heap and are valid while PlayerManager is alive
    return ((uintptr_t)ptr > 0x1000) ? ptr : nullptr;
}

template<typename T>
static inline T read_field(void* obj, uintptr_t offset) {
    return *(T*)((uintptr_t)obj + offset);
}

// ─────────────────────────────────────────────────────────────────────────────
// Base address
// ─────────────────────────────────────────────────────────────────────────────
static uintptr_t g_il2cpp_base = 0;

static uintptr_t find_lib_base(const char* libname) {
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        if (line.find(libname) == std::string::npos) continue;
        // want r--p or r-xp mapping at offset 0
        size_t perm_start = line.find(' ');
        if (perm_start == std::string::npos) continue;
        std::string perm = line.substr(perm_start + 1, 4);
        if (perm[0] != 'r') continue;
        // offset must be 00000000
        size_t col2 = line.find(' ', perm_start + 5);
        if (col2 == std::string::npos) continue;
        std::string offset_str = line.substr(col2 + 1, 8);
        if (offset_str != "00000000") continue;
        uintptr_t start = (uintptr_t)strtoull(line.c_str(), nullptr, 16);
        if (*(uint32_t*)start == 0x464C457F) return start;
    }
    return 0;
}

static inline void* rva(uintptr_t offset) {
    return (void*)(g_il2cpp_base + offset);
}

// ─────────────────────────────────────────────────────────────────────────────
// Hook loader — And64InlineHook (embedded, no external deps)
// ─────────────────────────────────────────────────────────────────────────────

static bool do_hook(uintptr_t rva_offset, void* hook_fn, void** orig) {
    void* target = rva(rva_offset);
    bool ok = A64HookFunction(target, hook_fn, orig);
    if (!ok) { LOGE("A64Hook FAILED at RVA 0x%lx", rva_offset); return false; }
    LOGI("A64Hook OK at RVA 0x%lx  orig=%p", rva_offset, orig ? *orig : nullptr);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Player registry
// ─────────────────────────────────────────────────────────────────────────────
struct PlayerInfo {
    void*       pm_ptr;
    Vec3        pos;
    float       health;
    float       max_health;
    std::string display_name;
    bool        is_local;
};

static std::mutex           g_players_mutex;
static std::vector<void*>   g_players;      // raw PlayerManager* pointers
static void*                g_local_pm = nullptr;
static std::atomic<bool>    g_injected{false};

static void add_player(void* pm) {
    std::lock_guard<std::mutex> lk(g_players_mutex);
    for (auto p : g_players) if (p == pm) return;
    g_players.push_back(pm);
    LOGI("player added: %p  total=%zu", pm, g_players.size());
}

static void remove_player(void* pm) {
    std::lock_guard<std::mutex> lk(g_players_mutex);
    auto it = std::find(g_players.begin(), g_players.end(), pm);
    if (it != g_players.end()) g_players.erase(it);
    if (g_local_pm == pm) g_local_pm = nullptr;
}

// read a PlayerInfo snapshot from a live PlayerManager*
static PlayerInfo snapshot_player(void* pm) {
    PlayerInfo pi{};
    pi.pm_ptr = pm;
    pi.is_local = (pm == g_local_pm);

    // position
    pi.pos = read_field<Vec3>(pm, OFF_PM_lastTickPosition);

    // health via playerEventHandler (Gum extends GuB which has Health)
    void* peh = safe_ptr(read_field<void*>(pm, OFF_PM_playerEventHandler));
    if (peh) {
        void* health_gun = safe_ptr(read_field<void*>(peh, OFF_GuB_Health));
        if (health_gun) {
            pi.health = read_field<float>(health_gun, OFF_GUN_float_value);
        }
        // display name
        void* name_str = safe_ptr(read_field<void*>(peh, OFF_GuB_DisplayName));
        if (name_str) {
            pi.display_name = read_il2cpp_string(name_str);
        }
    }

    // max health from vitals/GenericVitals chain
    // PlayerVitals → EntityVitals → GenericVitals (m_MaxHealth @ 0x88 within GenericVitals)
    // GenericVitals starts at its base class chain. Determined from dump:
    // NetworkBehaviour(~0x68) + Guy(0x68+0x10=0x78 total for Entity+bounds)
    // GenericVitals m_MaxHealth @ 0x88 (absolute from obj start)
    void* vitals = safe_ptr(read_field<void*>(pm, OFF_PM_vitals));
    if (vitals) {
        pi.max_health = read_field<float>(vitals, 0x88);
        if (pi.max_health <= 0.f || pi.max_health > 10000.f) pi.max_health = 100.f;
    } else {
        pi.max_health = 100.f;
    }

    if (pi.display_name.empty()) pi.display_name = "Player";
    return pi;
}

// ─────────────────────────────────────────────────────────────────────────────
// Menu state
// ─────────────────────────────────────────────────────────────────────────────
struct MenuState {
    bool visible         = false;
    int  active_tab      = 0; // 0=Aimbot 1=Visuals 2=Misc 3=Skins
    bool esp_enabled     = true;
    bool esp_box         = true;
    bool esp_health      = true;
    bool esp_name        = true;
    bool aimbot_enabled  = false;
    bool aimbot_silent   = false;
    bool aimbot_vis_only = true;
    bool no_recoil       = false;
    float esp_max_dist   = 500.f;
};
static MenuState g_menu;

// ─────────────────────────────────────────────────────────────────────────────
// Camera calls by RVA (safe to call from render thread — it's Unity's own thread)
// ─────────────────────────────────────────────────────────────────────────────
using fn_cam_getmain = void*(*)(void* method_info);
using fn_cam_w2s     = Vec3(*)(void* camera, Vec3 pos, void* method_info);
using fn_cam_pw      = int(*)(void* camera, void* method_info);
using fn_cam_ph      = int(*)(void* camera, void* method_info);

static fn_cam_getmain g_cam_getmain = nullptr;
static fn_cam_w2s     g_cam_w2s     = nullptr;
static fn_cam_pw      g_cam_pw      = nullptr;
static fn_cam_ph      g_cam_ph      = nullptr;

static void init_camera_fns() {
    g_cam_getmain = (fn_cam_getmain)rva(RVA_Cam_GetMain);
    g_cam_w2s     = (fn_cam_w2s)    rva(RVA_Cam_W2S);
    g_cam_pw      = (fn_cam_pw)     rva(0xc739174UL);
    g_cam_ph      = (fn_cam_ph)     rva(0xc739228UL);
}

// world→screen, returns false if behind camera (z < 0)
static bool world_to_screen(void* cam, const Vec3& world, Vec2& out) {
    Vec3 s = g_cam_w2s(cam, world, nullptr);
    if (s.z < 0.f) return false;
    out.x = s.x;
    out.y = s.y;
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// OpenGL ES 2.0 renderer
// ─────────────────────────────────────────────────────────────────────────────
static GLuint  g_prog  = 0;
static GLint   g_uloc_res   = -1;
static GLint   g_uloc_color = -1;
static GLint   g_aloc_pos   = -1;
static int     g_scr_w = 1280, g_scr_h = 720;
static bool    g_gl_ready   = false;

static const char* k_vs =
    "attribute vec2 aPos;\n"
    "uniform vec2 uRes;\n"
    "void main() {\n"
    "  vec2 p = aPos / uRes * 2.0 - 1.0;\n"
    "  gl_Position = vec4(p.x, -p.y, 0.0, 1.0);\n"
    "}\n";

static const char* k_fs =
    "precision mediump float;\n"
    "uniform vec4 uColor;\n"
    "void main() { gl_FragColor = uColor; }\n";

static GLuint compile_shader(GLenum type, const char* src) {
    GLuint s = glCreateShader(type);
    glShaderSource(s, 1, &src, nullptr);
    glCompileShader(s);
    return s;
}

static bool init_gl() {
    GLuint vs = compile_shader(GL_VERTEX_SHADER,   k_vs);
    GLuint fs = compile_shader(GL_FRAGMENT_SHADER, k_fs);
    g_prog = glCreateProgram();
    glAttachShader(g_prog, vs);
    glAttachShader(g_prog, fs);
    glLinkProgram(g_prog);
    glDeleteShader(vs);
    glDeleteShader(fs);

    g_uloc_res   = glGetUniformLocation(g_prog, "uRes");
    g_uloc_color = glGetUniformLocation(g_prog, "uColor");
    g_aloc_pos   = glGetAttribLocation(g_prog,  "aPos");
    LOGI("GL program linked, res=%d color=%d pos=%d", g_uloc_res, g_uloc_color, g_aloc_pos);
    return true;
}

static void set_color(float r, float g, float b, float a) {
    glUniform4f(g_uloc_color, r, g, b, a);
}

static void draw_verts(GLenum mode, const float* verts, int count) {
    glVertexAttribPointer(g_aloc_pos, 2, GL_FLOAT, GL_FALSE, 0, verts);
    glEnableVertexAttribArray(g_aloc_pos);
    glDrawArrays(mode, 0, count);
}

static void draw_rect_outline(float x, float y, float w, float h,
                               float r, float g, float b, float a, float thickness = 1.f) {
    (void)thickness;
    set_color(r, g, b, a);
    float v[] = { x,y, x+w,y, x+w,y+h, x,y+h };
    draw_verts(GL_LINE_LOOP, v, 4);
}

static void draw_rect_filled(float x, float y, float w, float h,
                              float r, float g, float b, float a) {
    set_color(r, g, b, a);
    float v[] = { x,y, x+w,y, x,y+h, x+w,y+h };
    draw_verts(GL_TRIANGLE_STRIP, v, 4);
}

static void draw_line(float x1, float y1, float x2, float y2,
                       float r, float g, float b, float a) {
    set_color(r, g, b, a);
    float v[] = { x1,y1, x2,y2 };
    draw_verts(GL_LINES, v, 2);
}

// ─── 5×7 bitmap font (ASCII 32-126) ─────────────────────────────────────────
// Each char: 5 columns × 7 rows, packed into 5 bytes (7 bits each, LSB=top)
static const uint8_t k_font[95][5] = {
  {0x00,0x00,0x00,0x00,0x00}, // 32 ' '
  {0x00,0x00,0x5f,0x00,0x00}, // 33 '!'
  {0x00,0x07,0x00,0x07,0x00}, // 34 '"'
  {0x14,0x7f,0x14,0x7f,0x14}, // 35 '#'
  {0x24,0x2a,0x7f,0x2a,0x12}, // 36 '$'
  {0x23,0x13,0x08,0x64,0x62}, // 37 '%'
  {0x36,0x49,0x55,0x22,0x50}, // 38 '&'
  {0x00,0x05,0x03,0x00,0x00}, // 39 '\''
  {0x00,0x1c,0x22,0x41,0x00}, // 40 '('
  {0x00,0x41,0x22,0x1c,0x00}, // 41 ')'
  {0x14,0x08,0x3e,0x08,0x14}, // 42 '*'
  {0x08,0x08,0x3e,0x08,0x08}, // 43 '+'
  {0x00,0x50,0x30,0x00,0x00}, // 44 ','
  {0x08,0x08,0x08,0x08,0x08}, // 45 '-'
  {0x00,0x60,0x60,0x00,0x00}, // 46 '.'
  {0x20,0x10,0x08,0x04,0x02}, // 47 '/'
  {0x3e,0x51,0x49,0x45,0x3e}, // 48 '0'
  {0x00,0x42,0x7f,0x40,0x00}, // 49 '1'
  {0x42,0x61,0x51,0x49,0x46}, // 50 '2'
  {0x21,0x41,0x45,0x4b,0x31}, // 51 '3'
  {0x18,0x14,0x12,0x7f,0x10}, // 52 '4'
  {0x27,0x45,0x45,0x45,0x39}, // 53 '5'
  {0x3c,0x4a,0x49,0x49,0x30}, // 54 '6'
  {0x01,0x71,0x09,0x05,0x03}, // 55 '7'
  {0x36,0x49,0x49,0x49,0x36}, // 56 '8'
  {0x06,0x49,0x49,0x29,0x1e}, // 57 '9'
  {0x00,0x36,0x36,0x00,0x00}, // 58 ':'
  {0x00,0x56,0x36,0x00,0x00}, // 59 ';'
  {0x08,0x14,0x22,0x41,0x00}, // 60 '<'
  {0x14,0x14,0x14,0x14,0x14}, // 61 '='
  {0x00,0x41,0x22,0x14,0x08}, // 62 '>'
  {0x02,0x01,0x51,0x09,0x06}, // 63 '?'
  {0x32,0x49,0x79,0x41,0x3e}, // 64 '@'
  {0x7e,0x11,0x11,0x11,0x7e}, // 65 'A'
  {0x7f,0x49,0x49,0x49,0x36}, // 66 'B'
  {0x3e,0x41,0x41,0x41,0x22}, // 67 'C'
  {0x7f,0x41,0x41,0x22,0x1c}, // 68 'D'
  {0x7f,0x49,0x49,0x49,0x41}, // 69 'E'
  {0x7f,0x09,0x09,0x09,0x01}, // 70 'F'
  {0x3e,0x41,0x49,0x49,0x7a}, // 71 'G'
  {0x7f,0x08,0x08,0x08,0x7f}, // 72 'H'
  {0x00,0x41,0x7f,0x41,0x00}, // 73 'I'
  {0x20,0x40,0x41,0x3f,0x01}, // 74 'J'
  {0x7f,0x08,0x14,0x22,0x41}, // 75 'K'
  {0x7f,0x40,0x40,0x40,0x40}, // 76 'L'
  {0x7f,0x02,0x0c,0x02,0x7f}, // 77 'M'
  {0x7f,0x04,0x08,0x10,0x7f}, // 78 'N'
  {0x3e,0x41,0x41,0x41,0x3e}, // 79 'O'
  {0x7f,0x09,0x09,0x09,0x06}, // 80 'P'
  {0x3e,0x41,0x51,0x21,0x5e}, // 81 'Q'
  {0x7f,0x09,0x19,0x29,0x46}, // 82 'R'
  {0x46,0x49,0x49,0x49,0x31}, // 83 'S'
  {0x01,0x01,0x7f,0x01,0x01}, // 84 'T'
  {0x3f,0x40,0x40,0x40,0x3f}, // 85 'U'
  {0x1f,0x20,0x40,0x20,0x1f}, // 86 'V'
  {0x3f,0x40,0x38,0x40,0x3f}, // 87 'W'
  {0x63,0x14,0x08,0x14,0x63}, // 88 'X'
  {0x07,0x08,0x70,0x08,0x07}, // 89 'Y'
  {0x61,0x51,0x49,0x45,0x43}, // 90 'Z'
  {0x00,0x7f,0x41,0x41,0x00}, // 91 '['
  {0x02,0x04,0x08,0x10,0x20}, // 92 '\'
  {0x00,0x41,0x41,0x7f,0x00}, // 93 ']'
  {0x04,0x02,0x01,0x02,0x04}, // 94 '^'
  {0x40,0x40,0x40,0x40,0x40}, // 95 '_'
  {0x00,0x01,0x02,0x04,0x00}, // 96 '`'
  {0x20,0x54,0x54,0x54,0x78}, // 97 'a'
  {0x7f,0x48,0x44,0x44,0x38}, // 98 'b'
  {0x38,0x44,0x44,0x44,0x20}, // 99 'c'
  {0x38,0x44,0x44,0x48,0x7f}, // 100 'd'
  {0x38,0x54,0x54,0x54,0x18}, // 101 'e'
  {0x08,0x7e,0x09,0x01,0x02}, // 102 'f'
  {0x0c,0x52,0x52,0x52,0x3e}, // 103 'g'
  {0x7f,0x08,0x04,0x04,0x78}, // 104 'h'
  {0x00,0x44,0x7d,0x40,0x00}, // 105 'i'
  {0x20,0x40,0x44,0x3d,0x00}, // 106 'j'
  {0x7f,0x10,0x28,0x44,0x00}, // 107 'k'
  {0x00,0x41,0x7f,0x40,0x00}, // 108 'l'
  {0x7c,0x04,0x18,0x04,0x78}, // 109 'm'
  {0x7c,0x08,0x04,0x04,0x78}, // 110 'n'
  {0x38,0x44,0x44,0x44,0x38}, // 111 'o'
  {0x7c,0x14,0x14,0x14,0x08}, // 112 'p'
  {0x08,0x14,0x14,0x18,0x7c}, // 113 'q'
  {0x7c,0x08,0x04,0x04,0x08}, // 114 'r'
  {0x48,0x54,0x54,0x54,0x20}, // 115 's'
  {0x04,0x3f,0x44,0x40,0x20}, // 116 't'
  {0x3c,0x40,0x40,0x20,0x7c}, // 117 'u'
  {0x1c,0x20,0x40,0x20,0x1c}, // 118 'v'
  {0x3c,0x40,0x30,0x40,0x3c}, // 119 'w'
  {0x44,0x28,0x10,0x28,0x44}, // 120 'x'
  {0x0c,0x50,0x50,0x50,0x3c}, // 121 'y'
  {0x44,0x64,0x54,0x4c,0x44}, // 122 'z'
  {0x00,0x08,0x36,0x41,0x00}, // 123 '{'
  {0x00,0x00,0x7f,0x00,0x00}, // 124 '|'
  {0x00,0x41,0x36,0x08,0x00}, // 125 '}'
  {0x10,0x08,0x08,0x10,0x08}, // 126 '~'
};

// draw a single char at pixel position, scale=pixel size per font-pixel
static void draw_char(char c, float px, float py, float scale,
                       float r, float g, float b, float a) {
    if (c < 32 || c > 126) return;
    const uint8_t* glyph = k_font[(int)c - 32];
    set_color(r, g, b, a);
    for (int col = 0; col < 5; col++) {
        uint8_t bits = glyph[col];
        for (int row = 0; row < 7; row++) {
            if (bits & (1 << row)) {
                float x = px + col * scale;
                float y = py + row * scale;
                float v[] = { x, y, x+scale, y, x, y+scale, x+scale, y+scale };
                draw_verts(GL_TRIANGLE_STRIP, v, 4);
            }
        }
    }
}

static void draw_text(const char* text, float px, float py, float scale,
                       float r, float g, float b, float a) {
    float cx = px;
    for (int i = 0; text[i]; i++) {
        draw_char(text[i], cx, py, scale, r, g, b, a);
        cx += 6.f * scale;
    }
}

static float text_width(const char* text, float scale) {
    int n = 0;
    for (const char* p = text; *p; p++) n++;
    return n * 6.f * scale;
}

// ─────────────────────────────────────────────────────────────────────────────
// ESP rendering
// ─────────────────────────────────────────────────────────────────────────────
static void render_esp() {
    if (!g_menu.esp_enabled) return;

    // Ждём 180 фреймов после инжекта
    static int frame_delay = 0;
    if (frame_delay < 180) { frame_delay++; return; }

    std::vector<void*> players_copy;
    void* local_copy;
    {
        std::lock_guard<std::mutex> lk(g_players_mutex);
        players_copy = g_players;
        local_copy   = g_local_pm;
    }
    if (players_copy.empty()) return;

    float W = (float)g_scr_w;
    float H = (float)g_scr_h;

    // Рисуем 2D список игроков в правом верхнем углу (без world-to-screen)
    float list_x = W - 200.f;
    float list_y = 40.f;

    draw_rect_filled(list_x - 4.f, list_y - 4.f, 196.f, 14.f + players_copy.size() * 20.f,
                     0.f, 0.f, 0.f, 0.5f);
    draw_text("PLAYERS", list_x, list_y, 1.5f, 0.9f, 0.08f, 0.08f, 1.f);
    list_y += 14.f;

    int drawn = 0;
    for (void* pm : players_copy) {
        if (!pm) continue;
        if (drawn >= 10) break; // максимум 10 в списке

        // Проверяем валидность объекта
        void* klass_ptr = *(void**)pm;
        if ((uintptr_t)klass_ptr < 0x1000) continue;

        // Читаем имя
        std::string name = "Player";
        float hp = 0.f;

        void* peh = *(void**)((uintptr_t)pm + OFF_PM_playerEventHandler);
        if ((uintptr_t)peh > 0x1000) {
            void* name_str = *(void**)((uintptr_t)peh + OFF_GuB_DisplayName);
            if ((uintptr_t)name_str > 0x1000)
                name = read_il2cpp_string(name_str);

            void* health_gun = *(void**)((uintptr_t)peh + OFF_GuB_Health);
            if ((uintptr_t)health_gun > 0x1000)
                hp = *(float*)((uintptr_t)health_gun + OFF_GUN_float_value);
        }
        if (name.empty()) name = "Player";
        if (hp < 0.f || hp > 9999.f) hp = 0.f;

        // Цвет: локальный игрок синий, остальные белые
        float cr = (pm == local_copy) ? 0.3f : 1.f;
        float cg = (pm == local_copy) ? 0.6f : 1.f;
        float cb = (pm == local_copy) ? 1.f  : 1.f;

        char buf[64];
        snprintf(buf, sizeof(buf), "%s  %.0fhp", name.c_str(), hp);

        // Полоска здоровья
        float bar_w = 190.f * std::max(0.f, std::min(1.f, hp / 100.f));
        draw_rect_filled(list_x - 2.f, list_y, 190.f, 2.f, 0.3f, 0.f, 0.f, 0.8f);
        draw_rect_filled(list_x - 2.f, list_y, bar_w,  2.f, 0.f,  0.8f, 0.2f, 0.9f);

        draw_text(buf, list_x, list_y + 3.f, 1.4f, cr, cg, cb, 1.f);
        list_y += 20.f;
        drawn++;
    }
}



// ─────────────────────────────────────────────────────────────────────────────
// Menu rendering  (BobaDLC External dark+red style)
// Colors: bg=#141414, panel=#1c1c1c, accent=#e53935, text=#ffffff, sub=#9e9e9e
// ─────────────────────────────────────────────────────────────────────────────
static void render_toggle(float x, float y, float w, float h, bool on,
                           const char* label) {
    // track bg
    draw_rect_filled(x, y, w, h, 0.13f,0.13f,0.13f, 1.f);
    draw_rect_outline(x, y, w, h, 0.25f,0.25f,0.25f, 1.f);
    // knob
    float kw = h * 0.9f;
    float kx = on ? (x + w - kw - 1.f) : (x + 1.f);
    float ky = y + (h - kw) * 0.5f;
    if (on) {
        draw_rect_filled(x, y, w, h, 0.9f,0.08f,0.08f, 1.f);
    }
    draw_rect_filled(kx, ky, kw, kw, 1.f,1.f,1.f, 1.f);
    // label
    draw_text(label, x - text_width(label, 1.5f) - 4.f, y + (h - 7*1.5f)*0.5f,
              1.5f, 1.f,1.f,1.f, 1.f);
}

static void render_menu() {
    if (!g_menu.visible) return;

    float W = (float)g_scr_w;
    float H = (float)g_scr_h;

    // center the menu
    float mw = 480.f, mh = 380.f;
    float mx = (W - mw) * 0.5f, my = (H - mh) * 0.5f;

    // ── main background ───────────────────────────────────────────────────────
    draw_rect_filled(mx, my, mw, mh, 0.078f, 0.078f, 0.078f, 0.97f);
    draw_rect_outline(mx, my, mw, mh, 0.15f, 0.15f, 0.15f, 1.f);

    // ── title bar ─────────────────────────────────────────────────────────────
    float th = 36.f;
    draw_rect_filled(mx, my, mw, th, 0.11f, 0.11f, 0.11f, 1.f);
    // 'Z' logo box (red)
    draw_rect_filled(mx + 8.f, my + 6.f, 24.f, 24.f, 0.9f, 0.08f, 0.08f, 1.f);
    draw_text("B", mx + 12.f, my + 11.f, 2.5f, 1.f, 1.f, 1.f, 1.f);
    draw_text("BobaDLC External", mx + 40.f, my + 11.f, 2.2f, 1.f, 1.f, 1.f, 1.f);
    // watermark text right side
    draw_text("bobadlc", mx + mw - text_width("bobadlc", 1.5f) - 8.f, my + 12.f,
              1.5f, 0.6f, 0.6f, 0.6f, 1.f);

    // ── tab bar ───────────────────────────────────────────────────────────────
    float tby = my + mh - 36.f;
    draw_rect_filled(mx, tby, mw, 36.f, 0.1f, 0.1f, 0.1f, 1.f);
    draw_line(mx, tby, mx+mw, tby, 0.18f, 0.18f, 0.18f, 1.f);

    const char* tabs[] = { "Aimbot", "Visuals", "Misc", "Skins" };
    float tab_w = mw / 4.f;
    for (int i = 0; i < 4; i++) {
        float tx = mx + i * tab_w;
        bool active = (g_menu.active_tab == i);
        if (active) {
            draw_rect_filled(tx, tby, tab_w, 36.f, 0.14f, 0.14f, 0.14f, 1.f);
            draw_rect_filled(tx, tby, tab_w, 2.f, 0.9f, 0.08f, 0.08f, 1.f);
        }
        float label_x = tx + (tab_w - text_width(tabs[i], 1.5f)) * 0.5f;
        float cr = active ? 1.f : 0.55f;
        float cg = active ? 1.f : 0.55f;
        float cb = active ? 1.f : 0.55f;
        draw_text(tabs[i], label_x, tby + 12.f, 1.5f, cr, cg, cb, 1.f);
    }

    // ── content area ─────────────────────────────────────────────────────────
    float cy = my + th + 12.f;
    float cx = mx + 12.f;
    float pw = (mw - 36.f) * 0.5f;  // two-column layout

    if (g_menu.active_tab == 0) {
        // ── AIMBOT ────────────────────────────────────────────────────────────
        draw_text("Enable",    cx + pw - text_width("Enable", 1.5f) - 36.f, cy,     1.5f, 0.8f,0.8f,0.8f, 1.f);
        render_toggle(cx + pw - 32.f, cy - 2.f, 28.f, 14.f, g_menu.aimbot_enabled, "");
        cy += 24.f;
        draw_text("Silent",    cx + pw - text_width("Silent", 1.5f) - 36.f, cy,     1.5f, 0.8f,0.8f,0.8f, 1.f);
        render_toggle(cx + pw - 32.f, cy - 2.f, 28.f, 14.f, g_menu.aimbot_silent, "");
        cy += 28.f;

        // divider
        draw_line(cx, cy, cx + (mw - 24.f), cy, 0.2f,0.2f,0.2f, 1.f);
        cy += 10.f;
        draw_text("Target", cx, cy, 1.5f, 0.5f,0.5f,0.5f, 1.f);
        cy += 20.f;
        draw_text("Bones Group",  cx, cy, 1.5f, 0.8f,0.8f,0.8f, 1.f);
        draw_text("Head",  cx + pw - text_width("Head",1.5f), cy, 1.5f, 0.9f,0.08f,0.08f, 1.f);
        cy += 20.f;
        draw_text("Visible Check", cx, cy, 1.5f, 0.8f,0.8f,0.8f, 1.f);
        render_toggle(cx + pw - 32.f, cy - 2.f, 28.f, 14.f, g_menu.aimbot_vis_only, "");

    } else if (g_menu.active_tab == 1) {
        // ── VISUALS ───────────────────────────────────────────────────────────
        draw_text("Enable", cx, cy + 3.f, 1.5f, 0.8f,0.8f,0.8f, 1.f);
        render_toggle(cx + pw - 32.f, cy - 2.f, 28.f, 14.f, g_menu.esp_enabled, "");
        cy += 24.f;

        draw_text("Bounding Box", cx, cy + 3.f, 1.5f, 0.8f,0.8f,0.8f, 1.f);
        render_toggle(cx + pw - 32.f, cy - 2.f, 28.f, 14.f, g_menu.esp_box, "");
        cy += 24.f;

        draw_text("Health Bar", cx, cy + 3.f, 1.5f, 0.8f,0.8f,0.8f, 1.f);
        render_toggle(cx + pw - 32.f, cy - 2.f, 28.f, 14.f, g_menu.esp_health, "");
        cy += 24.f;

        draw_text("Name + HP",  cx, cy + 3.f, 1.5f, 0.8f,0.8f,0.8f, 1.f);
        render_toggle(cx + pw - 32.f, cy - 2.f, 28.f, 14.f, g_menu.esp_name, "");
        cy += 28.f;

        draw_line(cx, cy, cx + (mw - 24.f), cy, 0.2f,0.2f,0.2f, 1.f);
        cy += 10.f;

        // ESP preview label (right column)
        draw_text("ESP Preview", cx + pw + 12.f, my + th + 12.f, 1.5f, 0.5f,0.5f,0.5f, 1.f);
        // small player silhouette
        float px2 = cx + pw + 60.f, py2 = my + th + 32.f;
        draw_rect_outline(px2, py2, 50.f, 120.f, 0.9f,0.08f,0.08f, 1.f);
        draw_rect_filled(px2 - 5.f, py2, 3.f, 120.f*0.7f, 0.9f, 0.4f, 0.1f, 0.8f);

    } else if (g_menu.active_tab == 2) {
        // ── MISC ──────────────────────────────────────────────────────────────
        draw_text("No Recoil", cx, cy + 3.f, 1.5f, 0.8f,0.8f,0.8f, 1.f);
        render_toggle(cx + pw - 32.f, cy - 2.f, 28.f, 14.f, g_menu.no_recoil, "");
        cy += 24.f;

        draw_text("Max ESP Dist", cx, cy + 3.f, 1.5f, 0.8f,0.8f,0.8f, 1.f);
        char dbuf[16]; snprintf(dbuf, sizeof(dbuf), "%.0fm", g_menu.esp_max_dist);
        draw_text(dbuf, cx + pw - text_width(dbuf, 1.5f), cy + 3.f, 1.5f, 0.9f,0.08f,0.08f, 1.f);
        cy += 24.f;

    } else if (g_menu.active_tab == 3) {
        // ── SKINS ─────────────────────────────────────────────────────────────
        draw_text("Coming soon", cx + (pw - text_width("Coming soon",2.f))*0.5f,
                  my + mh*0.5f - 10.f, 2.f, 0.5f,0.5f,0.5f, 1.f);
    }

    // ── watermark overlay (top-left corner) ───────────────────────────────────
    // Handled separately below (always visible)
}

// ─── permanent watermark (top bar, always on screen) ─────────────────────────
static void render_watermark() {
    float bw = 180.f, bh = 22.f, bx = 8.f, by = 8.f;
    draw_rect_filled(bx, by, bw, bh, 0.08f, 0.08f, 0.08f, 0.85f);
    draw_rect_outline(bx, by, bw, bh, 0.18f, 0.18f, 0.18f, 1.f);
    // red 'Z'
    draw_rect_filled(bx + 3.f, by + 3.f, 16.f, 16.f, 0.9f, 0.08f, 0.08f, 1.f);
    draw_text("B", bx + 5.5f, by + 5.f, 2.f, 1.f, 1.f, 1.f, 1.f);
    draw_text("BobaDLC External", bx + 22.f, by + 6.f, 1.5f, 0.9f, 0.9f, 0.9f, 1.f);
    // version
    draw_text("1.0", bx + bw - text_width("1.0", 1.2f) - 5.f, by + 7.f, 1.2f, 0.5f,0.5f,0.5f, 1.f);

    // menu toggle hint
    // подсказка — тапни по ватермарке чтобы открыть меню
    draw_text("[tap to open]", bx + bw + 5.f, by + 6.f, 1.2f,
              g_menu.visible ? 0.9f : 0.45f,
              g_menu.visible ? 0.1f : 0.45f,
              g_menu.visible ? 0.1f : 0.45f, 0.9f);
}

// ─────────────────────────────────────────────────────────────────────────────
// Touch input reader — читаем /dev/input/eventX напрямую в отдельном треде.
// Тап по ватермарке (левый верхний угол, 8..188 x 8..30 в экранных пикселях)
// переключает меню. Работает независимо от Unity input system.
// ─────────────────────────────────────────────────────────────────────────────
#include <linux/input.h>
#include <dirent.h>
#include <fcntl.h>

// Зона ватермарки в нормализованных координатах (0..1).
// Физически: bx=8 bw=180 by=8 bh=22 на любом разрешении.
// Берём с запасом чтобы было удобно тапать пальцем.
static constexpr float kWM_X0 = 0.f,   kWM_X1 = 0.22f;
static constexpr float kWM_Y0 = 0.f,   kWM_Y1 = 0.06f;

// Последняя позиция касания (в ABS единицах устройства, конвертируем позже)
struct TouchSlot {
    int x = 0, y = 0;
    bool down = false;
};

static std::atomic<bool> g_touch_menu_toggle{false}; // сигнал из тред → рендер

// Найти все /dev/input/eventX которые репортят ABS_MT_POSITION
static std::vector<std::string> find_touch_devices() {
    // Сначала пробуем найти через /proc/bus/input/devices — более надёжно
    std::vector<std::string> result;
    // Пробуем все event0..event9 напрямую
    for (int i = 0; i < 15; i++) {
        char path[32];
        snprintf(path, sizeof(path), "/dev/input/event%d", i);
        int fd = open(path, O_RDONLY | O_NONBLOCK);
        if (fd < 0) continue;
        uint8_t evbits[EV_MAX / 8 + 1] = {};
        if (ioctl(fd, EVIOCGBIT(0, sizeof(evbits)), evbits) >= 0) {
            bool has_abs = (evbits[EV_ABS / 8] & (1 << (EV_ABS % 8))) != 0;
            if (has_abs) {
                uint8_t absbits[ABS_MAX / 8 + 1] = {};
                ioctl(fd, EVIOCGBIT(EV_ABS, sizeof(absbits)), absbits);
                bool has_mt = (absbits[ABS_MT_POSITION_X / 8] & (1 << (ABS_MT_POSITION_X % 8))) != 0;
                bool has_abs_x = (absbits[ABS_X / 8] & (1 << (ABS_X % 8))) != 0;
                if (has_mt || has_abs_x) {
                    result.push_back(std::string(path));
                    LOGI("touch device found: %s", path);
                }
            }
        }
        close(fd);
    }
    return result;
}
// _REPLACED_OLD_FIND_

static void touch_reader_thread() {
    // ждём пока игра поднимется
    sleep(8);

    auto devices = find_touch_devices();
    if (devices.empty()) {
        LOGE("no touch devices found — меню через /data/local/tmp/.bobadlc_menu");
        // Fallback: файловый триггер если /dev/input недоступен
        while (true) {
            struct stat st{};
            bool file_exists = (stat("/data/local/tmp/.bobadlc_menu", &st) == 0);
            if (file_exists) g_touch_menu_toggle.store(true);
            sleep(1);
        }
        return;
    }

    // берём первое найденное тач-устройство
    const std::string& dev = devices[0];
    int fd = open(dev.c_str(), O_RDONLY);
    if (fd < 0) { LOGE("can't open %s", dev.c_str()); return; }

    // получить диапазоны ABS_MT_POSITION_X/Y чтобы нормализовать
    struct input_absinfo abs_x{}, abs_y{};
    ioctl(fd, EVIOCGABS(ABS_MT_POSITION_X), &abs_x);
    ioctl(fd, EVIOCGABS(ABS_MT_POSITION_Y), &abs_y);
    float max_x = (abs_x.maximum > 0) ? (float)abs_x.maximum : 1080.f;
    float max_y = (abs_y.maximum > 0) ? (float)abs_y.maximum : 1920.f;
    LOGI("touch range: x=0..%.0f y=0..%.0f", max_x, max_y);

    TouchSlot slot{};
    bool was_down = false;
    float touch_norm_x = 0.f, touch_norm_y = 0.f;

    struct input_event ev{};
    while (true) {
        ssize_t n = read(fd, &ev, sizeof(ev));
        if (n < (ssize_t)sizeof(ev)) { usleep(5000); continue; }

        if (ev.type == EV_ABS) {
            if (ev.code == ABS_MT_POSITION_X || ev.code == ABS_X)
                slot.x = ev.value;
            else if (ev.code == ABS_MT_POSITION_Y || ev.code == ABS_Y)
                slot.y = ev.value;
            else if (ev.code == ABS_MT_TRACKING_ID)
                slot.down = (ev.value != -1);
        } else if (ev.type == EV_KEY && ev.code == BTN_TOUCH) {
            slot.down = (ev.value == 1);
        } else if (ev.type == EV_SYN && ev.code == SYN_REPORT) {
            // палец поднялся — проверяем был ли тап по ватермарке
            if (was_down && !slot.down) {
                float nx = (float)slot.x / max_x;
                float ny = (float)slot.y / max_y;
                if (nx >= kWM_X0 && nx <= kWM_X1 &&
                    ny >= kWM_Y0 && ny <= kWM_Y1) {
                    g_touch_menu_toggle.store(true);
                    LOGI("watermark tapped! nx=%.3f ny=%.3f", nx, ny);
                }
            }
            was_down = slot.down;
        }
    }
    close(fd);
}

// check_menu_toggle вызывается из рендер-треда (eglSwapBuffers)
static void check_menu_toggle() {
    if (g_touch_menu_toggle.exchange(false)) {
        g_menu.visible = !g_menu.visible;
        LOGI("menu toggled -> %s", g_menu.visible ? "open" : "closed");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// eglSwapBuffers hook
// ─────────────────────────────────────────────────────────────────────────────
using fn_eglSwap = EGLBoolean(*)(EGLDisplay, EGLSurface);
static fn_eglSwap g_orig_swap = nullptr;

static EGLBoolean hooked_eglSwapBuffers(EGLDisplay dpy, EGLSurface surf) {
    if (!g_injected.load()) return g_orig_swap(dpy, surf);

    // init GL program once
    if (!g_gl_ready) {
        if (init_gl()) g_gl_ready = true;
        // читаем размер экрана через EGL — без IL2CPP вызовов
        EGLDisplay cur_dpy  = eglGetCurrentDisplay();
        EGLSurface cur_surf = eglGetCurrentSurface(EGL_DRAW);
        if (cur_surf != EGL_NO_SURFACE) {
            EGLint w = 0, h = 0;
            eglQuerySurface(cur_dpy, cur_surf, EGL_WIDTH,  &w);
            eglQuerySurface(cur_dpy, cur_surf, EGL_HEIGHT, &h);
            if (w > 0 && h > 0) { g_scr_w = w; g_scr_h = h; }
        }
        LOGI("screen via EGL: %dx%d", g_scr_w, g_scr_h);
    }

    if (g_gl_ready && g_prog) {
        glUseProgram(g_prog);
        glUniform2f(g_uloc_res, (float)g_scr_w, (float)g_scr_h);

        // save & set GL state
        GLboolean old_blend, old_depth;
        glGetBooleanv(GL_BLEND,       &old_blend);
        glGetBooleanv(GL_DEPTH_TEST,  &old_depth);
        glEnable(GL_BLEND);
        glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
        glDisable(GL_DEPTH_TEST);

        // render
        render_watermark();
        check_menu_toggle();
        render_menu();
        render_esp();

        // restore GL state
        if (!old_blend) glDisable(GL_BLEND);
        if (old_depth)  glEnable(GL_DEPTH_TEST);
        glUseProgram(0);
        glDisableVertexAttribArray(g_aloc_pos);
    }

    return g_orig_swap(dpy, surf);
}

// ─────────────────────────────────────────────────────────────────────────────
// PlayerManager hooks
// ─────────────────────────────────────────────────────────────────────────────
using fn_pm_void = void(*)(void* __this, void* method);

static fn_pm_void g_orig_awake     = nullptr;
static fn_pm_void g_orig_on_enable = nullptr;
static fn_pm_void g_orig_on_disable = nullptr;

static void hooked_Awake(void* __this, void* method) {
    // Вызываем оригинал ПЕРВЫМ — Unity должна инициализировать компонент
    if (g_orig_awake) g_orig_awake(__this, method);

    LOGI("Awake HIT! this=%p", __this);

    // Только сохраняем указатель — никаких чтений полей здесь
    // Поля читаем позже в render thread когда всё инициализировано
    static bool first = true;
    if (first) {
        g_local_pm = __this;
        first = false;
        g_injected.store(true);
        init_camera_fns();
        LOGI("local player set to %p, camera fns init done", __this);
    }
    add_player(__this);
}


static void hooked_OnEnable(void* __this, void* method) {
    if (g_orig_on_enable) g_orig_on_enable(__this, method);
    add_player(__this);
}

static void hooked_OnDisable(void* __this, void* method) {
    if (g_orig_on_disable) g_orig_on_disable(__this, method);
    remove_player(__this);
}

// ─────────────────────────────────────────────────────────────────────────────
// Hook installation
// ─────────────────────────────────────────────────────────────────────────────
static void install_hooks() {
    // PlayerManager hooks
    do_hook(RVA_PM_Awake,     (void*)hooked_Awake,      (void**)&g_orig_awake);
    do_hook(RVA_PM_OnEnable,  (void*)hooked_OnEnable,   (void**)&g_orig_on_enable);
    do_hook(RVA_PM_OnDisable, (void*)hooked_OnDisable,  (void**)&g_orig_on_disable);

    // eglSwapBuffers hook — the render thread is Unity's own, safe for IL2CPP calls
    void* egl_lib = dlopen("libEGL.so", RTLD_LAZY | RTLD_NOLOAD);
    if (!egl_lib) egl_lib = dlopen("libEGL.so", RTLD_LAZY);
    if (egl_lib) {
        void* swap_fn = dlsym(egl_lib, "eglSwapBuffers");
        if (swap_fn) {
            bool ok = A64HookFunction(swap_fn, (void*)hooked_eglSwapBuffers, (void**)&g_orig_swap);
            LOGI("eglSwapBuffers hook: %s  orig=%p", ok ? "OK" : "FAIL", g_orig_swap);
        } else {
            LOGE("eglSwapBuffers not found in libEGL.so");
        }
    } else {
        LOGE("libEGL.so dlopen failed");
    }

    LOGI("all hooks installed");

    // запускаем тред чтения тачскрина
    std::thread(touch_reader_thread).detach();
}

// ─────────────────────────────────────────────────────────────────────────────
// Zygisk module
// ─────────────────────────────────────────────────────────────────────────────
class LotusorModule : public zygisk::ModuleBase {
    zygisk::Api* api_ = nullptr;
    JNIEnv*      env_ = nullptr;
    bool         target_ = false;
public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        api_ = api; env_ = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs* args) override {
        if (!args || !args->nice_name) {
            api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }
        const char* pkg = env_->GetStringUTFChars(args->nice_name, nullptr);
        if (pkg) {
            // Oxide Survival by Catsbit
            if (strstr(pkg, "com.catsbit.oxidesurvivalisland") || strstr(pkg, "catsbit"))
                target_ = true;
            env_->ReleaseStringUTFChars(args->nice_name, pkg);
        }
        if (!target_) api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs*) override {
        if (!target_) return;

        // Find libil2cpp base — it may not be loaded yet at this point.
        // Spin in a detached thread until it appears.
        std::thread([]() {
            LOGI("waiting for libil2cpp.so...");
            for (int i = 0; i < 600; i++) {
                uintptr_t base = find_lib_base("libil2cpp.so");
                if (base) {
                    g_il2cpp_base = base;
                    LOGI("libil2cpp.so base: 0x%lx", base);
                    // small extra delay so the lib fully initializes before we hook
                    sleep(2);
                    install_hooks();
                    return;
                }
                usleep(200000); // 200ms
            }
            LOGE("libil2cpp.so never appeared");
        }).detach();
    }
};

REGISTER_ZYGISK_MODULE(LotusorModule)

extern "C" __attribute__((visibility("default"))) int zygisk_module_abi_version() { return 4; }
