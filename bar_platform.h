/* bar_platform.h - portable OS layer for the p4br tools.
 *
 * Replaces the original Win32-only I/O (HANDLE/CreateFileW/ReadFile, wchar_t
 * paths, FILETIME, FindFirstFile, _beginthreadex, _aligned_malloc) with
 * portable equivalents that work on Windows (MSVC + MinGW), Linux and macOS
 * (including Apple Silicon). All functions are `static` and header-only. */
#ifndef BAR_PLATFORM_H
#define BAR_PLATFORM_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#if defined(_WIN32)
  #include <windows.h>
  #include <io.h>
  #include <direct.h>
  #include <sys/utime.h>
  #include <sys/stat.h>
#else
  #include <unistd.h>
  #include <pthread.h>
  #include <dirent.h>
  #include <sys/stat.h>
  #include <utime.h>
#endif

/* ---- 64-bit file offsets ---- */
#if defined(_WIN32)
  #define bar_fseek64(f,off,wh) _fseeki64((f),(long long)(off),(wh))
  #define bar_ftell64(f)        _ftelli64((f))
#else
  #define bar_fseek64(f,off,wh) fseeko((f),(off_t)(off),(wh))
  #define bar_ftell64(f)        ftello((f))
#endif

/* ---- UTF-8 aware fopen (Windows needs UTF-16) ---- */
#if defined(_WIN32)
static wchar_t *bar_utf8_to_wide(const char *s)
{
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, NULL, 0);
    UINT cp = CP_UTF8;
    if (n == 0) { cp = CP_ACP; n = MultiByteToWideChar(cp, 0, s, -1, NULL, 0); }
    if (n == 0) return NULL;
    wchar_t *w = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (!w) return NULL;
    MultiByteToWideChar(cp, 0, s, -1, w, n);
    return w;
}
#endif

static FILE *bar_fopen(const char *path, const char *mode)
{
#if defined(_WIN32)
    wchar_t *w = bar_utf8_to_wide(path);
    if (!w) return NULL;
    wchar_t wm[8]; int i = 0;
    while (mode[i] && i < 7) { wm[i] = (wchar_t)mode[i]; i++; } wm[i] = 0;
    FILE *f = _wfopen(w, wm);
    free(w);
    return f;
#else
    return fopen(path, mode);
#endif
}

/* ---- mkdir -p for a host path (UTF-8). sep may be '/' or '\\'. ---- */
static int bar_mkdir_one(const char *path)
{
#if defined(_WIN32)
    wchar_t *w = bar_utf8_to_wide(path);
    if (!w) return -1;
    int r = _wmkdir(w);
    free(w);
    return (r == 0 || errno == EEXIST) ? 0 : -1;
#else
    int r = mkdir(path, 0777);
    return (r == 0 || errno == EEXIST) ? 0 : -1;
#endif
}

static void bar_mkdirs(const char *path)
{
    char tmp[4096];
    size_t n = strlen(path);
    if (n == 0 || n >= sizeof tmp) return;
    memcpy(tmp, path, n + 1);
    for (size_t i = 1; i < n; i++) {
        if (tmp[i] == '/' || tmp[i] == '\\') {
            char c = tmp[i]; tmp[i] = 0;
            /* skip a bare drive letter like "C:" */
            if (!(i == 2 && tmp[1] == ':')) bar_mkdir_one(tmp);
            tmp[i] = c;
        }
    }
    bar_mkdir_one(tmp);
}

static void bar_mkdirs_parent(const char *path)
{
    char tmp[4096];
    size_t n = strlen(path);
    if (n == 0 || n >= sizeof tmp) return;
    memcpy(tmp, path, n + 1);
    for (long i = (long)n - 1; i >= 0; i--) {
        if (tmp[i] == '/' || tmp[i] == '\\') { tmp[i] = 0; bar_mkdirs(tmp); return; }
    }
}

/* ---- set a file's mtime/atime (unix seconds) ---- */
static void bar_set_mtime(const char *path, uint32_t mtime)
{
    if (mtime == 0) return;
#if defined(_WIN32)
    wchar_t *w = bar_utf8_to_wide(path);
    if (!w) return;
    struct _utimbuf tb; tb.actime = (time_t)mtime; tb.modtime = (time_t)mtime;
    _wutime(w, &tb);
    free(w);
#else
    struct utimbuf tb; tb.actime = (time_t)mtime; tb.modtime = (time_t)mtime;
    utime(path, &tb);
#endif
}

/* ---- file size / existence (UTF-8 path) ---- */
static int bar_file_size(const char *path, uint64_t *out)
{
#if defined(_WIN32)
    wchar_t *w = bar_utf8_to_wide(path);
    if (!w) return -1;
    struct _stat64 st;
    int r = _wstat64(w, &st);
    free(w);
    if (r != 0) return -1;
    *out = (uint64_t)st.st_size;
    return 0;
#else
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    *out = (uint64_t)st.st_size;
    return 0;
#endif
}
static int bar_is_dir(const char *path)
{
#if defined(_WIN32)
    wchar_t *w = bar_utf8_to_wide(path);
    if (!w) return 0;
    DWORD a = GetFileAttributesW(w);
    free(w);
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
#else
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
#endif
}

static int bar_remove(const char *path)
{
#if defined(_WIN32)
    wchar_t *w = bar_utf8_to_wide(path);
    if (!w) return -1;
    int r = _wremove(w);
    free(w);
    return r;
#else
    return remove(path);
#endif
}

/* ---- aligned alloc / free (16-byte) ---- */
static void *bar_aligned_alloc(size_t sz)
{
#if defined(_WIN32)
    return _aligned_malloc(sz, 16);
#else
    void *p = NULL;
    if (posix_memalign(&p, 16, sz) != 0) return NULL;
    return p;
#endif
}
static void bar_aligned_free(void *p)
{
#if defined(_WIN32)
    _aligned_free(p);
#else
    free(p);
#endif
}

/* ---- atomics (64-bit) ---- */
#if defined(_WIN32)
  typedef volatile LONG64 bar_atomic64;
  #define BAR_ADD64(p,v) ((long long)InterlockedAdd64((p),(LONG64)(v)))
  #define BAR_INC64(p)   ((long long)InterlockedIncrement64((p)))
  #define BAR_LOAD64(p)  ((long long)(*(p)))
  #define BAR_STORE64(p,v) (*(p) = (LONG64)(v))
#else
  typedef volatile long long bar_atomic64;
  #define BAR_ADD64(p,v) __atomic_add_fetch((p),(long long)(v),__ATOMIC_SEQ_CST)
  #define BAR_INC64(p)   __atomic_add_fetch((p),1,__ATOMIC_SEQ_CST)
  #define BAR_LOAD64(p)  __atomic_load_n((p),__ATOMIC_SEQ_CST)
  #define BAR_STORE64(p,v) __atomic_store_n((p),(long long)(v),__ATOMIC_SEQ_CST)
#endif

/* ---- threads (uniform void*(*)(void*) signature) ---- */
typedef void *(*bar_thread_fn)(void *);

#if defined(_WIN32)
typedef struct { HANDLE h; bar_thread_fn fn; void *arg; void *ret; } bar_thread;
static DWORD WINAPI bar__thunk(LPVOID p) { bar_thread *t = (bar_thread *)p; t->ret = t->fn(t->arg); return 0; }
static int  bar_thread_create(bar_thread *t, bar_thread_fn fn, void *arg)
{ t->fn = fn; t->arg = arg; t->ret = NULL; t->h = CreateThread(NULL, 0, bar__thunk, t, 0, NULL); return t->h ? 0 : -1; }
static void bar_thread_join(bar_thread *t)
{ if (t->h) { WaitForSingleObject(t->h, INFINITE); CloseHandle(t->h); t->h = NULL; } }
#else
typedef struct { pthread_t h; } bar_thread;
static int  bar_thread_create(bar_thread *t, bar_thread_fn fn, void *arg)
{ return pthread_create(&t->h, NULL, fn, arg); }
static void bar_thread_join(bar_thread *t) { pthread_join(t->h, NULL); }
#endif

static int bar_cpu_count(void)
{
#if defined(_WIN32)
    SYSTEM_INFO si; GetSystemInfo(&si); return (int)si.dwNumberOfProcessors;
#else
    long n = sysconf(_SC_NPROCESSORS_ONLN); return n > 0 ? (int)n : 1;
#endif
}

static void bar_sleep_ms(int ms)
{
#if defined(_WIN32)
    Sleep((DWORD)ms);
#else
    struct timespec ts; ts.tv_sec = ms / 1000; ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
#endif
}

static double bar_monotonic(void)
{
#if defined(_WIN32)
    LARGE_INTEGER f, c; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&c);
    return (double)c.QuadPart / (double)f.QuadPart;
#else
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
#endif
}

/* random 64-bit seed source for per-segment IVs (any decent entropy is fine) */
static uint64_t bar_rand64(void)
{
    uint64_t x;
#if defined(_WIN32)
    LARGE_INTEGER c; QueryPerformanceCounter(&c);
    x = (uint64_t)c.QuadPart ^ ((uint64_t)GetCurrentProcessId() << 32) ^ (uint64_t)(uintptr_t)&x;
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) { if (fread(&x, 1, 8, f) != 8) x = 0; fclose(f); if (x) return x; }
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    x = (uint64_t)ts.tv_nsec ^ ((uint64_t)getpid() << 32) ^ (uint64_t)(uintptr_t)&x;
#endif
    /* splitmix step so low-entropy sources still spread */
    x += 0x9E3779B97F4A7C15ULL;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}

/* ---- portable directory enumeration ---- */
typedef struct { char name[512]; int is_dir; uint64_t size; uint32_t mtime; uint32_t ctime; uint32_t atime; } bar_dirent;
typedef int (*bar_dir_cb)(const bar_dirent *, void *);  /* return nonzero to stop */

#if defined(_WIN32)
static uint32_t bar__ft_unix(FILETIME ft)
{
    ULARGE_INTEGER u; u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime;
    if (u.QuadPart < 116444736000000000ULL) return 0;
    return (uint32_t)((u.QuadPart - 116444736000000000ULL) / 10000000ULL);
}
#endif

/* enumerate one directory (UTF-8 path); calls cb for each entry (not . / ..) */
static int bar_enum_dir(const char *dirpath, bar_dir_cb cb, void *ud)
{
#if defined(_WIN32)
    char patu[4096]; snprintf(patu, sizeof patu, "%s\\*", dirpath);
    wchar_t *pat = bar_utf8_to_wide(patu);
    if (!pat) return -1;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pat, &fd);
    free(pat);
    if (h == INVALID_HANDLE_VALUE) return -1;
    int stop = 0;
    do {
        if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
        bar_dirent e; memset(&e, 0, sizeof e);
        WideCharToMultiByte(CP_UTF8, 0, fd.cFileName, -1, e.name, (int)sizeof e.name, NULL, NULL);
        e.is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;
        e.size = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
        e.ctime = bar__ft_unix(fd.ftCreationTime);
        e.mtime = bar__ft_unix(fd.ftLastWriteTime);
        e.atime = bar__ft_unix(fd.ftLastAccessTime);
        if (cb(&e, ud)) { stop = 1; break; }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    (void)stop;
    return 0;
#else
    DIR *d = opendir(dirpath);
    if (!d) return -1;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        bar_dirent e; memset(&e, 0, sizeof e);
        snprintf(e.name, sizeof e.name, "%s", de->d_name);
        char full[4096]; snprintf(full, sizeof full, "%s/%s", dirpath, de->d_name);
        struct stat st;
        if (stat(full, &st) == 0) {
            e.is_dir = S_ISDIR(st.st_mode) ? 1 : 0;
            e.size = (uint64_t)st.st_size;
            e.mtime = (uint32_t)st.st_mtime;
            e.ctime = (uint32_t)st.st_ctime;
            e.atime = (uint32_t)st.st_atime;
        }
        if (cb(&e, ud)) break;
    }
    closedir(d);
    return 0;
#endif
}

/* directory of the running executable (UTF-8, no trailing slash) */
static void bar_exe_dir(char *out, size_t cap)
{
    out[0] = 0;
#if defined(_WIN32)
    wchar_t wp[MAX_PATH * 2];
    DWORD n = GetModuleFileNameW(NULL, wp, MAX_PATH * 2);
    if (n == 0) return;
    for (long i = (long)n - 1; i >= 0; i--) if (wp[i] == L'\\' || wp[i] == L'/') { wp[i] = 0; break; }
    WideCharToMultiByte(CP_UTF8, 0, wp, -1, out, (int)cap, NULL, NULL);
#elif defined(__APPLE__)
    extern int _NSGetExecutablePath(char *, uint32_t *);
    char buf[4096]; uint32_t sz = sizeof buf;
    if (_NSGetExecutablePath(buf, &sz) != 0) return;
    char real[4096];
    const char *p = realpath(buf, real) ? real : buf;
    snprintf(out, cap, "%s", p);
    for (long i = (long)strlen(out) - 1; i >= 0; i--) if (out[i] == '/') { out[i] = 0; break; }
#else
    char buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof buf - 1);
    if (n <= 0) return;
    buf[n] = 0;
    snprintf(out, cap, "%s", buf);
    for (long i = (long)strlen(out) - 1; i >= 0; i--) if (out[i] == '/') { out[i] = 0; break; }
#endif
}

#endif /* BAR_PLATFORM_H */
