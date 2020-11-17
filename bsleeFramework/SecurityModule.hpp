#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <assert.h>
#include <iostream>
#include <stdbool.h>
#include <string>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/getsect.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <cstring>

typedef int (*ptrace_ptr_t)(int _request,pid_t pid,caddr_t _addr, int _data);

class JailbreakDetect{
public:
    bool main();
    bool fileDetect();
    bool fileWrite();
    bool sandboxTest();
    bool dyldCkeck();
    bool symlinkCheck();
};

class TamperingDetect{
private:
    char *appPath;
public:
    TamperingDetect(char *appPath);
    bool main();
    bool sizeCheck();
    bool textCheck();
};

class DebuggingDetect{
public:
    void antiDebugging();
    bool beingDebugged();
    bool pidCheck();
    bool sysctlCheck();
};
