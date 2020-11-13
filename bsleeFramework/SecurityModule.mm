#import <Foundation/Foundation.h>
#include "SecurityModule.h"

bool JailbreakDetect::main(){

    if(fileDetect() || fileWrite() || sandboxTest() || dyldCkeck() || symlinkCheck()){
        return true;
    }
    
    return false;
}

bool JailbreakDetect::fileDetect(){
    std::string fileName[36] = {
        "/Applications/Cydia.app",
        "/Applications/FakeCarrier.app",
        "/Applications/Icy.app",
        "/Applications/IntelliScreen.app",
        "/Applications/MxTube.app",
        "/Applications/RockApp.app",
        "/Applications/SBSettings.app",
        "/Applications/WinterBoard.app",
        "/Applications/blackra1n.app",
        "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
        "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
        "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
        "/bin/bash",
        "/bin/sh",
        "/etc/apt",
        "/etc/ssh/sshd_config",
        "/private/var/lib/apt",
        "/private/var/lib/cydia",
        "/private/var/mobile/Library/SBSettings/Themes",
        "/private/var/stash",
        "/private/var/tmp/cydia.log",
        "/var/tmp/cydia.log",
        "/usr/bin/sshd",
        "/usr/libexec/sftp-server",
        "/usr/libexec/ssh-keysign",
        "/usr/sbin/sshd",
        "/var/cache/apt",
        "/var/lib/apt",
        "/var/lib/cydia",
        "/usr/sbin/frida-server",
        "/usr/bin/cycript",
        "/usr/local/bin/cycript",
        "/usr/lib/libcycript.dylib",
        "/var/log/syslog"
    };
        
    for(int i=0;i<sizeof(fileName)/sizeof(fileName[0]);i++){
        if(access((char *)fileName[i].c_str(),R_OK) > 0){
            NSLog(@"Jailbreak File Detected %s\n",(char *)fileName[i].c_str());
            return true;
        }
    }
    NSLog(@"Jailbreak File not Detected\n");
    return false;
}

bool JailbreakDetect::fileWrite(){
    int fd;
    fd = open((char *)"/private/jailbreak.txt",W_OK);
    if(fd > 0){
        NSLog(@"Possible to Write in /private/\n");
        return true;
    }
    NSLog(@"Not Possible to Write in /private/\n");
    return false;
}

bool JailbreakDetect::sandboxTest(){
    int pid = fork();
    if(pid > 0){
        NSLog(@"fork Success\n");
        return true;
    }
    NSLog(@"fork Failed\n");
    return false;
}

bool JailbreakDetect::dyldCkeck(){
    int count = _dyld_image_count();
    for(int i = 0;i < count ; i++){
        const char *dyld = _dyld_get_image_name(i);
        if(strstr(dyld,"Substrate") || strstr(dyld,"TweakInject") || strstr(dyld,"cycript") || strstr(dyld,"frida")){
            NSLog(@"Detected %s\n",_dyld_get_image_name(i));
            return true;
        }
    }
    NSLog(@"dyld Not Detected\n");
    return false;
}

bool JailbreakDetect::symlinkCheck(){
    
    struct stat status;
    if (!stat("/Applications/Cydia.app", &status)) {
        return true;
    }
    else if (!stat("/Library/MobileSubstrate/MobileSubstrate.dylib", &status)) {
        return true;
    }
    else if (!stat("/var/cache/apt", &status)) {
        return true;
    }
    else if (!stat("/var/lib/cydia", &status)) {
        return true;
    }
    else if (!stat("/var/log/syslog", &status)) {
        return true;
    }
    else if (!stat("/var/tmp/cydia.log", &status)) {
        return true;
    }
    else if (!stat("/bin/bash", &status)) {
        return true;
    }
    else if (!stat("/bin/sh", &status)) {
        return true;
    }
    else if (!stat("/usr/sbin/sshd", &status)) {
        return true;
    }
    else if (!stat("/usr/libexec/ssh-keysign", &status)) {
        return true;
    }
    else if (!stat("/etc/ssh/sshd_config", &status)) {
        return true;
    }
    else if (!stat("/etc/apt", &status)) {
        return true;
    }
    
    NSLog(@"Symbolic Link not Detected\n");
    return false;
}

bool TamperingDetect::main(){
    if(textCheck() || sizeCheck()){
        return true;
    }
    return false;
}

bool TamperingDetect::sizeCheck(){
    return false;
    unsigned char fileSizePlaceholder[] = {0xd0,0x3f,0x01,0x00};
    
    NSString *name=@"bsApp";
    NSString *path = [[NSBundle mainBundle] pathForResource:name ofType:0 ];
    NSFileHandle *fh;
    
    NSLog(@"path: %@", path);
    
    
    fh = [NSFileHandle fileHandleForReadingAtPath: path];
    NSData *content = [fh readDataToEndOfFile];
    unsigned int fileSize = (CC_LONG)[content length];
    NSLog(@"file size : %d", fileSize);
    [fh closeFile];

    NSData *trustedSizeData = [NSData dataWithBytes:fileSizePlaceholder  length:4];
    unsigned int trustedSize;
    [trustedSizeData getBytes:&trustedSize length:sizeof(trustedSize)];

    NSLog(@"ts : %d",trustedSize);
    NSLog(@"fs : %d",fileSize);
    if (trustedSize == fileSize) {
        NSLog(@"Not Modified");
        return false;
    }
    
    NSLog(@"Modified");
    return true;
}

bool TamperingDetect::textCheck(){
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    unsigned char md5Placeholder[CC_MD5_DIGEST_LENGTH] = {0xc3,0xe3,0x30,0x36,0x39,0x85,0x0c,0x59,0xc7,0xb5,0xb8,0xc7,0x7c,0x3d,0x67,0x45};
    
    int textSize = 0x8000-0x5648;
    NSData *databuffer;
    
    NSString *name=@"bsApp";
    NSString *path = [[NSBundle mainBundle] pathForResource:name ofType:0 ];
    NSFileHandle *fh;

    fh = [NSFileHandle fileHandleForReadingAtPath: path];

    if (fh == nil)
        NSLog(@"Failed to open file");

    [fh seekToFileOffset: 0x5648];
    databuffer = [fh readDataOfLength:textSize];
    //NSLog(@"%@",databuffer);
    [fh closeFile];
    
    
    unsigned char *d = CC_MD5([databuffer bytes], textSize, digest);
    NSData *md5Data = [NSData dataWithBytes:d length:CC_MD5_DIGEST_LENGTH];
    NSLog(@"data = %@", md5Data);
    
    NSData *md5PlaceholderData = [NSData dataWithBytes:md5Placeholder length:CC_MD5_DIGEST_LENGTH];
    NSLog(@"trusted data = %@", md5PlaceholderData);

    if([md5Data isEqual:md5PlaceholderData]){
        NSLog(@"Not Modified");
        return false;
    }
    NSLog(@"Modified");
    return true;
}


void DebuggingDetect::antiDebugging(){
    ptrace_ptr_t ptrace_ptr = (ptrace_ptr_t)dlsym(RTLD_SELF,"ptrace");
    ptrace_ptr(31,0,0,0);
}

bool DebuggingDetect::beingDebugged(){
    if(pidCheck() || sysctlCheck() ){
        return true;
    }
    return false;
}

bool DebuggingDetect::pidCheck(){
    int ppid = getppid();
    if(ppid != 1){
        NSLog(@"Debugged ppid : %d\n",ppid);
        return true;
    }
    NSLog(@"Not Debugged ppid : %d\n",ppid);
    return false;
}

bool DebuggingDetect::sysctlCheck(){
    int                 junk;
    int                 mib[4];
    struct kinfo_proc   info;
    size_t              size;

    info.kp_proc.p_flag = 0;

    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();

    size = sizeof(info);
    junk = sysctl(mib, sizeof(mib) / sizeof(*mib), &info, &size, NULL, 0);
    assert(junk == 0);
    int result = ((info.kp_proc.p_flag & P_TRACED) != 0);
    NSLog(@"ptrace flag is %d\n",result);
    return result;
}

