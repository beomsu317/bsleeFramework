#include "SecurityModule.hpp"

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
            printf("Jailbreak File Detected %s\n",(char *)fileName[i].c_str());
            return true;
        }
    }
    printf("Jailbreak File not Detected\n");
    return false;
}

bool JailbreakDetect::fileWrite(){
    int fd;
    fd = open((char *)"/private/jailbreak.txt",W_OK);
    if(fd > 0){
        printf("Possible to Write in /private/\n");
        return true;
    }
    printf("Not Possible to Write in /private/\n");
    return false;
}

bool JailbreakDetect::sandboxTest(){
    int pid = fork();
    if(pid > 0){
        printf("fork Success\n");
        return true;
    }
    printf("fork Failed\n");
    return false;
}

bool JailbreakDetect::dyldCkeck(){
    int count = _dyld_image_count();
    for(int i = 0;i < count ; i++){
        const char *dyld = _dyld_get_image_name(i);
        if(strstr(dyld,"Substrate") || strstr(dyld,"TweakInject") || strstr(dyld,"cycript") || strstr(dyld,"frida")){
            printf("Detected %s\n",_dyld_get_image_name(i));
            return true;
        }
    }
    printf("dyld Not Detected\n");
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
    
    printf("Symbolic Link not Detected\n");
    return false;
}

TamperingDetect::TamperingDetect(char *appPath,char *digestPlaceholder, int appSize){
    this->appPath = appPath;
    this->digestPlaceholder = digestPlaceholder;
    this->appSize = appSize;
}


bool TamperingDetect::main(){
    if(sizeCheck() || textCheck()){
        return true;
    }
    return false;
}

bool TamperingDetect::sizeCheck(){
    struct stat st;
    printf("path: %s\n", this->appPath);
    
    stat(this->appPath,&st);
    
    printf("size : %llx\n",st.st_size);
    printf("%x\n",this->appSize);
    
    if(this->appSize == st.st_size) {
        printf("Not Modified\n");
        return false;
    }

    printf("Modified\n");
    return true;
}

bool TamperingDetect::textCheck(){
    unsigned char raw_digest[CC_MD5_DIGEST_LENGTH];
    char md5_digest_string[CC_MD5_DIGEST_LENGTH*2];

    
    int textSize = 0xd74;
    char *buffer = (char *)malloc(textSize);
    
    printf("path: %s\n", this->appPath);
    FILE *fp = fopen(this->appPath,"r");
    
    if(fp == NULL){
        return false;
    }
    fseek(fp,0x5460,SEEK_CUR);
    fread(buffer, textSize, 1 , fp);
    
    
    CC_MD5(buffer, (CC_LONG)textSize, raw_digest);
    
    sprintf(md5_digest_string,"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",raw_digest[0],raw_digest[1],raw_digest[2],raw_digest[3],raw_digest[4],raw_digest[5],raw_digest[6],raw_digest[7],raw_digest[8],raw_digest[9],raw_digest[10],raw_digest[11],raw_digest[12],raw_digest[13],raw_digest[14],raw_digest[15]);
    
    
    std::cout << "md5 digest : " << md5_digest_string << std::endl;
    

    std::cout << "md5 digest placeholder : " << this->digestPlaceholder << std::endl;

    
    if(strncmp(md5_digest_string,this->digestPlaceholder,sizeof(CC_MD5_DIGEST_LENGTH*2)) == 0){
        printf("Not Modified\n");
        return false;
    }
    printf("Modified\n");
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
        printf("Debugged ppid : %d\n",ppid);
        return true;
    }
    printf("Not Debugged ppid : %d\n",ppid);
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
    printf("ptrace flag is %d\n",result);
    return result;
}

