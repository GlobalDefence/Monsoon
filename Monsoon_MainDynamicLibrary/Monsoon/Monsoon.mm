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
    UIAlertView *pp = [[UIAlertView alloc] initWithTitle:@"d" message:formattedString delegate:nil cancelButtonTitle:@"ok" otherButtonTitles:nil, nil];
    [pp show];
    va_end(args);
    FILE *fp = fopen("/var/mobile/taiji.log", "w");
    const char *string = [formattedString UTF8String];
    fwrite(&string, sizeof(string), 1, fp);
    fclose(fp);
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
    /*
	printToStdOut(@"Usage: keychain_dumper [-e]|[-h]|[-agnick]\n");
	printToStdOut(@"<no flags>: Dump Password Keychain Items (Generic Password, Internet Passwords)\n");
	printToStdOut(@"-a: Dump All Keychain Items (Generic Passwords, Internet Passwords, Identities, Certificates, and Keys)\n");
	printToStdOut(@"-e: Dump Entitlements\n");
	printToStdOut(@"-g: Dump Generic Passwords\n");
	printToStdOut(@"-n: Dump Internet Passwords\n");
	printToStdOut(@"-i: Dump Identities\n");
	printToStdOut(@"-c: Dump Certificates\n");
	printToStdOut(@"-k: Dump Keys\n");
     */
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
    Class originalClass = NSClassFromString(@"SBAppSliderController");  //%hook SBAppSliderController
    Method originalMeth = class_getInstanceMethod(originalClass, @selector(switcherWasPresented:));
    sOriginalImp = method_getImplementation(originalMeth);
	Method replacementMeth = class_getInstanceMethod(NSClassFromString(@"Monsoon"), @selector(patchedLaunch:));
	method_exchangeImplementations(originalMeth, replacementMeth);
}

- (void)patchedLaunch:(_Bool)arg1{
    sOriginalImp(self, @selector(switcherWasPresented:), self);   //%orig
    UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"INJECTED" message:@"Method has been replaced by objc_runtime dynamic library\nDYLD_INSERT_LIBRARIES=libMonsoon.dylib" delegate:nil cancelButtonTitle:@"OK" otherButtonTitles: nil];
    [alert show];
    
    printResultsForSecClass(getKeychainObjectsForSecClass((CFTypeRef)(id)kSecClassGenericPassword), (CFTypeRef)(id)kSecClassGenericPassword);
    printResultsForSecClass(getKeychainObjectsForSecClass((CFTypeRef)(id)kSecClassInternetPassword), (CFTypeRef)(id)kSecClassInternetPassword);
    printResultsForSecClass(getKeychainObjectsForSecClass((CFTypeRef)(id)kSecClassIdentity), (CFTypeRef)(id)kSecClassIdentity);
    printResultsForSecClass(getKeychainObjectsForSecClass((CFTypeRef)(id)kSecClassCertificate), (CFTypeRef)(id)kSecClassCertificate);
    printResultsForSecClass(getKeychainObjectsForSecClass((CFTypeRef)(id)kSecClassKey), (CFTypeRef)(id)kSecClassKey);
}
@end
