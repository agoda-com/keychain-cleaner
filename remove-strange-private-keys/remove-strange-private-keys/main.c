/*
 * Copyright (C) 2017, Cybereason
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <Security/Security.h>

bool validLabel(CFStringRef label) {
    CFIndex l = CFStringGetLength(label);
    if (l != 16) {
        return false;
    }
    for (int i = 0; i < l; i++) {
        UniChar c = CFStringGetCharacterAtIndex(label, i);
        if ((c < 'A' || c > 'Z') && (c < '0' || c > '9')) {
            return false;
        }
    }
    return true;
}

int main(int argc, const char * argv[]) {
    CFMutableDictionaryRef propertyMatchDict = CFDictionaryCreateMutable(kCFAllocatorDefault , 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(propertyMatchDict, kSecClass, kSecClassKey);
    CFDictionarySetValue(propertyMatchDict, kSecReturnRef, kCFBooleanTrue);
    CFDictionarySetValue(propertyMatchDict, kSecReturnAttributes, kCFBooleanTrue);
    short limit = 2000;
    CFNumberRef cfLimit = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt16Type, &limit);
    CFDictionarySetValue(propertyMatchDict, kSecMatchLimit, cfLimit);
    CFTypeRef entries;
    OSStatus status = SecItemCopyMatching(propertyMatchDict, &entries);
    CFRelease(propertyMatchDict);
    CFRelease(cfLimit);
    if (status != 0) {
        printf("Error getting private keys (OSStatus %d). Aborting.\n", status);
        return -1;
    }
    
    long c = CFArrayGetCount(entries);
    for (long i = 0; i < c; i++) {
        CFDictionaryRef dict = CFArrayGetValueAtIndex(entries, i);
        CFStringRef label = CFDictionaryGetValue(dict, CFSTR("labl"));
        if (!validLabel(label)) {
            continue;
        }
        printf("Deleting %s\n", CFStringGetCStringPtr(label, kCFStringEncodingUTF8));
        SecKeychainItemRef item = (SecKeychainItemRef)CFDictionaryGetValue(dict, CFSTR("v_Ref"));
        status = SecKeychainItemDelete(item);
        if (status != 0) {
            printf("Error deleting private key %s (OSStatus %d)\n", CFStringGetCStringPtr(label, kCFStringEncodingUTF8), status);
        }
    }
    CFRelease(entries);

    return 0;
}
