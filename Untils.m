//
//  Untils.m
//  TestDemo
//
//  Created by MS on 15/12/16.
//  Copyright © 2015年 LjxProduct. All rights reserved.
//

#import "Untils.h"
#import <CommonCrypto/CommonDigest.h>

@implementation Untils
#pragma mark base32加密
+(NSString *)getDictKeys:(NSDictionary *)dic{
    
    NSMutableString *pm=[[NSMutableString alloc] init];
    for (int i=0; i<[[dic allKeys] count]; i++) {
        NSString *key1=[[dic allKeys] objectAtIndex:i];
        [pm appendFormat:@"%@,",key1];
    }
    NSString *auth=@"";
    if ([[dic allKeys] count]>0) {
        auth=[pm substringToIndex:[pm length]-1];
    }
    NSLog(@"auth=%@",auth);
    //转化二进制
    NSData * utf8encoding = [auth dataUsingEncoding:NSUTF8StringEncoding];
    // 进行位运算 再转成字符串
    auth=[self  base32StringFromData:utf8encoding];
    return auth;
}

+(NSString *)base32StringFromData:(NSData *)data
{
    NSString *encoding = nil;
    unsigned char *encodingBytes = NULL;
    @try {
        static char encodingTable[32] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        static NSUInteger paddingTable[] = {0,6,4,3,1};
        
        // Table 3: The Base 32 Alphabet
        //
        // Value Encoding Value Encoding Value Encoding Value Encoding
        // 0 A 9 J 18 S 27 3
        // 1 B 10 K 19 T 28 4
        // 2 C 11 L 20 U 29 5
        // 3 D 12 M 21 V 30 6
        // 4 E 13 N 22 W 31 7
        // 5 F 14 O 23 X
        // 6 G 15 P 24 Y (pad) =
        // 7 H 16 Q 25 Z
        // 8 I 17 R 26 2
        
        NSUInteger dataLength = [data length];
        NSUInteger encodedBlocks = (dataLength * 8) / 40;
        NSUInteger padding = paddingTable[dataLength % 5];
        if( padding > 0 ) encodedBlocks++;
        NSUInteger encodedLength = encodedBlocks * 8;
        
        encodingBytes = malloc(encodedLength);
        if( encodingBytes != NULL ) {
            NSUInteger rawBytesToProcess = dataLength;
            NSUInteger rawBaseIndex = 0;
            NSUInteger encodingBaseIndex = 0;
            unsigned char *rawBytes = (unsigned char *)[data bytes];
            unsigned char rawByte1, rawByte2, rawByte3, rawByte4, rawByte5;
            while( rawBytesToProcess >= 5 ) {
                rawByte1 = rawBytes[rawBaseIndex];
                rawByte2 = rawBytes[rawBaseIndex+1];
                rawByte3 = rawBytes[rawBaseIndex+2];
                rawByte4 = rawBytes[rawBaseIndex+3];
                rawByte5 = rawBytes[rawBaseIndex+4];
                encodingBytes[encodingBaseIndex] = encodingTable[((rawByte1 >> 3) & 0x1F)];
                encodingBytes[encodingBaseIndex+1] = encodingTable[((rawByte1 << 2) & 0x1C) | ((rawByte2 >> 6) & 0x03) ];
                encodingBytes[encodingBaseIndex+2] = encodingTable[((rawByte2 >> 1) & 0x1F)];
                encodingBytes[encodingBaseIndex+3] = encodingTable[((rawByte2 << 4) & 0x10) | ((rawByte3 >> 4) & 0x0F)];
                encodingBytes[encodingBaseIndex+4] = encodingTable[((rawByte3 << 1) & 0x1E) | ((rawByte4 >> 7) & 0x01)];
                encodingBytes[encodingBaseIndex+5] = encodingTable[((rawByte4 >> 2) & 0x1F)];
                encodingBytes[encodingBaseIndex+6] = encodingTable[((rawByte4 << 3) & 0x18) | ((rawByte5 >> 5) & 0x07)];
                encodingBytes[encodingBaseIndex+7] = encodingTable[rawByte5 & 0x1F];
                
                rawBaseIndex += 5;
                encodingBaseIndex += 8;
                rawBytesToProcess -= 5;
            }
            rawByte4 = 0;
            rawByte3 = 0;
            rawByte2 = 0;
            switch (dataLength-rawBaseIndex) {
                case 4:
                    rawByte4 = rawBytes[rawBaseIndex+3];
                case 3:
                    rawByte3 = rawBytes[rawBaseIndex+2];
                case 2:
                    rawByte2 = rawBytes[rawBaseIndex+1];
                case 1:
                    rawByte1 = rawBytes[rawBaseIndex];
                    encodingBytes[encodingBaseIndex] = encodingTable[((rawByte1 >> 3) & 0x1F)];
                    encodingBytes[encodingBaseIndex+1] = encodingTable[((rawByte1 << 2) & 0x1C) | ((rawByte2 >> 6) & 0x03) ];
                    encodingBytes[encodingBaseIndex+2] = encodingTable[((rawByte2 >> 1) & 0x1F)];
                    encodingBytes[encodingBaseIndex+3] = encodingTable[((rawByte2 << 4) & 0x10) | ((rawByte3 >> 4) & 0x0F)];
                    encodingBytes[encodingBaseIndex+4] = encodingTable[((rawByte3 << 1) & 0x1E) | ((rawByte4 >> 7) & 0x01)];
                    encodingBytes[encodingBaseIndex+5] = encodingTable[((rawByte4 >> 2) & 0x1F)];
                    encodingBytes[encodingBaseIndex+6] = encodingTable[((rawByte4 << 3) & 0x18)];
                    // we can skip rawByte5 since we have a partial block it would always be 0
                    break;
            }
            // compute location from where to begin inserting padding, it may overwrite some bytes from the partial block encoding
            // if their value was 0 (cases 1-3).
            encodingBaseIndex = encodedLength - padding;
            while( padding-- > 0 ) {
                encodingBytes[encodingBaseIndex++] = '=';
            }
            encoding = [[NSString alloc] initWithBytes:encodingBytes length:encodedLength encoding:NSASCIIStringEncoding];
        }
    }
    @catch (NSException *exception) {
        encoding = nil;
        NSLog(@"WARNING: error occured while tring to encode base 32 data: %@", exception);
    }
    @finally {
        if( encodingBytes != NULL ) {
            free( encodingBytes );
        }
    }
    return encoding;
}
#pragma mark md5加密

+(NSString *)getDictKeysValues:(NSDictionary *)dic{
    NSMutableString *pmv=[[NSMutableString alloc] init];
    for (int i=0; i<[[dic allKeys] count]; i++) {
        NSString *key1=[[dic allKeys] objectAtIndex:i];
        [pmv appendFormat:@"%@",[dic valueForKey:key1]];
    }
    NSString *ipmv = [NSString stringWithString:pmv];
    NSLog(@"ipmv=%@",ipmv);
    ipmv=[self md5Digest:ipmv];
    return ipmv;
}
+(NSString*)md5Digest:(NSString *)str{
    //32位MD5小写
    const char *cStr = [str UTF8String];
    unsigned char result[32];
    CC_MD5( cStr, (int)strlen(cStr), result );
    return [NSString stringWithFormat:
            @"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            
            result[0], result[1], result[2], result[3],
            
            result[4], result[5], result[6], result[7],
            
            result[8], result[9], result[10], result[11],
            
            result[12], result[13], result[14], result[15]
            
            ];
}




@end
