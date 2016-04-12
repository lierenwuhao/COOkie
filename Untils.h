//
//  Untils.h
//  TestDemo
//
//  Created by MS on 15/12/16.
//  Copyright © 2015年 LjxProduct. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface Untils : NSObject
//base32 auth加密
+(NSString *)getDictKeys:(NSDictionary *)dic;
//md5加密
+(NSString *)getDictKeysValues:(NSDictionary *)dic;
@end
