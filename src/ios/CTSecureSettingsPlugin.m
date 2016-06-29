//
//  CTSecureSettingsPlugin.m
//  mDesign 10
//
//  Created by Gary Meehan on 28/03/2016.
//  Copyright (c) 2016 CommonTime Limited. All rights reserved.
//

#import "CTSecureSettingsPlugin.h"

#import "UICKeyChainStore.h"

static NSString* CTHexStringFromBytes(const uint8_t* bytes, size_t length)
{
  if (bytes)
  {
    if (length == 0)
    {
      return @"";
    }
    else
    {
      NSMutableString* string = [NSMutableString stringWithCapacity: length * 2];
      
      for (size_t i = 0; i != length; ++i)
      {
        [string appendFormat: @"%02x", bytes[i]];
      }
      
      return string;
    }
  }
  else
  {
    return nil;
  }
}

@implementation CTSecureSettingsPlugin

- (void) get: (CDVInvokedUrlCommand*) command
{
  @try
  {
    if (command.arguments.count < 1)
    {
      CDVPluginResult* result = [CDVPluginResult resultWithStatus: CDVCommandStatus_ERROR
                                                  messageAsString: @"incorrent number of arguments"];
      
      [self.commandDelegate sendPluginResult: result callbackId: command.callbackId];
      
      return;
    }
    
    id name = command.arguments[0];
    
    if (![name isKindOfClass: [NSString class]])
    {
      CDVPluginResult* result = [CDVPluginResult resultWithStatus: CDVCommandStatus_ERROR
                                                  messageAsString: @"bad type for name"];
      
      [self.commandDelegate sendPluginResult: result callbackId: command.callbackId];
      
      return;
    }
    
    NSString* value = [UICKeyChainStore stringForKey: name];
    
    CDVPluginResult* result = [CDVPluginResult resultWithStatus: CDVCommandStatus_OK
                                                messageAsString: value];
    
    [self.commandDelegate sendPluginResult: result callbackId: command.callbackId];
  }
  @catch (NSException *exception)
  {
    CDVPluginResult* result = [CDVPluginResult resultWithStatus: CDVCommandStatus_ERROR
                                                messageAsString: [exception reason]];
    
    [self.commandDelegate sendPluginResult: result callbackId: command.callbackId];
  }
}

- (void) set: (CDVInvokedUrlCommand*) command
{
  @try
  {
    if (command.arguments.count < 2)
    {
      CDVPluginResult* result = [CDVPluginResult resultWithStatus: CDVCommandStatus_ERROR
                                                  messageAsString: @"incorrent number of arguments"];
      
      [self.commandDelegate sendPluginResult: result callbackId: command.callbackId];

      return;
    }
    
    id name = command.arguments[0];
    
    if (![name isKindOfClass: [NSString class]])
    {
      CDVPluginResult* result = [CDVPluginResult resultWithStatus: CDVCommandStatus_ERROR
                                                  messageAsString: @"bad type for name"];
      
      [self.commandDelegate sendPluginResult: result callbackId: command.callbackId];
      
      return;
    }
    
    id value = command.arguments[1];

    if ([value isKindOfClass: [NSString class]])
    {
      [UICKeyChainStore setString: value forKey: name];

      CDVPluginResult* result = [CDVPluginResult resultWithStatus: CDVCommandStatus_OK];
      
      [self.commandDelegate sendPluginResult: result callbackId: command.callbackId];
    }
    else if ([value isKindOfClass: [NSNull class]])
    {
      [UICKeyChainStore removeItemForKey: name];
      
      CDVPluginResult* result = [CDVPluginResult resultWithStatus: CDVCommandStatus_OK];
      
      [self.commandDelegate sendPluginResult: result callbackId: command.callbackId];
    }
    else
    {
      CDVPluginResult* result = [CDVPluginResult resultWithStatus: CDVCommandStatus_ERROR
                                                  messageAsString: @"bad type for value"];
      
      [self.commandDelegate sendPluginResult: result callbackId: command.callbackId];
    
    }
  }
  @catch (NSException *exception)
  {
    CDVPluginResult* result = [CDVPluginResult resultWithStatus: CDVCommandStatus_ERROR
                                                messageAsString: [exception reason]];
    
    [self.commandDelegate sendPluginResult: result callbackId: command.callbackId];
  }
}

- (void) createCryptographicKey: (CDVInvokedUrlCommand*) command
{
  @try
  {
    if (command.arguments.count < 1)
    {
      CDVPluginResult* result = [CDVPluginResult resultWithStatus: CDVCommandStatus_ERROR
                                                  messageAsString: @"incorrent number of arguments"];
      
      [self.commandDelegate sendPluginResult: result callbackId: command.callbackId];
      
      return;
    }
 
    int numBits = [command.arguments[0] intValue];
    
    if (numBits <= 0 || numBits % 8 != 0)
    {
      CDVPluginResult* result = [CDVPluginResult resultWithStatus: CDVCommandStatus_ERROR
                                                  messageAsString: @"bad length"];
      
      [self.commandDelegate sendPluginResult: result callbackId: command.callbackId];
      
      return;
    }
    
    size_t numBytes = (size_t) numBits / 8;
    uint8_t buffer[numBytes];
    
    int result = SecRandomCopyBytes(kSecRandomDefault, numBytes, buffer);
    
    if (result == 0)
    {
      NSString* key = CTHexStringFromBytes(buffer, numBytes);
      
      CDVPluginResult* result = [CDVPluginResult resultWithStatus: CDVCommandStatus_OK
                                                  messageAsString: key];
      
      [self.commandDelegate sendPluginResult: result callbackId: command.callbackId];
    }
    else
    {
      CDVPluginResult* result = [CDVPluginResult resultWithStatus: CDVCommandStatus_ERROR
                                                  messageAsString: @"couldn't generate key"];
      
      [self.commandDelegate sendPluginResult: result callbackId: command.callbackId];
    }
  }
  @catch (NSException *exception)
  {
    CDVPluginResult* result = [CDVPluginResult resultWithStatus: CDVCommandStatus_ERROR
                                                messageAsString: [exception reason]];
    
    [self.commandDelegate sendPluginResult: result callbackId: command.callbackId];
  }
}

@end