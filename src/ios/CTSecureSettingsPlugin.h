//
//  CTSecureSettingsPlugin.h
//  mDesign 10
//
//  Created by Gary Meehan on 28/03/2016.
//  Copyright (c) 2016 CommonTime Limited. All rights reserved.
//

#import <Cordova/CDV.h>

@interface CTSecureSettingsPlugin : CDVPlugin

- (void) get: (CDVInvokedUrlCommand*) command;

- (void) set: (CDVInvokedUrlCommand*) command;

- (void) createCryptographicKey: (CDVInvokedUrlCommand*) command;

@end