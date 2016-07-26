# Secure Settings

The Secure Settings plugin provides two related facilities:

* to store name/value string pairs inside the device's secure store (KeyChain on iOS and OS X, KeyStore on Android)
* to generate and securely store cryptographic keys

## Calls

### plugins.securesettings.get

Retrieve the string value associated with the given name.

```javascript
function successCallback (value) {
  if (typeof value === 'string') {
    // a value for name was previously set
  } else {
    // no value for name was previously set
  }  
}

function errorCallback (message) {
  // an error occurred, detailed in the given message  
}

plugins.securesettings.get(successCallback, errorCallback, name)
```

### plugins.securesettings.set

Sets the string value to be associated with the given name. Passing a null string as the value will remove the association.

```javascript
function successCallback () {
  // The value was successfully set
}

function errorCallback (message) {
  // an error occurred, detailed in the given message  
}

plugins.securesettings.set(successCallback, errorCallback, name, value)
```

### plugins.securesettings.createCryptographicKey

Creates a cryptographic key with the given length, in bits (which should be divisible by 8). The returned key is specified hex string.

```javascript
function successCallback (key) {
  // key is a hexstring specifying the given key (and whose length
  // is keyLengthInBits / 4)
}

function errorCallback (message) {
  // an error occurred, detailed in the given message  
}

plugins.securesettings.createCryptographicKey(successCallback, errorCallback, keyLengthInBits)
```

### plugins.securesettings.getOrCreateCryptographicKey

Retrieves the cryptographic key associate with the given name or, if one doesn't exist, creates one and associates it with the given name. Note, this is defined purely in terms of the preceding functions, i.e., there is no native component.

```javascript
function successCallback (key) {
  // key is a hexstring specifying the given key (and whose length
  // is keyLengthInBits / 4)
}

function errorCallback (message) {
  // an error occurred, detailed in the given message  
}

plugins.securesettings.getOrCreateCryptographicKey(successCallback, errorCallback, name, keyLengthInBits)
```
