
var argscheck = require('cordova/argscheck'), exec = require('cordova/exec')

module.exports = {
  get: function (successCallback, errorCallback, name) {
    cordova.exec(successCallback, errorCallback, 'SecureSettings', 'get', [name])
  },

  set: function (successCallback, errorCallback, name, value) {
    cordova.exec(successCallback, errorCallback, 'SecureSettings', 'set', [name, value])
  },

  createCryptographicKey: function (successCallback, errorCallback, keyLengthInBits) {
    cordova.exec(successCallback, errorCallback, 'SecureSettings', 'createCryptographicKey', [keyLengthInBits])
  },

  getOrCreateCryptographicKey: function (successCallback, errorCallback, name, keyLengthInBits) {
    function onCreateCryptographicKeySucceeded (key) {
      plugins.securesettings.set(function () { successCallback(key) }, errorCallback, name, key)
    }

    function onGetSucceeded (value) {
      if (typeof value === 'string') {
        successCallback(value)
      } else {
        plugins.securesettings.createCryptographicKey(onCreateCryptographicKeySucceeded, errorCallback, keyLengthInBits)
      }
    }

    plugins.securesettings.get(onGetSucceeded, errorCallback, name)
  }
}
