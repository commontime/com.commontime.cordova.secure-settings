var cryptoKeyName = '__crypto_key__'

function getOrCreateCryptographicKey () {
  function success (key) {
    window.alert(key)
  }

  function error (message) {
    window.alert(message)
  }

  plugins.securesettings.getOrCreateCryptographicKey(success, error, cryptoKeyName, 512)
}

function clearCryptographicKey () {
  function success () {
    window.alert('Cleared Key!')
  }

  function error (message) {
    window.alert(message)
  }

  plugins.securesettings.set(success, error, cryptoKeyName, null)
}
