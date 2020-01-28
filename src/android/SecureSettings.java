package com.commontime.plugin;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Semaphore;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.security.auth.x500.X500Principal;

public class SecureSettings extends CordovaPlugin {

    private final String PREFS_FILE_KEY = "securesettingsplugin";

    private KeyStore ks;
    private SharedPreferences sharedPref;
    private KeyPair newKeyPair;

    private static Semaphore semaphore = new Semaphore(1);

    @Override
    public boolean execute(String action, final JSONArray data, final CallbackContext callbackContext) throws JSONException
    {
        try {
            semaphore.acquire();
        } catch (InterruptedException e) {
            Log.e("SECURE", "Serious Semaphore error: " + e);
            e.printStackTrace();
            return true;
        }

        ks = null;
        sharedPref = null;

        setKeyStoreInstanceIfRequired();
        setSharedPrefsIfRequired();

        if(action.equals("get"))
        {
            if(data.length() < 1)
            {
                callbackContext.error("Incorrect number of arguments.");
                semaphore.release();
                return true;
            }

            final String name = data.getString(0);

            if(name == null)
            {
                callbackContext.error("Name must be a string.");
                semaphore.release();
                return true;
            }

            get(callbackContext, name);
        }
        else if(action.equals("set"))
        {
            if(data.length() < 2)
            {
                callbackContext.error("Incorrect number of arguments.");
                semaphore.release();
                return true;
            }

            final String name = data.getString(0);
            final String value = data.getString(1);

            if(name == null || value == null)
            {
                callbackContext.error("Name and value must be a string.");
                semaphore.release();
                return true;
            }

            set(callbackContext, name, value);
        }
        else if(action.equals("createCryptographicKey"))
        {
            if(data.length() < 1)
            {
                callbackContext.error("Incorrect number of arguments.");
                semaphore.release();
                return true;
            }

            final int numBits  = data.getInt(0);

            if (numBits <= 0 || numBits % 8 != 0)
            {
                callbackContext.error("Bad length");
                semaphore.release();
                return true;
            }

            createCryptographicKey(callbackContext, numBits);
        }

        semaphore.release();
        return true;
    }

    private void get(CallbackContext callbackContext, String alias)
    {
        try
        {
            if(ks == null || sharedPref == null)
                throw new Exception();

            if(useKeyStore())
            {
                PrivateKey privateKey = (PrivateKey) ks.getKey(alias, null);

                if (privateKey == null) {
                    callbackContext.success(0);
                    return;
                }
            }

            String encryptedString = sharedPref.getString(alias, null);

            if (encryptedString == null)
            {
                callbackContext.success(0);
                return;
            }

            String decryptedString = decryptString(alias, encryptedString);

            callbackContext.success(decryptedString);
        }
        catch (Exception e)
        {
            e.printStackTrace();
            callbackContext.error("Unable to get the value");
        }
    }

    private void set(CallbackContext callbackContext, String alias, String value)
    {
        try
        {
            if(ks == null || sharedPref == null || value == null)
                throw new Exception();

            if (value.equals("null"))
            {
                boolean deleted = deleteEntry(alias);
                if (deleted)
                    callbackContext.success();
                else
                    callbackContext.error("Unable to delete value");
                return;
            }

            if(useKeyStore())
            {
                if (!ks.containsAlias(alias))
                {
                    newKeyPair = createKeyPair(alias);

                    if (newKeyPair == null)
                    {
                        callbackContext.error("Unable to create key from alias");
                        return;
                    }
                }
            }

            String encryptedText = encryptString(alias, value);

            sharedPref.edit().putString(alias, encryptedText).commit();

            if(encryptedText != null)
                callbackContext.success();
            else
                callbackContext.error("Unable to set the value");
        }
        catch (Exception e)
        {
            e.printStackTrace();
            callbackContext.error("Unable to set the value");
        }
    }

    private KeyPair createKeyPair(String alias)
    {
        try
        {
            KeyPair kp = null;
            KeyPairGenerator generator = KeyPairGenerator .getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            if(Build.VERSION.SDK_INT > Build.VERSION_CODES.M)
            {
                KeyGenParameterSpec spec = new  KeyGenParameterSpec.Builder(
                        alias,
                        KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT )
                        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                        .build();
                generator.initialize(spec);
                kp = generator.generateKeyPair();
            }
            else
            {
                final Locale localeBeforeFakingEnglishLocale = Locale.getDefault();
                setFakeEnglishLocale();
                Calendar start = Calendar.getInstance();
                Calendar end = Calendar.getInstance();
                end.add(Calendar.YEAR, 1);
                KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(cordova.getActivity())
                        .setAlias(alias)
                        .setSubject(new X500Principal("CN=Sample Name, O=Android Authority"))
                        .setSerialNumber(BigInteger.ONE)
                        .setStartDate(start.getTime())
                        .setEndDate(end.getTime())
                        .build();
                generator.initialize(spec);
                kp = generator.generateKeyPair();
                setLocale(localeBeforeFakingEnglishLocale);
            }
            return kp;
        }
        catch(Exception e)
        {
            e.printStackTrace();
            return null;
        }
    }

    private void createCryptographicKey(CallbackContext callbackContext, int numBits)
    {
        int bytes = (int) numBits / 8;
        byte[] buffer = new byte[bytes];
        randomBytes(buffer);
        String key = hexStringFromBytes(buffer, bytes);
        if(key != null)
            callbackContext.success(key);
        else
            callbackContext.error("Unable to generate key");
    }

    private void randomBytes(byte[] buffer)
    {
        SecureRandom random = new SecureRandom();
        random.nextBytes(buffer);
    }

    private boolean deleteEntry(String alias)
    {
        try
        {
            if(ks == null || sharedPref == null)
                throw new Exception();

            sharedPref.edit().remove(alias).commit();

            if(useKeyStore())
                ks.deleteEntry(alias);

            return true;
        }
        catch (Exception e)
        {
            return false;
        }
    }

    private String encryptString(String alias, String value)
    {
        if(useKeyStore())
            return encryptKeystore(alias, value);
        else
            return encryptEncryptor(value);
    }

    private String encryptKeystore(String alias, String value)
    {
        try
        {
            if(ks == null || sharedPref == null)
                throw new Exception();

            if(value.isEmpty())
                throw new Exception();

            RSAPublicKey publicKey = null;

            if(newKeyPair != null)
            {
                publicKey = (RSAPublicKey) newKeyPair.getPublic();
                newKeyPair = null;
            }
            else
            {
                publicKey = (RSAPublicKey) ks.getCertificate(alias).getPublicKey();
            }

            if(publicKey == null)
                return null;

            Cipher input;

            if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                OAEPParameterSpec sp = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT);
                input = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                input.init(Cipher.ENCRYPT_MODE, publicKey, sp);
            } else {
                input = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
                input.init(Cipher.ENCRYPT_MODE, publicKey);
            }

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(
                    outputStream, input);
            cipherOutputStream.write(value.getBytes("UTF-8"));
            cipherOutputStream.close();

            byte [] vals = outputStream.toByteArray();
            return Base64.encodeToString(vals, Base64.DEFAULT);
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return null;
        }
    }

    private String encryptEncryptor(String value)
    {
        return GaryEncryptor.get().encrypt(value);
    }

    private String decryptString(String alias, String value)
    {
        if(useKeyStore())
            return decryptKeystore(alias, value);
        else
            return decryptEncryptor(value);
    }

    private String decryptKeystore(String alias, String value)
    {
        try
        {
            if(ks == null || sharedPref == null)
                throw new Exception();

            PrivateKey privateKey = null;

            if(newKeyPair != null)
            {
                privateKey = newKeyPair.getPrivate();
                newKeyPair = null;
            }
            else
            {
                privateKey = (PrivateKey) ks.getKey(alias, null);
            }

            if(privateKey == null)
                return null;

            Cipher output;

            if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                OAEPParameterSpec sp = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
                output = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                output.init(Cipher.DECRYPT_MODE, privateKey, sp);
            } else {
                output = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
                output.init(Cipher.DECRYPT_MODE, privateKey);
            }

            CipherInputStream cipherInputStream = new CipherInputStream(
                    new ByteArrayInputStream(Base64.decode(value, Base64.DEFAULT)), output);
            ArrayList<Byte> values = new ArrayList<Byte>();
            int nextByte;
            while ((nextByte = cipherInputStream.read()) != -1) {
                values.add((byte)nextByte);
            }

            byte[] bytes = new byte[values.size()];
            for(int i = 0; i < bytes.length; i++) {
                bytes[i] = values.get(i).byteValue();
            }

            return new String(bytes, 0, bytes.length, "UTF-8");
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return null;
        }
    }

    private String decryptEncryptor(String value)
    {
        return GaryEncryptor.get().decrypt(value);
    }

    private void setKeyStoreInstanceIfRequired()
    {
        if(ks == null)
        {
            try
            {
                ks = KeyStore.getInstance("AndroidKeyStore");
                ks.load(null);
            }
            catch(Exception e) {}
        }
    }

    private void setSharedPrefsIfRequired()
    {
        try
        {
            Context context = cordova.getActivity();
            sharedPref = context.getSharedPreferences(PREFS_FILE_KEY, Context.MODE_PRIVATE);
        }
        catch(Exception e) {}
    }

    private boolean useKeyStore()
    {
        if(Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP)
            return false;
        else
            return true;
    }

    static String hexStringFromBytes(byte[] bytes, int length)
    {
        if (bytes != null)
        {
            if (length == 0)
            {
                return "";
            }
            else
            {
                String string = "";

                for (int i = 0; i < length; i++)
                {
                    string = string + String.format("%02x", bytes[i]);
                }

                return string;
            }
        }
        else
        {
            return null;
        }
    }

    /**
     * Workaround for known date parsing issue in KeyPairGenerator class
     * https://issuetracker.google.com/issues/37095309
     */
    private void setFakeEnglishLocale() {
        setLocale(Locale.ENGLISH);
    }

    private void setLocale(final Locale locale) {
        Locale.setDefault(locale);
        final Resources resources = cordova.getActivity().getResources();
        final Configuration config = resources.getConfiguration();
        config.locale = locale;
        resources.updateConfiguration(config, resources.getDisplayMetrics());
    }
}
