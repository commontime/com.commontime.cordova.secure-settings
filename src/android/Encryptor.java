package com.commontime.plugin;

import android.content.Context;

public interface Encryptor {
    void init(Context ctx);
    String encrypt(String source);
    String decrypt(String source);
    String getFilename();
}
