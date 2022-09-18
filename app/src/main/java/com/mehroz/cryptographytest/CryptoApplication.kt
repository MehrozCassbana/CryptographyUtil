package com.mehroz.cryptographytest

import android.app.Application
import com.mehroz.cryptographytest.cryptography.Cryptography

class CryptoApplication: Application() {
    override fun onCreate() {
        super.onCreate()
        /**
         * For Storing the keys in KeyStore
         */
        Cryptography.initialize(this)
    }
}