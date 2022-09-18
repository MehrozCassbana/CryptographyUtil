package com.mehroz.cryptographytest

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Base64
import android.util.Log
import com.mehroz.cryptographytest.cryptography.Cryptography
import com.mehroz.cryptographytest.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        testEncryption()
    }

    private fun testEncryption() {
        binding.encryptBtn.setOnClickListener {
            if (binding.enterTextEdt.text.toString().isNotEmpty())
                binding.encryptedText.text = Cryptography.encrypt(binding.enterTextEdt.text.toString())
            Log.d("OriginalText",binding.enterTextEdt.text.toString())
            Log.d("EncryptedText",binding.encryptedText.text.toString())
        }

        binding.decryptBtn.setOnClickListener {
            Cryptography.secretKey?.let {
                Log.d("SecretKey", Cryptography.convertSecretKeyToString(it)!!)
                binding.decryptedText.text = Cryptography.decrypt(binding.encryptedText.text.toString(), Cryptography.convertSecretKeyToString(it))
            }
        }
    }
}