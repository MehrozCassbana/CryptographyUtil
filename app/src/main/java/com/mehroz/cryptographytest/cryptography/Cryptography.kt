package com.mehroz.cryptographytest.cryptography

import android.annotation.TargetApi
import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.NoSuchAlgorithmException
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.security.auth.x500.X500Principal
import kotlin.math.abs

/**
 * The class is responsible for generating crypto keys [AES and RSA] in AndroidKeyStore
 *
 * It exposes only three methods to client:
 * - encrypt > to encrypt plain text format into cipher format
 * - decrypt > to decrypt cipher format into plain text
 * - initialize(Context) > must be called ONLY once (Ideally from Application class) before using
 * encrypt/decrypt as it is responsible to generate crypto keys according to OS level
 * (generate RSA key for Below Android M and AES key for Android M+ in AndroidKeyStore) as
 * Below Android M, AES key is not supported by AndroidKeyStore. So, RSA key will be used to
 * encrypt/decrypt the AES key for below Android M and then store in preferences to use later to
 * encrypt/decrypt the actual text data. Uses only AES key for encryption/decryption to the text.
 */
object Cryptography {
    private const val TAG = "CryptographyTAG"
    private const val KEY_SIZE = 256
    private const val KEY_ALIAS = "MySecretKeyAlias"
    private const val KEYSTORE_PROVIDER_ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val TYPE_AES = "AES"
    private const val TYPE_RSA = "RSA"
    private const val IV_SEPARATOR = "[IV_SEPARATE]"
    private const val SECRET_PREF = "SECRET_PREF"
    private const val SECRET_KEY_IN_PREF = "SECRET_KEY_IN_PREF"
    private const val RSA_PADDING = "RSA/NONE/PKCS1Padding"
    private const val AES_PADDING = "AES/CBC/NoPadding"
    var secretKey: SecretKey? = null
    private var preferences: SharedPreferences? = null
    private var attemptToCreateSecretKey = false

    /**
     * Generating keys [AES or RSA] according to Android OS level
     *
     * @param   context     Context
     */
    fun initialize(context: Context) {
        preferences = context.getSharedPreferences(SECRET_PREF, Context.MODE_PRIVATE)
        if (!isSigningKeyAvailable()) {
            if (isOSFromM()) {
                createSecretKeyForM()
            } else {
                createRSAKeys(context)
            }
        }
        secretKey = KeyGenerator.getInstance(TYPE_AES).apply {
            init(KEY_SIZE)
        }.generateKey()
        secretKey?.let {
            Log.d("secretKey", String(it.encoded))
        }
    }

    /**
     * Generating secret key for Android M+ in AndroidKeyStore
     */
    @TargetApi(Build.VERSION_CODES.M)
    private fun createSecretKeyForM() {
        //instance of key generator with AES in AndroidKeyStore
        val keyGenerator =
            KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                KEYSTORE_PROVIDER_ANDROID_KEYSTORE
            )
        //Reason to wrapping in try..catch is, setting StrongBox feature will throw [StrongBoxUnavailableException]
        //for the devices that doesn't support StrongBox feature for Android P+
        //So, If Android P+ devices that doesn't support hardware base AndroidKeyStore will throw
        //exception in generating key. If exception occurs, we generate key without StrongBox in catch block
        try {
            val keyGenParameterSpec = getKeyGenParameterSpec(true)
            keyGenerator.init(keyGenParameterSpec)
            keyGenerator.generateKey()
        } catch (e: Exception) {
            e.printStackTrace()
            Log.d(TAG, "Creating secret key without StrongBox as the device does not support it.")
            val keyGenParameterSpec = getKeyGenParameterSpec(false)
            keyGenerator.init(keyGenParameterSpec)
            keyGenerator.generateKey()
        }
    }

    /**
     * Generate secret keys specifications builder for Android M
     *
     * @param   setStrongBox            Boolean to set Strong box feature (Hardware based AndroidKeyStore)
     *                                  for Android P+
     * @return  [KeyGenParameterSpec]   Builder for secret key
     */
    @TargetApi(Build.VERSION_CODES.M)
    private fun getKeyGenParameterSpec(setStrongBox: Boolean): KeyGenParameterSpec {
        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setKeySize(KEY_SIZE)
            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)

        //setting strong box feature for android P+
        if (isOSFromP())
            builder.setIsStrongBoxBacked(setStrongBox)

        return builder.build()
    }

    /**
     * Getting secret (AES) key
     *
     * @return      [SecretKey]     generated secret key if available else null
     */
    private fun getSecretKey(context: Context): SecretKey? {
        return if (isOSFromM()) {
            //Getting Secret Key from AndroidKeyStore for Android M+
            getKeystore()?.let {
                val secretKeyEntry = it.getEntry(KEY_ALIAS, null) as KeyStore.SecretKeyEntry
                secretKeyEntry.secretKey
            }
        } else {
            //Getting Secret Key stored in preferences else null
            preferences?.getString(SECRET_KEY_IN_PREF, null)?.let { encodedSecretKey ->
                //decode the secret key that was stored in preferences in Base64 encoded form
                val decodedSecretKey = Base64.decode(encodedSecretKey, Base64.DEFAULT)
                //decrypt the secret key after getting the decode form of secret key
                val decryptedSecretKey = decryptSecretKeyForPreM(decodedSecretKey)
                //Create secret key object
                SecretKeySpec(decodedSecretKey, 0, decryptedSecretKey.size, TYPE_AES)
            } ?: run {
                //Generate RSA keys if not generated before
                createRSAKeys(context)
                //checking if secret key finding attempted to avoid looping infinitely
                if (!attemptToCreateSecretKey) {
                    attemptToCreateSecretKey = true
                    getSecretKey(context)
                } else null
            }
        }
    }

    /**
     * Get keystore instance from AndroidKeyStore
     *
     * @return  [KeyStore]  Keystore instance if available else null
     */
    private fun getKeystore(): KeyStore? = if (isSigningKeyAvailable()) {
        KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID_KEYSTORE).apply {
            load(null)
        }
    } else {
        null
    }

    /**
     * Generate secret (AES) key for below Android M
     */
    private fun createSecretKeyForPreM() = KeyGenerator.getInstance(TYPE_AES).apply {
        init(KEY_SIZE)
    }.generateKey()

    /**
     * Generating RSA keys [Public and Private] inside AndroidKeyStore for below android M
     */
    @Suppress("DEPRECATION")
    private fun createRSAKeys(context: Context) {
        //certificate start time
        val start: Calendar = GregorianCalendar()
        //certificate end time
        val end: Calendar = GregorianCalendar()
        //30 years for expiration of certificate
        end.add(Calendar.YEAR, 30)
        //creating certificate specifications for key generation

        val spec =
            KeyPairGeneratorSpec.Builder(context)
                // for the key!
                .setAlias(KEY_ALIAS)
                .setSubject(X500Principal("CN=$KEY_ALIAS"))
                .setSerialNumber(
                    BigInteger.valueOf(abs(KEY_ALIAS.hashCode()).toLong())
                ) // Date range of validity for the generated pair.
                .setStartDate(start.time)
                .setEndDate(end.time)
                .build()

        //get instance for AndroidKeyStore
        val kpGenerator =
            KeyPairGenerator.getInstance(TYPE_RSA, KEYSTORE_PROVIDER_ANDROID_KEYSTORE)
        //initialize for RSA key generation
        kpGenerator.initialize(spec)
        //generate RSA keys inside AndroidKeyStore
        kpGenerator.generateKeyPair()
        //Creating secret (AES) key for encryption/decryption, RSA will not be used for that
        val secretKey = createSecretKeyForPreM()
        Log.d(TAG, String(secretKey.encoded))
        //Encrypt generated secret key
        val encryptedSecretKey = encryptSecretKeyForPreM(secretKey)
        //Encode encrypted secret key to Base64
        val encodedSecretKey = Base64.encodeToString(encryptedSecretKey, Base64.DEFAULT)
        //store encrypted secret key in Base64 encoded form
        preferences?.edit()?.putString(SECRET_KEY_IN_PREF, encodedSecretKey)?.apply()
    }

    /**
     * Getting RSA keys [public and private] from keystore
     *
     * @return      [Pair<RSAPrivateKey, RSAPublicKey>] pair of RSA keys
     */
    private fun getRSAPairKeys(): Pair<RSAPrivateKey, RSAPublicKey> {
        val privateKeyEntry = getKeystore()?.getEntry(KEY_ALIAS, null) as KeyStore.PrivateKeyEntry
        val privateKey = privateKeyEntry.privateKey as RSAPrivateKey
        val publicKey = privateKeyEntry.certificate.publicKey as RSAPublicKey
        Log.d(TAG, Base64.encodeToString(privateKeyEntry.certificate.encoded, Base64.DEFAULT))
        return Pair(privateKey, publicKey)
    }

    /**
     * Encrypt AES key with RSA public key for below Android M
     *
     * @param       secretKey       plain AES key
     * @return      [ByteArray]     encrypted AES key
     */
    private fun encryptSecretKeyForPreM(secretKey: SecretKey): ByteArray {
        val publicKey = getRSAPairKeys().second
        val cipher = Cipher.getInstance(RSA_PADDING)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        return cipher.doFinal(secretKey.encoded)
    }

    /**
     * Decrypt AES key with RSA private key for below Android M
     *
     * @param   decodedSecretKey  Base64 decoded [encrypted secret key] that was stored in preferences
     *                            in Base64 encoded form
     * @return  [ByteArray]       Decrypted secret key
     */
    private fun decryptSecretKeyForPreM(decodedSecretKey: ByteArray): ByteArray {
        val privateKey = getRSAPairKeys().first
        val cipher = Cipher.getInstance(RSA_PADDING)
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return cipher.doFinal(decodedSecretKey)
    }

    /**
     * Encrypt the plain text into cipher format
     *
     * @param   plaintText      plain text
     * @return  [String]        cipher return if the params and secret key are not null else plaintext
     */
    fun encrypt(plaintText: String?): String? {
        return if (!plaintText.isNullOrEmpty() && secretKey != null) {
            var finalEncryptedText = ""
            val cipher = Cipher.getInstance(AES_PADDING)
            var temp: String = plaintText
            while (temp.toByteArray().size % KEY_SIZE != 0) {
                temp += "\u0020"
            }
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            val ivBytes = cipher.iv
            finalEncryptedText += "${Base64.encodeToString(ivBytes, Base64.DEFAULT)}$IV_SEPARATOR"
            val encryptedBytes = cipher.doFinal(temp.toByteArray(Charsets.UTF_8))
            finalEncryptedText += Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
            finalEncryptedText
        } else plaintText
    }

    /**
     * Decrypt the cipher formatted text
     *
     * @param   encryptedText   cipher formatted text
     * @return  [String]        plaintext return if the params and secret key are not null else ciphered text
     */
    fun decrypt(encryptedText: String?): String? {
        return if (!encryptedText.isNullOrEmpty() && secretKey != null) {
            val splitData = encryptedText.split(IV_SEPARATOR)
            val iv = Base64.decode(splitData[0], Base64.DEFAULT)
            val cipher = Cipher.getInstance(AES_PADDING)
            val spec = IvParameterSpec(iv)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
            return String(cipher.doFinal(Base64.decode(splitData[1], Base64.DEFAULT))).trim()
        } else encryptedText
    }

    /**
     * Decrypt the cipher formatted text
     *
     * @param   encryptedText   cipher formatted text
     * @param   secretKey       externally retrieved secret key as String
     * @return  [String]        plaintext return if the params and secret key are not null else ciphered text
     */
    fun decrypt(encryptedText: String?, secretKey: String?): String? {
        // decode the base64 encoded string
        val originalKey = convertStringToSecretKey(secretKey)
        return if (!encryptedText.isNullOrEmpty() && secretKey != null) {
            val splitData = encryptedText.split(IV_SEPARATOR)
            val iv = Base64.decode(splitData[0], Base64.DEFAULT)
            val cipher = Cipher.getInstance(AES_PADDING)
            val spec = IvParameterSpec(iv)
            cipher.init(Cipher.DECRYPT_MODE, originalKey, spec)
            return String(cipher.doFinal(Base64.decode(splitData[1], Base64.DEFAULT))).trim()
        } else encryptedText
    }

    @Throws(NoSuchAlgorithmException::class)
    fun convertSecretKeyToString(secretKey: SecretKey): String? {
        val rawData = secretKey.encoded
        return Base64.encodeToString(rawData, Base64.DEFAULT)
    }

    fun convertStringToSecretKey(encodedKey: String?): SecretKey {
        val decodedKey: ByteArray = Base64.decode(encodedKey, Base64.DEFAULT)
        return SecretKeySpec(decodedKey, 0, decodedKey.size, TYPE_AES)
    }

    /**
     * If Key with the default alias exists, returns true, else false.
     * on pre-JBMR2 returns true always.
     */
    private fun isSigningKeyAvailable(): Boolean {
        return try {
            val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID_KEYSTORE)
            keyStore.load(null)
            keyStore.containsAlias(KEY_ALIAS)
        } catch (e: java.lang.Exception) {
            Log.e(TAG, e.message, e)
            false
        }
    }

    private fun isOSFromM() = true
    private fun isOSFromP() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
}