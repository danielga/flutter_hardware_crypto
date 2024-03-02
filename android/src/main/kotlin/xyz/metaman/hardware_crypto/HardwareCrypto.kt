package xyz.metaman.hardware_crypto

import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProtection
import androidx.annotation.ChecksSdkIntAtLeast
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.suspendCancellableCoroutine
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECPublicKeySpec
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PublicKey
import java.security.Signature
import java.security.cert.Certificate
import java.security.interfaces.ECPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import java.util.Calendar
import java.util.Date
import kotlin.coroutines.resume

class HardwareCrypto(private val activityBinding: ActivityPluginBinding) {
    companion object {
        const val minimumAndroidSDK = Build.VERSION_CODES.R
        const val notImplementedError = "Not implemented before Android SDK $minimumAndroidSDK"

        const val privateKeyPrefix = "-----BEGIN PRIVATE KEY-----\n"
        const val privateKeySuffix = "\n-----END PRIVATE KEY-----"
        const val privateRsaKeyPrefix = "-----BEGIN RSA PRIVATE KEY-----\n"
        const val privateRsaKeySuffix = "\n-----END RSA PRIVATE KEY-----"
    }

    private val activity: FragmentActivity = activityBinding.activity as? FragmentActivity ?:
    throw Error("Android Activity is not a FragmentActivity")

    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    private val isEmulator: Boolean
        get() = (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")
                || Build.FINGERPRINT.startsWith("generic")
                || Build.FINGERPRINT.startsWith("unknown")
                || Build.HARDWARE.contains("goldfish")
                || Build.HARDWARE.contains("ranchu")
                || Build.MODEL.contains("google_sdk")
                || Build.MODEL.contains("Emulator")
                || Build.MODEL.contains("Android SDK built for x86")
                || Build.MANUFACTURER.contains("Genymotion")
                || Build.PRODUCT.contains("sdk_google")
                || Build.PRODUCT.contains("google_sdk")
                || Build.PRODUCT.contains("sdk")
                || Build.PRODUCT.contains("sdk_x86")
                || Build.PRODUCT.contains("vbox86p")
                || Build.PRODUCT.contains("emulator")
                || Build.PRODUCT.contains("simulator"))

    @ChecksSdkIntAtLeast(api = minimumAndroidSDK)
    fun isSupported(): Boolean {
        if (Build.VERSION.SDK_INT < minimumAndroidSDK) {
            return false
        }

        if (isEmulator) {
            return true
        }

        val packageManager = activityBinding.activity.applicationContext.packageManager
        return packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    }

    private class BiometricPromptCallback(
        private val continuation: CancellableContinuation<Result<BiometricPrompt.CryptoObject>>
    ): BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
            super.onAuthenticationError(errorCode, errString)
            continuation.resume(Result.failure(Error("Error code ${errorCode}: $errString")))
        }

        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            super.onAuthenticationSucceeded(result)
            val cryptoObject = result.cryptoObject
            if (cryptoObject != null) {
                continuation.resume(Result.success(cryptoObject))
            } else {
                continuation.resume(Result.failure(Error("onAuthenticationSucceeded gave a null cryptoObject")))
            }
        }
    }

    private fun publicFromPrivateKey(privateKey: ECPrivateKey): PublicKey {
        val ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1")
        val q = ecSpec.g.multiply(privateKey.s)
        val kSpec = ECPublicKeySpec(q, ecSpec)
        val factory = KeyFactory.getInstance("ECDSA", BouncyCastleProvider())
        return factory.generatePublic(kSpec)
    }

    private fun selfSign(keyPair: KeyPair): Certificate? {
        val now = System.currentTimeMillis()
        val startDate = Date(now)
        val dnName = X500Name("cn=example")
        val certSerialNumber = BigInteger(now.toString())
        val calendar = Calendar.getInstance()
        calendar.time = startDate
        calendar.add(Calendar.YEAR, 1)
        val endDate = calendar.time
        val contentSigner = JcaContentSignerBuilder("SHA256withECDSA")
            .build(keyPair.private)
        val certBuilder = JcaX509v3CertificateBuilder(
            dnName,
            certSerialNumber,
            startDate,
            endDate,
            dnName,
            keyPair.public
        )

        val basicConstraints = BasicConstraints(true)
        certBuilder.addExtension(
            ASN1ObjectIdentifier("2.5.29.19"),
            true,
            basicConstraints
        )

        val bcProvider = BouncyCastleProvider()
        return JcaX509CertificateConverter().setProvider(bcProvider)
            .getCertificate(certBuilder.build(contentSigner))
    }

    private fun cleanUpPEMKey(key: String): String {
        return if (key.startsWith(privateKeyPrefix)) {
            key
                .trim()
                .removePrefix(privateKeyPrefix)
                .removeSuffix(privateKeySuffix)
                .replace("\\s".toRegex(), "")
        } else if (key.startsWith(privateRsaKeyPrefix)) {
            key
                .trim()
                .removePrefix(privateRsaKeyPrefix)
                .removeSuffix(privateRsaKeySuffix)
                .replace("\\s".toRegex(), "")
        } else {
            key.replace("\\s".toRegex(), "")
        }
    }

    fun importPEMKey(alias: String, key: String) {
        if (!isSupported()) {
            throw Error(notImplementedError)
        }

        val headerlessKey = cleanUpPEMKey(key)
        val privateKeySpec = PKCS8EncodedKeySpec(Base64.getDecoder().decode(headerlessKey))

        val factory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC)
        val privateKey = factory.generatePrivate(privateKeySpec) as ECPrivateKey
        val publicKeyBC = publicFromPrivateKey(privateKey)
        val publicKey = factory.translateKey(publicKeyBC) as PublicKey
        val certificate = selfSign(KeyPair(publicKey, privateKey))
            ?: throw Error("Failed to generate certificate for public key")

        keyStore.setEntry(
            alias,
            KeyStore.PrivateKeyEntry(privateKey, arrayOf(certificate)),
            KeyProtection.Builder(KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setInvalidatedByBiometricEnrollment(false)
                .setUserAuthenticationRequired(true)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build()
        )
    }

    fun generateKeyPair(alias: String) {
        if (!isSupported()) {
            throw Error(notImplementedError)
        }

        val kpg = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore"
        )
        val parameterSpec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            // Enforce strong biometric protection and authentication for every operation
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            // Use Android's StrongBox
            .setIsStrongBoxBacked(!isEmulator)
            // Don't invalidate key after changing biometrics, otherwise we lose it
            .setInvalidatedByBiometricEnrollment(false)
            // Require user authentication
            .setUserAuthenticationRequired(true)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .build()

        kpg.initialize(parameterSpec)
        kpg.generateKeyPair()

        val entry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        val factory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        val keyInfo = factory.getKeySpec(entry.privateKey, KeyInfo::class.java)
        if (!keyInfo.isUserAuthenticationRequirementEnforcedBySecureHardware && !isEmulator) {
            keyStore.deleteEntry(alias)
            throw Error("Generate keypair security is not enforced by hardware")
        }
    }

    fun exportPublicKey(alias: String): ByteArray {
        if (!isSupported()) {
            throw Error(notImplementedError)
        }

        return keyStore.getCertificate(alias).publicKey.encoded.takeLast(65).toByteArray()
    }

    fun deleteKeyPair(alias: String) {
        if (!isSupported()) {
            throw Error(notImplementedError)
        }

        keyStore.deleteEntry(alias)
    }

    suspend fun sign(alias: String, data: ByteArray): Result<ByteArray> {
        if (!isSupported()) {
            return Result.failure(Error(notImplementedError))
        }

        val entry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(entry.privateKey)

        val result = authenticate(BiometricPrompt.CryptoObject(signature))
        val cryptoObject = result.getOrElse {
            return Result.failure(it)
        }

        val authorizedSignature = cryptoObject.signature
            ?: return Result.failure(Error("CryptoObject.signature is null"))
        authorizedSignature.update(data)
        return Result.success(authorizedSignature.sign())
    }

    private suspend fun authenticate(
        cryptoObject: BiometricPrompt.CryptoObject
    ): Result<BiometricPrompt.CryptoObject> = suspendCancellableCoroutine { continuation ->
        val executor = ContextCompat.getMainExecutor(activity)
        val biometricPrompt = BiometricPrompt(
            activity,
            executor,
            BiometricPromptCallback(continuation)
        )

        continuation.invokeOnCancellation { biometricPrompt.cancelAuthentication() }

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Biometric login for my app")
            .setSubtitle("Log in using your biometric credential")
            .setNegativeButtonText("Use account password")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()

        biometricPrompt.authenticate(promptInfo, cryptoObject)
    }
}
