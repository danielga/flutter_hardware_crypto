package xyz.metaman.hardware_crypto

import androidx.lifecycle.coroutineScope
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.embedding.engine.plugins.lifecycle.FlutterLifecycleAdapter
import kotlinx.coroutines.launch

class HardwareCryptoPlugin: FlutterPlugin, ActivityAware, HardwareCryptoApi {
    private var hardwareCrypto: HardwareCrypto? = null
    private var activityBinding: ActivityPluginBinding? = null

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        HardwareCryptoApi.setUp(binding.binaryMessenger, this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        HardwareCryptoApi.setUp(binding.binaryMessenger, null)
        activityBinding = null
        hardwareCrypto = null
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activityBinding = binding
        hardwareCrypto = HardwareCrypto(binding)
    }

    override fun onDetachedFromActivityForConfigChanges() {}

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        activityBinding = binding
        hardwareCrypto = HardwareCrypto(binding)
    }

    override fun onDetachedFromActivity() {}

    override fun isSupported(): Boolean {
        val hardwareCrypto = this.hardwareCrypto ?: throw Error("HardwareCrypto not initialized")
        return hardwareCrypto.isSupported()
    }

    override fun importPEMKey(alias: String, key: String, callback: (Result<Unit>) -> Unit) {
        try {
            val hardwareCrypto = this.hardwareCrypto ?: throw Error("HardwareCrypto not initialized")
            hardwareCrypto.importPEMKey(alias, key)
            callback(Result.success(Unit))
        } catch (e: Throwable) {
            callback(Result.failure(e))
        }
    }

    override fun generateKeyPair(alias: String, callback: (Result<Unit>) -> Unit) {
        try {
            val hardwareCrypto = this.hardwareCrypto ?: throw Error("HardwareCrypto not initialized")
            hardwareCrypto.generateKeyPair(alias)
            callback(Result.success(Unit))
        } catch (e: Throwable) {
            callback(Result.failure(e))
        }
    }

    override fun exportPublicKey(alias: String, callback: (Result<ByteArray>) -> Unit) {
        try {
            val hardwareCrypto = this.hardwareCrypto ?: throw Error("HardwareCrypto not initialized")
            val publicKey = hardwareCrypto.exportPublicKey(alias)
            callback(Result.success(publicKey))
        } catch (e: Throwable) {
            callback(Result.failure(e))
        }
    }

    override fun deleteKeyPair(alias: String, callback: (Result<Unit>) -> Unit) {
        try {
            val hardwareCrypto = this.hardwareCrypto ?: throw Error("HardwareCrypto not initialized")
            hardwareCrypto.deleteKeyPair(alias)
            callback(Result.success(Unit))
        } catch (e: Throwable) {
            callback(Result.failure(e))
        }
    }

    override fun sign(alias: String, data: ByteArray, callback: (Result<ByteArray>) -> Unit) {
        try {
            val activityBinding = this.activityBinding ?: throw Error("ActivityPluginBinding not initialized")
            val hardwareCrypto = this.hardwareCrypto ?: throw Error("HardwareCrypto not initialized")
            val lifecycle = FlutterLifecycleAdapter.getActivityLifecycle(activityBinding)
            lifecycle.coroutineScope.launch {
                try {
                    callback(hardwareCrypto.sign(alias, data))
                } catch (e: Throwable) {
                    callback(Result.failure(e))
                }
            }
        } catch (e: Throwable) {
            callback(Result.failure(e))
        }
    }
}