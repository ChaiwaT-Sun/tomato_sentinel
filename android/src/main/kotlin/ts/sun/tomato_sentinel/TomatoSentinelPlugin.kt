// Copyright (c) 2026 Tomato Sentinel
// Production-grade Android security implementation
// OWASP MASVS L2 Compliant

package ts.sun.tomato_sentinel

import android.content.Context
import android.os.Build
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import ts.sun.tomato_sentinel.security.*

/**
 * Tomato Sentinel Plugin - Main entry point
 * 
 * Coordinates security checks and provides Flutter interface.
 */
class TomatoSentinelPlugin : FlutterPlugin, MethodCallHandler {
    private lateinit var methodChannel: MethodChannel
    private lateinit var eventChannel: EventChannel
    private lateinit var context: Context
    
    // Security components
    private lateinit var rootDetector: RootDetector
    private lateinit var emulatorDetector: EmulatorDetector
    private lateinit var hookDetector: HookDetector
    private lateinit var tamperDetector: TamperDetector
    private lateinit var sslPinningValidator: SSLPinningValidator
    private var integrityChecker: PlayIntegrityChecker? = null

    override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        context = flutterPluginBinding.applicationContext
        
        // Initialize method channel
        methodChannel = MethodChannel(
            flutterPluginBinding.binaryMessenger,
            "tomato_sentinel"
        )
        methodChannel.setMethodCallHandler(this)
        
        // Initialize event channel
        eventChannel = EventChannel(
            flutterPluginBinding.binaryMessenger,
            "tomato_sentinel/events"
        )
        
        // Initialize security components
        initializeSecurityComponents()
    }

    private fun initializeSecurityComponents() {
        rootDetector = RootDetector(context)
        emulatorDetector = EmulatorDetector(context)
        hookDetector = HookDetector(context)
        tamperDetector = TamperDetector(context)
        sslPinningValidator = SSLPinningValidator(context)
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        try {
            when (call.method) {
                "getPlatformVersion" -> {
                    result.success("Android ${Build.VERSION.RELEASE}")
                }
                
                "isDeviceRooted" -> {
                    val isRooted = rootDetector.isDeviceRooted()
                    result.success(isRooted)
                }
                
                "isEmulator" -> {
                    val isEmulator = emulatorDetector.isEmulator()
                    result.success(isEmulator)
                }
                
                "isHooked" -> {
                    val isHooked = hookDetector.isHooked()
                    result.success(isHooked)
                }
                
                "isTampered" -> {
                    val isTampered = tamperDetector.isTampered()
                    result.success(isTampered)
                }
                
                "verifyPin" -> {
                    val domain = call.argument<String>("domain")
                    val pins = call.argument<List<String>>("pins")
                    val certChain = call.argument<String>("certificateChain")
                    
                    if (domain != null && pins != null && certChain != null) {
                        val isValid = sslPinningValidator.verifyPin(domain, pins, certChain)
                        result.success(isValid)
                    } else {
                        result.error("INVALID_ARGS", "Missing required arguments", null)
                    }
                }
                
                "initializePlayIntegrity" -> {
                    val cloudProjectNumber = call.argument<String>("cloudProjectNumber")
                    if (cloudProjectNumber != null) {
                        integrityChecker = PlayIntegrityChecker(context, cloudProjectNumber)
                        result.success(null)
                    } else {
                        result.error("INVALID_ARGS", "Missing cloud project number", null)
                    }
                }
                
                "checkIntegrity" -> {
                    if (integrityChecker != null) {
                        integrityChecker!!.checkIntegrity { integrityResult ->
                            result.success(integrityResult)
                        }
                    } else {
                        result.error("NOT_INITIALIZED", "Play Integrity not initialized", null)
                    }
                }
                
                else -> {
                    result.notImplemented()
                }
            }
        } catch (e: Exception) {
            result.error("SECURITY_ERROR", e.message, e.stackTraceToString())
        }
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        methodChannel.setMethodCallHandler(null)
    }
}
