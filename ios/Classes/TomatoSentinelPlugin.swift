// Copyright (c) 2026 Tomato Sentinel
// Production-grade iOS security implementation
// OWASP MASVS L2 Compliant

import Flutter
import UIKit

public class TomatoSentinelPlugin: NSObject, FlutterPlugin {
    private var jailbreakDetector: JailbreakDetector!
    private var simulatorDetector: SimulatorDetector!
    private var hookDetector: HookDetector!
    private var tamperDetector: TamperDetector!
    private var sslPinningValidator: SSLPinningValidator!
    private var appAttestService: AppAttestService?
    
    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(
            name: "tomato_sentinel",
            binaryMessenger: registrar.messenger()
        )
        let instance = TomatoSentinelPlugin()
        instance.initializeSecurityComponents()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }
    
    private func initializeSecurityComponents() {
        jailbreakDetector = JailbreakDetector()
        simulatorDetector = SimulatorDetector()
        hookDetector = HookDetector()
        tamperDetector = TamperDetector()
        sslPinningValidator = SSLPinningValidator()
    }
    
    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "getPlatformVersion":
            result("iOS " + UIDevice.current.systemVersion)
            
        case "isDeviceRooted":
            let isJailbroken = jailbreakDetector.isJailbroken()
            result(isJailbroken)
            
        case "isEmulator":
            let isSimulator = simulatorDetector.isSimulator()
            result(isSimulator)
            
        case "isHooked":
            let isHooked = hookDetector.isHooked()
            result(isHooked)
            
        case "isTampered":
            let isTampered = tamperDetector.isTampered()
            result(isTampered)
            
        case "verifyPin":
            guard let args = call.arguments as? [String: Any],
                  let domain = args["domain"] as? String,
                  let pins = args["pins"] as? [String],
                  let certChain = args["certificateChain"] as? String else {
                result(FlutterError(
                    code: "INVALID_ARGS",
                    message: "Missing required arguments",
                    details: nil
                ))
                return
            }
            
            let isValid = sslPinningValidator.verifyPin(
                domain: domain,
                pins: pins,
                certificateChain: certChain
            )
            result(isValid)
            
        case "initializeAppAttest":
            guard let args = call.arguments as? [String: Any],
                  let keyId = args["keyId"] as? String else {
                result(FlutterError(
                    code: "INVALID_ARGS",
                    message: "Missing key ID",
                    details: nil
                ))
                return
            }
            
            appAttestService = AppAttestService(keyId: keyId)
            result(nil)
            
        case "checkIntegrity":
            guard let attestService = appAttestService else {
                result(FlutterError(
                    code: "NOT_INITIALIZED",
                    message: "App Attest not initialized",
                    details: nil
                ))
                return
            }
            
            attestService.checkIntegrity { integrityResult in
                result(integrityResult)
            }
            
        default:
            result(FlutterMethodNotImplemented)
        }
    }
}
