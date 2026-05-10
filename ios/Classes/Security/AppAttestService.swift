// Copyright (c) 2026 Tomato Sentinel
// App Attest integration

import Foundation
import DeviceCheck

@available(iOS 14.0, *)
class AppAttestService {
    private let keyId: String
    private let service: DCAppAttestService
    
    init(keyId: String) {
        self.keyId = keyId
        self.service = DCAppAttestService.shared
    }
    
    func checkIntegrity(completion: @escaping ([String: Any]) -> Void) {
        guard service.isSupported else {
            completion([
                "isValid": false,
                "error": "App Attest not supported on this device"
            ])
            return
        }
        
        // Generate key if needed
        service.generateKey { [weak self] keyId, error in
            guard let self = self else { return }
            
            if let error = error {
                completion([
                    "isValid": false,
                    "error": error.localizedDescription
                ])
                return
            }
            
            guard let keyId = keyId else {
                completion([
                    "isValid": false,
                    "error": "Failed to generate key"
                ])
                return
            }
            
            // Attest the key
            let challenge = self.generateChallenge()
            self.service.attestKey(keyId, clientDataHash: challenge) { attestation, error in
                if let error = error {
                    completion([
                        "isValid": false,
                        "error": error.localizedDescription
                    ])
                    return
                }
                
                completion([
                    "isValid": true,
                    "keyId": keyId,
                    "attestation": attestation?.base64EncodedString() ?? "",
                    "isKeyValid": true
                ])
            }
        }
    }
    
    private func generateChallenge() -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes)
    }
}
