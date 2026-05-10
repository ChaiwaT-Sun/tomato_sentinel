// Copyright (c) 2026 Tomato Sentinel
// OWASP MASVS: MSTG-NETWORK-4

import Foundation
import CommonCrypto

class SSLPinningValidator {
    func verifyPin(domain: String, pins: [String], certificateChain: String) -> Bool {
        guard let certData = Data(base64Encoded: certificateChain) else {
            return false
        }
        
        guard let certificate = SecCertificateCreateWithData(nil, certData as CFData) else {
            return false
        }
        
        let spkiHash = computeSPKIHash(certificate: certificate)
        return pins.contains(spkiHash)
    }
    
    private func computeSPKIHash(certificate: SecCertificate) -> String {
        guard let publicKey = SecCertificateCopyKey(certificate) else {
            return ""
        }
        
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            return ""
        }
        
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        publicKeyData.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(publicKeyData.count), &hash)
        }
        
        return Data(hash).base64EncodedString()
    }
}
