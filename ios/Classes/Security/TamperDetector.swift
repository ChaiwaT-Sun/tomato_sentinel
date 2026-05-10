// Copyright (c) 2026 Tomato Sentinel
// OWASP MASVS: MSTG-RESILIENCE-3

import Foundation

class TamperDetector {
    func isTampered() -> Bool {
        return checkCodeSignature() ||
            checkEmbeddedMobileProvision() ||
            checkAppStoreReceipt()
    }
    
    private func checkCodeSignature() -> Bool {
        guard let executablePath = Bundle.main.executablePath else {
            return true
        }
        
        // Check if code signature is valid
        let task = Process()
        task.launchPath = "/usr/bin/codesign"
        task.arguments = ["--verify", "--deep", "--strict", executablePath]
        
        let pipe = Pipe()
        task.standardError = pipe
        task.launch()
        task.waitUntilExit()
        
        return task.terminationStatus != 0
    }
    
    private func checkEmbeddedMobileProvision() -> Bool {
        // Check for embedded.mobileprovision (should not exist in App Store builds)
        let provisioningPath = Bundle.main.path(forResource: "embedded", ofType: "mobileprovision")
        
        // In production App Store builds, this file should not exist
        // For development/enterprise, it's expected
        return false // Adjust based on your distribution method
    }
    
    private func checkAppStoreReceipt() -> Bool {
        guard let receiptURL = Bundle.main.appStoreReceiptURL else {
            return true
        }
        
        // Check if receipt exists (App Store builds should have it)
        return !FileManager.default.fileExists(atPath: receiptURL.path)
    }
}
