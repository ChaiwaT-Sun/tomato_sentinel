// Copyright (c) 2026 Tomato Sentinel
// OWASP MASVS: MSTG-RESILIENCE-1

import Foundation
import UIKit

class JailbreakDetector {
    
    private let jailbreakPaths = [
        "/Applications/Cydia.app",
        "/Applications/blackra1n.app",
        "/Applications/FakeCarrier.app",
        "/Applications/Icy.app",
        "/Applications/IntelliScreen.app",
        "/Applications/MxTube.app",
        "/Applications/RockApp.app",
        "/Applications/SBSettings.app",
        "/Applications/WinterBoard.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
        "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
        "/private/var/lib/apt",
        "/private/var/lib/cydia",
        "/private/var/mobile/Library/SBSettings/Themes",
        "/private/var/stash",
        "/private/var/tmp/cydia.log",
        "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
        "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
        "/usr/bin/sshd",
        "/usr/libexec/sftp-server",
        "/usr/sbin/sshd",
        "/etc/apt",
        "/bin/bash",
        "/bin/sh",
        "/usr/libexec/cydia",
        "/usr/bin/cycript",
        "/usr/local/bin/cycript",
        "/usr/lib/libcycript.dylib"
    ]
    
    func isJailbroken() -> Bool {
        return checkJailbreakPaths() ||
            checkCanWriteToPrivate() ||
            checkCydiaURLScheme() ||
            checkSuspiciousApps() ||
            checkFork() ||
            checkSymlinks()
    }
    
    private func checkJailbreakPaths() -> Bool {
        for path in jailbreakPaths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
            
            // Try to open file (some jailbreaks hide file existence)
            if let file = fopen(path, "r") {
                fclose(file)
                return true
            }
        }
        return false
    }
    
    private func checkCanWriteToPrivate() -> Bool {
        let testPath = "/private/jailbreak_test.txt"
        do {
            try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: testPath)
            return true
        } catch {
            return false
        }
    }
    
    private func checkCydiaURLScheme() -> Bool {
        if let url = URL(string: "cydia://package/com.example.package") {
            return UIApplication.shared.canOpenURL(url)
        }
        return false
    }
    
    private func checkSuspiciousApps() -> Bool {
        let suspiciousApps = [
            "cydia://",
            "undecimus://",
            "sileo://",
            "zbra://"
        ]
        
        for scheme in suspiciousApps {
            if let url = URL(string: scheme) {
                if UIApplication.shared.canOpenURL(url) {
                    return true
                }
            }
        }
        return false
    }
    
    private func checkFork() -> Bool {
        // fork() should fail on non-jailbroken devices
        let result = fork()
        if result >= 0 {
            if result > 0 {
                // Parent process - kill child
                kill(result, SIGTERM)
            }
            return true
        }
        return false
    }
    
    private func checkSymlinks() -> Bool {
        // Check for suspicious symlinks
        let symlinks = [
            "/Applications",
            "/Library/Ringtones",
            "/Library/Wallpaper",
            "/usr/arm-apple-darwin9",
            "/usr/include",
            "/usr/libexec",
            "/usr/share"
        ]
        
        for path in symlinks {
            do {
                let attributes = try FileManager.default.attributesOfItem(atPath: path)
                if let fileType = attributes[.type] as? FileAttributeType,
                   fileType == .typeSymbolicLink {
                    return true
                }
            } catch {
                continue
            }
        }
        return false
    }
}
