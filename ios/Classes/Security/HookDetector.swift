// Copyright (c) 2026 Tomato Sentinel
// OWASP MASVS: MSTG-RESILIENCE-4

import Foundation
import MachO

class HookDetector {
    func isHooked() -> Bool {
        return checkFridaServer() ||
            checkSuspiciousLibraries() ||
            checkDebugger() ||
            checkDynamicLibraries()
    }
    
    private func checkFridaServer() -> Bool {
        let fridaPorts = [27042, 27043]
        for port in fridaPorts {
            if isPortOpen(port: port) {
                return true
            }
        }
        return false
    }
    
    private func isPortOpen(port: Int) -> Bool {
        let sock = socket(AF_INET, SOCK_STREAM, 0)
        guard sock >= 0 else { return false }
        
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(port).bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        
        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        
        close(sock)
        return result == 0
    }
    
    private func checkSuspiciousLibraries() -> Bool {
        let suspiciousLibs = [
            "FridaGadget",
            "frida",
            "cynject",
            "libcycript"
        ]
        
        for i in 0..<_dyld_image_count() {
            if let imageName = _dyld_get_image_name(i) {
                let name = String(cString: imageName)
                for lib in suspiciousLibs {
                    if name.lowercased().contains(lib.lowercased()) {
                        return true
                    }
                }
            }
        }
        return false
    }
    
    private func checkDebugger() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        
        let result = sysctl(&mib, u_int(mib.count), &info, &size, nil, 0)
        return result == 0 && (info.kp_proc.p_flag & P_TRACED) != 0
    }
    
    private func checkDynamicLibraries() -> Bool {
        let imageCount = _dyld_image_count()
        // Suspicious if too many dynamic libraries loaded
        return imageCount > 400
    }
}
