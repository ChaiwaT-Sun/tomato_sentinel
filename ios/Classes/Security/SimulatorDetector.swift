// Copyright (c) 2026 Tomato Sentinel
// OWASP MASVS: MSTG-RESILIENCE-5

import Foundation
import UIKit

class SimulatorDetector {
    func isSimulator() -> Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return checkSimulatorEnvironment()
        #endif
    }
    
    private func checkSimulatorEnvironment() -> Bool {
        return ProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"] != nil ||
               ProcessInfo.processInfo.environment["SIMULATOR_UDID"] != nil ||
               UIDevice.current.model.contains("Simulator")
    }
}
