import Foundation
import Darwin
import CryptoKit

/// Anti-debugging layer (iOS/macOS port of target_demo/protection/
/// anti_debug.py):
///
///     * sysctl P_TRACED flag (gdb/lldb/ptrace attach)
///     * macOS: launched-from-debugger check (getppid() != launchd)
///     * timing checks (SHA-256 workload anomaly detection)
///     * macOS: optional PT_DENY_ATTACH at bootstrap (makes attaching
///       impossible — also breaks YOUR debugger, so default OFF in dev)
///
/// On detection: .exit kills the process after a randomized 2-8 s delay
/// (looks like a normal crash) or .degrade makes all licensing checks fail
/// with a generic "damaged" message.
final class AntiDebug {

    private let config: ProtectionConfig
    private(set) var degraded = false
    private var detected = false
    private var timingBaseline: Double = 0
    private var watchdogTimer: DispatchSourceTimer?

    init(_ config: ProtectionConfig) {
        self.config = config
    }

    // ------------------------------------------------------------ detection
    /// True when the environment looks clean right now.
    @discardableResult
    func initialScan() -> Bool {
        if config.devMode { return true }
        timingBaseline = measureTimingWorkload()
        let findings = scan()
        if !findings.isEmpty { onDetect() }
        return findings.isEmpty
    }

    private func scan() -> [String] {
        var findings: [String] = []
        if isTraced() { findings.append("traced") }
        #if os(macOS)
        if getppid() != 1 { findings.append("debugger-parent") }
        #endif
        if config.timingChecks && timingAnomaly() { findings.append("timing") }
        return findings
    }

    /// kern.proc P_TRACED — the classic sysctl debugger check.
    private func isTraced() -> Bool {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        memset(&info, 0, size)
        guard sysctl(&mib, u_int(mib.count), &info, &size, nil, 0) == 0 else {
            return false
        }
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }

    /// Fixed-size SHA-256 workload; debugger/instrumentation hooks and
    /// single-stepping blow the runtime far above a calm baseline.
    private func measureTimingWorkload() -> Double {
        let start = Date()
        let block = [UInt8](repeating: 0x5A, count: 4096)
        for _ in 0..<48 {
            var h = SHA256()
            h.update(data: Data(block))
            _ = h.finalize()
        }
        return Date().timeIntervalSince(start) * 1000
    }

    private func timingAnomaly() -> Bool {
        guard timingBaseline > 0 else { return false }
        return measureTimingWorkload() > timingBaseline * 8.0 + 150.0
    }

    // ------------------------------------------------------------ actions
    private func onDetect() {
        guard !detected else { return }
        detected = true
        switch config.onDetect {
        case .degrade:
            degraded = true
        case .exit:
            let delay = Double(Int.random(in: config.detectDelayRangeSeconds.min
                                          ... max(config.detectDelayRangeSeconds.max,
                                                  config.detectDelayRangeSeconds.min)))
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
                exit(0) // silent, non-obvious termination (documented policy)
            }
        }
    }

    // ------------------------------------------------------------ watchdog
    /// Jittered watchdog (20-45 s by default) — mirrors the Windows
    /// client's background thread. No-op in dev mode.
    func startWatchdog() {
        guard !config.devMode, watchdogTimer == nil else { return }
        let queue = DispatchQueue(label: "com.securecode.watchdog")
        let timer = DispatchSource.makeTimerSource(queue: queue)
        watchdogTimer = timer
        scheduleNext(timer)
    }

    private func scheduleNext(_ timer: DispatchSourceTimer) {
        let delay = Double(Int.random(in: config.watchdogIntervalSeconds.min
                                      ... max(config.watchdogIntervalSeconds.max,
                                              config.watchdogIntervalSeconds.min)))
        timer.schedule(deadline: .now() + delay)
        timer.setEventHandler { [weak self] in
            guard let self = self else { return }
            if !self.scan().isEmpty { self.onDetect() }
            if !self.detected || self.config.onDetect == .degrade {
                self.scheduleNext(timer)
            }
        }
        timer.resume()
    }

    func stopWatchdog() {
        watchdogTimer?.cancel()
        watchdogTimer = nil
    }
}
