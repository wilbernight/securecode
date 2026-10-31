import Foundation

/// Owns the background anti-RE machinery for one process — the iOS/macOS
/// port of target_demo/protection.ProtectionRuntime.
///
/// Call `bootstrap` ONCE as the very first statements of main() /
/// AppDelegate.application(_:didFinishLaunching:) — it never returns a
/// rejected state; on hard integrity failure it exits silently (graceful,
/// non-obvious termination by design).
public enum ProtectionRuntime {

    public final class Handle {
        let antiDebug: AntiDebug
        public let clockGuard: ClockGuard

        init(_ antiDebug: AntiDebug, _ clock: ClockGuard) {
            self.antiDebug = antiDebug
            self.clockGuard = clock
        }

        /// True when anti-debug switched to silent-degrade mode — pass to
        /// LicenseClient.verifyInstalled(degraded:).
        public var degraded: Bool { antiDebug.degraded }

        /// Stop watchdog timers on clean application exit.
        public func shutdown() { antiDebug.stopWatchdog() }

        /// A LicenseClient wired to this runtime's clock guard.
        public func licenseClient(_ config: ProtectionConfig) -> LicenseClient {
            LicenseClient(config, antiDebug: antiDebug, clockGuard: clockGuard)
        }
    }

    @discardableResult
    public static func bootstrap(_ config: ProtectionConfig) -> Handle {
        if config.integrityChecks, !config.devMode {
            let (ok, _) = Integrity.runChecks(config)
            if !ok {
                exit(0) // silent, non-obvious termination (documented policy)
            }
        }
        let anti = AntiDebug(config)
        let clock = ClockGuard(config)
        if config.antiDebugEnabled, !config.devMode {
            anti.initialScan()
            anti.startWatchdog()
        }
        return Handle(anti, clock)
    }
}
