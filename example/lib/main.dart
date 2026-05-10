// Copyright (c) 2026 Tomato Sentinel
// Example application demonstrating security SDK usage

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:tomato_sentinel/tomato_sentinel.dart';

/// Application entry point.
///
/// Execution order:
/// 1. [WidgetsFlutterBinding.ensureInitialized] — prepares the Flutter engine
///    before any async code runs in main(). Required whenever await is used.
///
/// 2. [initializeSecurity] — configures and starts the Tomato Sentinel SDK.
///    Must complete before runApp so security checks run before the UI renders.
///
/// 3. [ProviderScope] — Riverpod wrapper that must surround the entire widget
///    tree, making all providers (including securityStatusProvider) available
///    to descendant widgets.
void main() async {
  // Ensure Flutter binding is ready before calling plugins or async code.
  WidgetsFlutterBinding.ensureInitialized();

  // Initialize Tomato Sentinel with production configuration.
  await initializeSecurity();

  runApp(
    // ProviderScope: required for Riverpod providers to function.
    const ProviderScope(
      child: MyApp(),
    ),
  );
}

/// Configures the Tomato Sentinel SDK with a production configuration.
///
/// This function has two main sections:
///   A) Build a [PinConfiguration] for SSL pinning.
///   B) Build a [TomatoSentinelConfig] and call [TomatoSentinel.initialize].
///
/// ─── Section A: PinConfigurationBuilder ────────────────────────────────────
///
/// [PinConfigurationBuilder] uses the Builder Pattern to construct a
/// [PinConfiguration]. Each method returns the builder (method chaining)
/// until [build] is called.
///
/// • .domain('api.example.com')
///     Sets the hostname to pin. Must match the host in HTTPS requests.
///     Throws [ArgumentError] on [build] if not set.
///
/// • .addPin('AAAA...=')   ← Primary pin
///     Adds the SPKI SHA-256 hash of the public key, Base64-encoded (44 chars).
///     Generate with:
///       openssl s_client -connect api.example.com:443 | \
///       openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | \
///       openssl dgst -sha256 -binary | base64
///
/// • .addPin('BBBB...=')   ← Backup pin
///     Backup pin for certificate rotation. At least 2 pins are required.
///     Throws [ArgumentError] on [build] if fewer than 2 pins are provided.
///     Rationale: if the primary cert expires with no backup pin, the app
///     becomes unreachable.
///
/// • .includeSubdomains(true)
///     When true, the pin applies to all subdomains of the configured domain.
///     e.g. 'api.example.com' also pins 'v2.api.example.com'.
///     When false (default), only the exact domain is pinned.
///
/// • .expiresAt(DateTime.now().add(Duration(days: 90)))
///     Sets the expiry date for this pin configuration.
///     After this date, connections fail closed (all certificates rejected).
///     Should align with the actual certificate lifetime (typically 90–365 days).
///     If not set, the pin never expires (not recommended for production).
///
/// • .build()
///     Creates an immutable [PinConfiguration] object.
///     Validates that domain is set and pins.length >= 2 before returning.
///
/// ─── Section B: TomatoSentinelConfig.production ─────────────────────────────
///
/// [TomatoSentinelConfig.production] enables all security features by default:
///   enableRootDetection    = true
///   enableEmulatorDetection = true
///   enableHookDetection    = true
///   enableTamperDetection  = true
///   enableIntegrityCheck   = true
///   failClosed             = true
///   enforceInDebugMode     = true
///
/// Required parameters:
///
/// • pinConfigurations: Map<String, PinConfiguration>
///     Map of domain → PinConfiguration.
///     Keys must match the hostnames used in HTTPS requests.
///     Must not be empty (asserted) — production always requires pins.
///
/// • remoteConfigUrl: String
///     URL for fetching dynamic security configuration.
///     Allows pin updates without releasing a new app version.
///     Must be HTTPS.
///
/// • remoteConfigPublicKey: String (PEM format)
///     Public key used to verify the signature of the remote config.
///     Prevents MITM attacks that attempt to inject a fake config.
///     Must be RSA 4096-bit or ECDSA P-384 minimum.
///     Must not be empty (asserted).
///
/// • playIntegrityCloudProjectNumber: String? (Android only)
///     Cloud Project Number from Google Cloud Console.
///     Used with the Play Integrity API to verify the app runs on a real
///     device, has not been tampered with, and was installed from the Play Store.
///     If omitted, the integrity check is skipped on Android.
///
/// • appAttestKeyId: String? (iOS only)
///     Key identifier for Apple App Attest / DeviceCheck.
///     Verifies the app runs on a genuine Apple device and is not jailbroken.
///     If omitted, the integrity check is skipped on iOS.
///
/// • onSecurityEvent: SecurityEventCallback
///     Callback invoked every time a security event occurs.
///     Use for logging, analytics, or alerting a backend.
///     Receives a [SecurityEvent] with .type, .message, .timestamp, .metadata.
///     Event types: rootDetected, emulatorDetected, hookDetected,
///                  tamperDetected, pinningViolation, integrityCheckFailed, etc.
///
/// ─── TomatoSentinel.initialize ───────────────────────────────────────────────
///
/// [TomatoSentinel.initialize] starts the SDK and runs the initial security check.
///
/// • If failClosed = true and a critical threat is found → throws [SecurityException].
///   Catch and handle appropriately, e.g. show an error screen or exit the app.
///
/// • If failClosed = false → logs a warning but does not throw.
///   Suitable for development configs only.
///
/// • Safe to call multiple times — subsequent calls are no-ops.
Future<void> initializeSecurity() async {
  // ─── A: Build SSL Pin Configuration ─────────────────────────────────────────

  // PinConfigurationBuilder: builds a pin config via method chaining.
  final pinConfig = PinConfigurationBuilder()
      // Set the domain to pin (must match the host in HTTPS requests).
      .domain('api.example.com')
      // Primary pin: SPKI SHA-256 hash of the main certificate (Base64, 44 chars).
      .addPin('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=')
      // Backup pin: used during certificate rotation — at least 2 pins required.
      .addPin('BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=')
      // Also pin all subdomains, e.g. v2.api.example.com.
      .includeSubdomains(true)
      // Pin expires in 90 days — connections fail closed after this date.
      .expiresAt(DateTime.now().add(const Duration(days: 90)))
      // Build the immutable PinConfiguration — validates domain + pins >= 2.
      .build();

  // ─── B: Build Production Config ──────────────────────────────────────────────

  // TomatoSentinelConfig.production: enables all security checks + failClosed = true.
  final config = TomatoSentinelConfig.production(
    // Map of domain → PinConfiguration (must not be empty).
    pinConfigurations: {
      'api.example.com': pinConfig,
    },
    // URL for fetching dynamic security config (must be HTTPS).
    remoteConfigUrl: 'https://api.example.com/security/config',
    // PEM public key for verifying the remote config signature.
    // Prevents MITM from injecting a fake config — must be RSA-4096 or ECDSA P-384.
    remoteConfigPublicKey: '''
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA...
-----END PUBLIC KEY-----
''',
    // Google Cloud Project Number (Android: Play Integrity API).
    playIntegrityCloudProjectNumber: '123456789',
    // Apple App Attest key ID (iOS: verifies genuine device + not jailbroken).
    appAttestKeyId: 'com.example.app.attest',
    // onSecurityEvent is wired to SecurityAlertNotifier inside SecurityDashboard
    // after ProviderScope is ready. See _SecurityDashboardState.initState().
    onSecurityEvent: (event) {
      // event.type      — event category (rootDetected, hookDetected, etc.)
      // event.message   — human-readable description
      // event.timestamp — when the event occurred
      // event.metadata  — optional extra data (url, error, etc.)
      debugPrint('Security Event: ${event.type} - ${event.message}');
    },
  );

  // ─── C: Start the SDK ────────────────────────────────────────────────────────

  try {
    // initialize: runs all initial security checks and starts periodic monitoring.
    // Throws SecurityException if a critical threat is found and failClosed = true.
    await TomatoSentinel.initialize(config);
    debugPrint('Security initialized successfully');
  } catch (e) {
    // SecurityException: critical threat detected (root, hook, tamper, etc.).
    // Handle appropriately — show an error screen or terminate the app.
    debugPrint('Security initialization failed: $e');
  }
}

/// Root widget of the application.
///
/// [MaterialApp] configures the theme and sets the home screen.
/// [ColorScheme.fromSeed] generates a color palette from red (Tomato brand color).
/// [useMaterial3] enables Material Design 3 components.
class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Tomato Sentinel Demo',
      theme: ThemeData(
        // Generate a color scheme from red — applied automatically throughout the app.
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.red),
        useMaterial3: true,
      ),
      home: const SecurityDashboard(),
    );
  }
}

/// Main screen displaying the device security status.
///
/// Uses [ConsumerStatefulWidget] to:
///   1. Watch [securityStatusProvider] for displaying the current status.
///   2. Listen to [securityAlertProvider].alertStream to show a dialog
///      immediately when a security event occurs (e.g. proxy intercept,
///      hook detection).
class SecurityDashboard extends ConsumerStatefulWidget {
  const SecurityDashboard({super.key});

  @override
  ConsumerState<SecurityDashboard> createState() => _SecurityDashboardState();
}

class _SecurityDashboardState extends ConsumerState<SecurityDashboard> {
  @override
  void initState() {
    super.initState();
    // Wire SecurityAlertNotifier to the SDK after the first frame renders.
    // Deferred because showing a dialog requires a valid BuildContext.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _wireSecurityAlerts();
    });
  }

  /// Connects the SDK's onSecurityEvent to [SecurityAlertNotifier] and
  /// listens to the alert stream to show a dialog immediately on any event.
  void _wireSecurityAlerts() {
    final alertNotifier = ref.read(securityAlertProvider.notifier);

    // Override the global security event callback to point at the notifier.
    // The SDK was already initialized with a debugPrint callback; this replaces
    // it with one that drives the UI alert system.
    // Note: ProviderScope was not ready during initializeSecurity(), so the
    // wire must happen here instead.
    TomatoSentinelConfigCallback.overrideSecurityEventCallback(
      alertNotifier.onSecurityEvent,
    );



    // Listen to the alert stream — show a dialog immediately on each new alert.
    alertNotifier.alertStream.listen((alert) {
      if (mounted) {
        _showSecurityAlertDialog(alert);
      }
    });
  }

  /// Displays an alert dialog when a security threat is detected.
  void _showSecurityAlertDialog(SecurityAlert alert) {
    showDialog<void>(
      context: context,
      // Critical alerts cannot be dismissed by tapping outside — user must tap OK.
      barrierDismissible: !alert.isCritical,
      builder: (ctx) => AlertDialog(
        backgroundColor: alert.isCritical ? Colors.red[50] : Colors.orange[50],
        icon: Icon(
          alert.isCritical ? Icons.gpp_bad : Icons.warning_amber,
          color: alert.isCritical ? Colors.red : Colors.orange,
          size: 48,
        ),
        title: Text(
          alert.title,
          style: TextStyle(
            color: alert.isCritical ? Colors.red[900] : Colors.orange[900],
            fontWeight: FontWeight.bold,
          ),
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(alert.message),
            const SizedBox(height: 12),
            Text(
              'Time: ${alert.timestamp.toLocal()}',
              style: const TextStyle(fontSize: 12, color: Colors.grey),
            ),
          ],
        ),
        actions: [
          if (!alert.isCritical)
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(),
              child: const Text('Dismiss'),
            ),
          FilledButton(
            style: FilledButton.styleFrom(
              backgroundColor: alert.isCritical ? Colors.red : Colors.orange,
            ),
            onPressed: () {
              Navigator.of(ctx).pop();
              // Refresh security status after the user acknowledges the alert.
              ref.refresh(securityStatusProvider);
            },
            child: const Text('Acknowledge'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final securityStatus = ref.watch(securityStatusProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Security Dashboard'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
      ),
      body: securityStatus.when(
        data: (status) => SecurityStatusView(status: status),
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (error, stack) => ErrorView(error: error),
      ),
      floatingActionButton: FloatingActionButton(
        // Manually trigger a fresh security check.
        onPressed: () => ref.refresh(securityStatusProvider),
        tooltip: 'Refresh Security Status',
        child: const Icon(Icons.refresh),
      ),
    );
  }
}

/// Renders the full security status as a scrollable list.
///
/// Receives a [SecurityStatus] containing:
///   • [SecurityStatus.isDeviceSecure]  — overall pass/fail summary
///   • [SecurityStatus.checkResults]   — per-check results (root, emulator, etc.)
///   • [SecurityStatus.allThreats]     — flat list of all detected threats
///
/// UI structure:
///   1. [SecurityCard]      — summary card (Secure / Issues Detected)
///   2. [SecurityCheckCard] × N — individual check result cards
///   3. [ThreatCard]        × N — shown only when threats are present
class SecurityStatusView extends StatelessWidget {
  final SecurityStatus status;

  const SecurityStatusView({super.key, required this.status});

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // Summary card: overall device security status.
        SecurityCard(
          title: 'Device Security',
          isSecure: status.isDeviceSecure,
          // Switch icon based on status: shield (secure) or warning (issues).
          icon: status.isDeviceSecure ? Icons.security : Icons.warning,
        ),
        const SizedBox(height: 16),
        // Individual check cards for each check type (root, emulator, hook, tamper).
        ...status.checkResults.entries.map((entry) {
          return SecurityCheckCard(
            checkType: entry.key,   // Check name, e.g. 'root', 'emulator'.
            result: entry.value,    // SecurityCheckResult for that check.
          );
        }),
        // Threat list — rendered only when at least one threat is present.
        if (status.allThreats.isNotEmpty) ...[
          const SizedBox(height: 16),
          const Text(
            'Detected Threats',
            style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 8),
          ...status.allThreats.map((threat) => ThreatCard(threat: threat)),
        ],
      ],
    );
  }
}

class SecurityCard extends StatelessWidget {
  final String title;
  final bool isSecure;
  final IconData icon;

  const SecurityCard({
    super.key,
    required this.title,
    required this.isSecure,
    required this.icon,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      color: isSecure ? Colors.green[50] : Colors.red[50],
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          children: [
            Icon(
              icon,
              size: 48,
              color: isSecure ? Colors.green : Colors.red,
            ),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    title,
                    style: const TextStyle(
                      fontSize: 18,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  Text(
                    isSecure ? 'Secure' : 'Security Issues Detected',
                    style: TextStyle(
                      color: isSecure ? Colors.green : Colors.red,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class SecurityCheckCard extends StatelessWidget {
  final String checkType;
  final SecurityCheckResult result;

  const SecurityCheckCard({
    super.key,
    required this.checkType,
    required this.result,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      child: ListTile(
        leading: Icon(
          result.isSecure ? Icons.check_circle : Icons.error,
          color: result.isSecure ? Colors.green : Colors.red,
        ),
        title: Text(checkType.toUpperCase()),
        subtitle: Text(
          result.isSecure
              ? 'Passed'
              : '${result.threats.length} threat(s) detected',
        ),
        trailing: result.isSecure
            ? null
            : Chip(
                label: Text(result.maxSeverity.name),
                backgroundColor: _getSeverityColor(result.maxSeverity),
              ),
      ),
    );
  }

  Color _getSeverityColor(ThreatSeverity severity) {
    switch (severity) {
      case ThreatSeverity.critical:
        return Colors.red;
      case ThreatSeverity.high:
        return Colors.orange;
      case ThreatSeverity.medium:
        return Colors.yellow;
      case ThreatSeverity.low:
        return Colors.blue;
      case ThreatSeverity.info:
        return Colors.grey;
    }
  }
}

class ThreatCard extends StatelessWidget {
  final SecurityThreat threat;

  const ThreatCard({super.key, required this.threat});

  @override
  Widget build(BuildContext context) {
    return Card(
      color: Colors.red[50],
      child: ListTile(
        leading: const Icon(Icons.warning, color: Colors.red),
        title: Text(threat.type.name),
        subtitle: Text(threat.description),
        trailing: Chip(
          label: Text(threat.severity.name),
          backgroundColor: _getSeverityColor(threat.severity),
        ),
      ),
    );
  }

  Color _getSeverityColor(ThreatSeverity severity) {
    switch (severity) {
      case ThreatSeverity.critical:
        return Colors.red;
      case ThreatSeverity.high:
        return Colors.orange;
      case ThreatSeverity.medium:
        return Colors.yellow;
      case ThreatSeverity.low:
        return Colors.blue;
      case ThreatSeverity.info:
        return Colors.grey;
    }
  }
}

class ErrorView extends StatelessWidget {
  final Object error;

  const ErrorView({super.key, required this.error});

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.error, size: 64, color: Colors.red),
            const SizedBox(height: 16),
            const Text(
              'Security Check Failed',
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            Text(
              error.toString(),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }
}
