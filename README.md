# Tomato Sentinel 🍅

[![pub package](https://img.shields.io/pub/v/tomato_sentinel.svg)](https://pub.dev/packages/tomato_sentinel)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Production-grade Flutter security SDK** providing comprehensive mobile application security for Android and iOS. Built for banking-grade applications with OWASP MASVS L2 compliance.

## Features

### 🔐 SSL Public Key Pinning
- **SPKI SHA-256** certificate pinning
- Embedded backup pins
- Dynamic pin updates via signed remote config
- Direct integration with Dio HTTP client
- Prevents MITM attacks

### 🛡️ Runtime Security
- **Root/Jailbreak Detection** - Multi-layered detection
- **Emulator Detection** - Identifies simulator environments
- **Frida Detection** - Detects hooking frameworks (Frida, Xposed, Cydia Substrate)
- **Tamper Detection** - Binary integrity verification
- **Debugger Detection** - Runtime debugging detection

### ✅ Device Integrity
- **Play Integrity API** (Android) - Google's device attestation
- **App Attest** (iOS) - Apple's app integrity verification
- **DeviceCheck** support

### 🔄 Remote Configuration
- **Signed remote config** with RSA-4096/ECDSA P-384
- Dynamic security policy updates
- Replay attack prevention
- Automatic configuration validation

### 🏗️ Architecture
- Clean, modular architecture
- Riverpod state management support
- Async initialization
- TOCTOU prevention
- Fail-closed security model
- Production-ready obfuscation support

## OWASP MASVS Compliance

This SDK implements security controls aligned with OWASP Mobile Application Security Verification Standard (MASVS) Level 2:

| Control | Description | Implementation |
|---------|-------------|----------------|
| MSTG-NETWORK-4 | SSL Pinning | ✅ SPKI SHA-256 pinning |
| MSTG-RESILIENCE-1 | Root/Jailbreak Detection | ✅ Multi-method detection |
| MSTG-RESILIENCE-2 | Debugger Detection | ✅ Runtime checks |
| MSTG-RESILIENCE-3 | Tamper Detection | ✅ Signature verification |
| MSTG-RESILIENCE-4 | Hook Detection | ✅ Frida/Xposed detection |
| MSTG-RESILIENCE-5 | Emulator Detection | ✅ Environment checks |

## Installation

Add to your `pubspec.yaml`:

```yaml
dependencies:
  tomato_sentinel: ^1.0.0
```

## Quick Start

### 1. Initialize the SDK

```dart
import 'package:tomato_sentinel/tomato_sentinel.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  
  // Configure SSL pinning
  final pinConfig = PinConfigurationBuilder()
      .domain('api.example.com')
      .addPin('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=') // Primary
      .addPin('BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=') // Backup
      .includeSubdomains(true)
      .build();

  // Production configuration
  final config = TomatoSentinelConfig.production(
    pinConfigurations: {'api.example.com': pinConfig},
    remoteConfigUrl: 'https://api.example.com/security/config',
    remoteConfigPublicKey: 'YOUR_PUBLIC_KEY_PEM',
    playIntegrityCloudProjectNumber: '123456789',
    appAttestKeyId: 'com.example.app.attest',
    onSecurityEvent: (event) {
      print('Security Event: ${event.type}');
    },
  );

  await TomatoSentinel.initialize(config);
  
  runApp(MyApp());
}
```

### 2. Check Security Status

```dart
// Get current security status
final status = await TomatoSentinel.instance.getSecurityStatus();

if (!status.isDeviceSecure) {
  // Handle security threats
  for (final threat in status.allThreats) {
    print('Threat: ${threat.type} - ${threat.description}');
  }
}

// Check specific threats
final isRooted = await TomatoSentinel.instance.isDeviceRooted();
final isEmulator = await TomatoSentinel.instance.isEmulator();
final isHooked = await TomatoSentinel.instance.isHooked();
```

### 3. Secure HTTP Client

```dart
import 'package:tomato_sentinel/tomato_sentinel.dart';

// Create secure Dio client with SSL pinning
final client = SecureDioClient.create(config);

// Make requests - pinning is automatic
final response = await client.get('https://api.example.com/data');
```

### 4. Riverpod Integration

```dart
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:tomato_sentinel/tomato_sentinel.dart';

class MyApp extends ConsumerWidget {
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final securityStatus = ref.watch(securityStatusProvider);
    
    return securityStatus.when(
      data: (status) => status.isDeviceSecure 
          ? SecureApp() 
          : SecurityWarningScreen(),
      loading: () => LoadingScreen(),
      error: (error, stack) => ErrorScreen(error),
    );
  }
}
```

## Generating SSL Pins

To generate SPKI SHA-256 pins for your certificates:

### Using OpenSSL

```bash
# Extract SPKI from certificate
openssl x509 -in certificate.crt -pubkey -noout | \
openssl pkey -pubin -outform der | \
openssl dgst -sha256 -binary | \
openssl enc -base64
```

### Using Online Tools

1. Visit your API endpoint in Chrome
2. Click the lock icon → Certificate
3. Use tools like [SSL Labs](https://www.ssllabs.com/ssltest/) to get the pin

### Important: Always Include Backup Pins

```dart
final pinConfig = PinConfigurationBuilder()
    .domain('api.example.com')
    .addPin('PRIMARY_PIN_HERE')      // Current certificate
    .addPin('BACKUP_PIN_HERE')       // Backup certificate
    .addPin('ROOT_CA_PIN_HERE')      // Root CA (optional)
    .build();
```

## Remote Configuration

### Server-Side Setup

1. Generate RSA-4096 key pair:

```bash
# Generate private key
openssl genrsa -out private_key.pem 4096

# Extract public key
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

2. Create signed configuration:

```json
{
  "version": 2,
  "createdAt": "2026-05-08T10:00:00Z",
  "expiresAt": "2026-08-08T10:00:00Z",
  "nonce": "RANDOM_NONCE_HERE",
  "pinConfigurations": {
    "api.example.com": {
      "domain": "api.example.com",
      "pins": ["PIN1", "PIN2"],
      "includeSubdomains": true
    }
  },
  "securityPolicy": {
    "enforceRootDetection": true,
    "enforceEmulatorDetection": true,
    "enforceHookDetection": true,
    "enforceTamperDetection": true,
    "minimumAppVersion": 100
  },
  "signature": "BASE64_SIGNATURE_HERE"
}
```

3. Sign the configuration:

```bash
# Create signature payload
echo -n "2|2026-05-08T10:00:00Z|2026-08-08T10:00:00Z|NONCE" | \
openssl dgst -sha256 -sign private_key.pem | \
openssl enc -base64
```

## Android Setup

### build.gradle

```gradle
android {
    compileSdkVersion 34
    
    defaultConfig {
        minSdkVersion 24
        targetSdkVersion 34
    }
    
    buildTypes {
        release {
            minifyEnabled true
            shrinkResources true
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
        }
    }
}

dependencies {
    // Play Integrity API
    implementation 'com.google.android.play:integrity:1.3.0'
}
```

### ProGuard Rules

```proguard
# Tomato Sentinel
-keep class ts.sun.tomato_sentinel.** { *; }
-keep class ts.sun.tomato_sentinel.security.** { *; }

# Play Integrity
-keep class com.google.android.play.core.integrity.** { *; }
```

## iOS Setup

### Podfile

```ruby
platform :ios, '13.0'

target 'Runner' do
  use_frameworks!
  use_modular_headers!

  flutter_install_all_ios_pods File.dirname(File.realpath(__FILE__))
end
```

### Info.plist

```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <false/>
</dict>
```

## Security Best Practices

### 1. Fail-Closed Policy

Always use fail-closed in production:

```dart
final config = TomatoSentinelConfig.production(
  failClosed: true,  // App terminates on critical threats
  enforceInDebugMode: true,
);
```

### 2. Multiple Pins

Always configure at least 2 pins:

```dart
.addPin('CURRENT_CERT_PIN')   // Primary
.addPin('BACKUP_CERT_PIN')    // Backup for rotation
```

### 3. Pin Expiration

Set expiration dates:

```dart
.expiresAt(DateTime.now().add(Duration(days: 90)))
```

### 4. Security Event Monitoring

Monitor all security events:

```dart
onSecurityEvent: (event) {
  // Log to your analytics/monitoring service
  analytics.logSecurityEvent(
    type: event.type.name,
    message: event.message,
    metadata: event.metadata,
  );
}
```

### 5. Obfuscation

Enable code obfuscation:

```bash
flutter build apk --obfuscate --split-debug-info=build/debug-info
flutter build ios --obfuscate --split-debug-info=build/debug-info
```

## Threat Model

### Threats Mitigated

1. **MITM Attacks** - SSL pinning prevents certificate substitution
2. **Root/Jailbreak Exploitation** - Detects compromised devices
3. **Runtime Manipulation** - Detects Frida, Xposed, debuggers
4. **Emulator-Based Attacks** - Identifies non-genuine devices
5. **Binary Tampering** - Signature verification
6. **Replay Attacks** - Nonce-based remote config

### Attack Surface

- Network layer (SSL/TLS)
- Runtime environment
- Binary integrity
- Device integrity

## Performance

- **Initialization**: < 100ms
- **Security checks**: < 50ms (cached)
- **SSL pinning**: No measurable overhead
- **Memory footprint**: < 5MB

## Limitations

1. **Root/Jailbreak Detection**: Not 100% foolproof - determined attackers can bypass
2. **Obfuscation**: Provides security through obscurity, not cryptographic security
3. **Play Integrity**: Requires Google Play Services
4. **App Attest**: Requires iOS 14+ and Apple Developer Program

## Development Mode

For development, use relaxed configuration:

```dart
final config = TomatoSentinelConfig.development(
  pinConfigurations: {}, // No pinning in dev
);
```

**⚠️ WARNING**: Never ship development configuration to production!

## Testing

```dart
void main() {
  test('Security initialization', () async {
    final config = TomatoSentinelConfig.development();
    await TomatoSentinel.initialize(config);
    expect(TomatoSentinel.isInitialized, true);
  });
}
```

## Troubleshooting

### SSL Pinning Failures

1. Verify pin format (Base64, 44 characters)
2. Check certificate chain
3. Ensure pins match current certificate
4. Verify domain configuration

### Root Detection False Positives

Some legitimate tools may trigger detection:
- Development tools
- Accessibility services
- Custom ROMs

Adjust sensitivity in configuration.

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT License - see [LICENSE](LICENSE) file.

## Support

- 📧 Email: support@example.com
- 🐛 Issues: [GitHub Issues](https://github.com/yourusername/tomato_sentinel/issues)
- 📖 Docs: [Documentation](https://docs.example.com)

## Acknowledgments

- OWASP Mobile Security Project
- Flutter Security Community
- Contributors and testers

---

**⚠️ Security Notice**: This SDK provides defense-in-depth security controls but is not a silver bullet. Always follow secure development practices and conduct regular security audits.

**Built with ❤️ for secure Flutter applications**
