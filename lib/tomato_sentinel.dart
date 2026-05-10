// Copyright (c) 2026 Tomato Sentinel
// Production-grade Flutter Security SDK — OWASP MASVS L2 Compliant
//
// Provides comprehensive security features:
//   - SSL Public Key Pinning (SPKI SHA-256)
//   - Root/Jailbreak Detection
//   - Emulator Detection
//   - Frida/Runtime Hook Detection
//   - Tamper Detection
//   - Play Integrity API (Android)
//   - App Attest / DeviceCheck (iOS)
//   - Signed Remote Configuration
//   - Secure HTTP Client Integration

// Core
export 'src/tomato_sentinel.dart';
export 'src/tomato_sentinel_config.dart';

// Models
export 'src/models/security_threat.dart';
export 'src/models/security_check_result.dart';
export 'src/models/pin_configuration.dart';
export 'src/models/remote_config.dart';
export 'src/models/integrity_result.dart';

// Services
export 'src/services/security_manager.dart';
export 'src/services/ssl_pinning_service.dart';
export 'src/services/remote_config_service.dart';
export 'src/services/integrity_service.dart';

// Network
export 'src/network/secure_dio_client.dart';
export 'src/network/pinning_interceptor.dart';

// Riverpod Providers
export 'src/providers/security_providers.dart';

// Exceptions
export 'src/exceptions/security_exceptions.dart';
