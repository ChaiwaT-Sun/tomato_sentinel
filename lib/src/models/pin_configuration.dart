// Copyright (c) 2026 Tomato Sentinel
// OWASP MASVS: MSTG-NETWORK-4

import 'package:meta/meta.dart';

/// SSL Public Key Pinning Configuration
/// Uses SPKI (Subject Public Key Info) SHA-256 hashing
/// 
/// Threat Model:
/// - Compromised Certificate Authorities
/// - MITM attacks with valid but unauthorized certificates
/// - Certificate substitution attacks
@immutable
class PinConfiguration {
  /// Domain to apply pinning (e.g., "api.example.com")
  final String domain;

  /// List of SPKI SHA-256 hashes (Base64 encoded)
  /// MUST include at least 2 pins (primary + backup)
  final List<String> pins;

  /// Include subdomains in pinning
  final bool includeSubdomains;

  /// Expiration date for this pin configuration
  /// After this date, pinning will fail closed
  final DateTime? expiresAt;

  /// Allow pinning to be bypassed in debug mode
  /// WARNING: Never set to true in production
  final bool allowDebugBypass;

  const PinConfiguration({
    required this.domain,
    required this.pins,
    this.includeSubdomains = false,
    this.expiresAt,
    this.allowDebugBypass = false,
  }) : assert(pins.length >= 2, 'Must provide at least 2 pins (primary + backup)');

  /// Check if configuration is expired
  bool get isExpired {
    if (expiresAt == null) return false;
    return DateTime.now().isAfter(expiresAt!);
  }

  /// Validate pin format (Base64 encoded SHA-256)
  bool validatePinFormat(String pin) {
    // SHA-256 produces 32 bytes = 44 characters in Base64
    final base64Regex = RegExp(r'^[A-Za-z0-9+/]{43}=$');
    return base64Regex.hasMatch(pin);
  }

  /// Check if all pins are valid
  bool get hasValidPins {
    return pins.every(validatePinFormat);
  }

  PinConfiguration copyWith({
    String? domain,
    List<String>? pins,
    bool? includeSubdomains,
    DateTime? expiresAt,
    bool? allowDebugBypass,
  }) {
    return PinConfiguration(
      domain: domain ?? this.domain,
      pins: pins ?? this.pins,
      includeSubdomains: includeSubdomains ?? this.includeSubdomains,
      expiresAt: expiresAt ?? this.expiresAt,
      allowDebugBypass: allowDebugBypass ?? this.allowDebugBypass,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'domain': domain,
      'pins': pins,
      'includeSubdomains': includeSubdomains,
      'expiresAt': expiresAt?.toIso8601String(),
      'allowDebugBypass': allowDebugBypass,
    };
  }

  factory PinConfiguration.fromJson(Map<String, dynamic> json) {
    return PinConfiguration(
      domain: json['domain'] as String,
      pins: (json['pins'] as List).cast<String>(),
      includeSubdomains: json['includeSubdomains'] as bool? ?? false,
      expiresAt: json['expiresAt'] != null
          ? DateTime.parse(json['expiresAt'] as String)
          : null,
      allowDebugBypass: json['allowDebugBypass'] as bool? ?? false,
    );
  }

  @override
  String toString() {
    return 'PinConfiguration(domain: $domain, pins: ${pins.length}, includeSubdomains: $includeSubdomains)';
  }

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    return other is PinConfiguration &&
        other.domain == domain &&
        _listEquals(other.pins, pins) &&
        other.includeSubdomains == includeSubdomains;
  }

  @override
  int get hashCode => Object.hash(domain, Object.hashAll(pins), includeSubdomains);

  bool _listEquals<T>(List<T>? a, List<T>? b) {
    if (a == null) return b == null;
    if (b == null || a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

/// Helper to generate pin configurations
class PinConfigurationBuilder {
  String? _domain;
  final List<String> _pins = [];
  bool _includeSubdomains = false;
  DateTime? _expiresAt;
  bool _allowDebugBypass = false;

  PinConfigurationBuilder domain(String domain) {
    _domain = domain;
    return this;
  }

  PinConfigurationBuilder addPin(String pin) {
    _pins.add(pin);
    return this;
  }

  PinConfigurationBuilder addPins(List<String> pins) {
    _pins.addAll(pins);
    return this;
  }

  PinConfigurationBuilder includeSubdomains(bool include) {
    _includeSubdomains = include;
    return this;
  }

  PinConfigurationBuilder expiresAt(DateTime date) {
    _expiresAt = date;
    return this;
  }

  PinConfigurationBuilder allowDebugBypass(bool allow) {
    _allowDebugBypass = allow;
    return this;
  }

  PinConfiguration build() {
    if (_domain == null) {
      throw ArgumentError('Domain is required');
    }
    if (_pins.length < 2) {
      throw ArgumentError('At least 2 pins required (primary + backup)');
    }
    return PinConfiguration(
      domain: _domain!,
      pins: List.unmodifiable(_pins),
      includeSubdomains: _includeSubdomains,
      expiresAt: _expiresAt,
      allowDebugBypass: _allowDebugBypass,
    );
  }
}
