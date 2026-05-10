// Copyright (c) 2026 Tomato Sentinel
// Secure Dio HTTP client with SSL pinning

import 'package:dio/dio.dart';
import '../tomato_sentinel_config.dart';
import 'pinning_interceptor.dart';

/// Secure Dio HTTP Client
/// 
/// Pre-configured Dio instance with SSL pinning enabled.
/// Automatically validates certificates against configured pins.
/// 
/// Usage:
/// ```dart
/// final client = SecureDioClient.create(config);
/// final response = await client.get('https://api.example.com/data');
/// ```
class SecureDioClient {
  final Dio _dio;

  SecureDioClient._(this._dio);

  /// Create a secure Dio client with SSL pinning
  factory SecureDioClient.create(
    TomatoSentinelConfig config, {
    BaseOptions? options,
    List<Interceptor>? additionalInterceptors,
  }) {
    final baseOptions = options ??
        BaseOptions(
          connectTimeout: const Duration(seconds: 30),
          receiveTimeout: const Duration(seconds: 30),
          validateStatus: (status) => status != null && status < 500,
        );

    final dio = Dio(baseOptions);

    // Add pinning interceptor first (highest priority)
    dio.interceptors.add(PinningInterceptor(config));

    // Add additional interceptors
    if (additionalInterceptors != null) {
      dio.interceptors.addAll(additionalInterceptors);
    }

    // Add logging in debug mode
    if (!const bool.fromEnvironment('dart.vm.product')) {
      dio.interceptors.add(LogInterceptor(
        requestBody: true,
        responseBody: true,
        error: true,
      ));
    }

    return SecureDioClient._(dio);
  }

  /// Get the underlying Dio instance
  Dio get dio => _dio;

  /// GET request
  Future<Response<T>> get<T>(
    String path, {
    Map<String, dynamic>? queryParameters,
    Options? options,
    CancelToken? cancelToken,
    ProgressCallback? onReceiveProgress,
  }) {
    return _dio.get<T>(
      path,
      queryParameters: queryParameters,
      options: options,
      cancelToken: cancelToken,
      onReceiveProgress: onReceiveProgress,
    );
  }

  /// POST request
  Future<Response<T>> post<T>(
    String path, {
    dynamic data,
    Map<String, dynamic>? queryParameters,
    Options? options,
    CancelToken? cancelToken,
    ProgressCallback? onSendProgress,
    ProgressCallback? onReceiveProgress,
  }) {
    return _dio.post<T>(
      path,
      data: data,
      queryParameters: queryParameters,
      options: options,
      cancelToken: cancelToken,
      onSendProgress: onSendProgress,
      onReceiveProgress: onReceiveProgress,
    );
  }

  /// PUT request
  Future<Response<T>> put<T>(
    String path, {
    dynamic data,
    Map<String, dynamic>? queryParameters,
    Options? options,
    CancelToken? cancelToken,
    ProgressCallback? onSendProgress,
    ProgressCallback? onReceiveProgress,
  }) {
    return _dio.put<T>(
      path,
      data: data,
      queryParameters: queryParameters,
      options: options,
      cancelToken: cancelToken,
      onSendProgress: onSendProgress,
      onReceiveProgress: onReceiveProgress,
    );
  }

  /// DELETE request
  Future<Response<T>> delete<T>(
    String path, {
    dynamic data,
    Map<String, dynamic>? queryParameters,
    Options? options,
    CancelToken? cancelToken,
  }) {
    return _dio.delete<T>(
      path,
      data: data,
      queryParameters: queryParameters,
      options: options,
      cancelToken: cancelToken,
    );
  }

  /// PATCH request
  Future<Response<T>> patch<T>(
    String path, {
    dynamic data,
    Map<String, dynamic>? queryParameters,
    Options? options,
    CancelToken? cancelToken,
    ProgressCallback? onSendProgress,
    ProgressCallback? onReceiveProgress,
  }) {
    return _dio.patch<T>(
      path,
      data: data,
      queryParameters: queryParameters,
      options: options,
      cancelToken: cancelToken,
      onSendProgress: onSendProgress,
      onReceiveProgress: onReceiveProgress,
    );
  }

  /// Close the client
  void close({bool force = false}) {
    _dio.close(force: force);
  }
}
