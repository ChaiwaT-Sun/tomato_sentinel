// Copyright (c) 2026 Tomato Sentinel
// OWASP MASVS: MSTG-NETWORK-4

package ts.sun.tomato_sentinel.security

import android.content.Context
import android.util.Base64
import java.security.MessageDigest
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.io.ByteArrayInputStream

class SSLPinningValidator(private val context: Context) {

    fun verifyPin(domain: String, pins: List<String>, certificateChain: String): Boolean {
        return try {
            val certificates = parseCertificateChain(certificateChain)
            
            // Extract SPKI and compute SHA-256 for each certificate
            certificates.any { cert ->
                val spkiHash = computeSPKIHash(cert)
                pins.contains(spkiHash)
            }
        } catch (e: Exception) {
            false
        }
    }

    private fun parseCertificateChain(certChain: String): List<X509Certificate> {
        val certificates = mutableListOf<X509Certificate>()
        val certFactory = CertificateFactory.getInstance("X.509")
        
        // Parse PEM or DER encoded certificates
        val certBytes = if (certChain.contains("BEGIN CERTIFICATE")) {
            // PEM format
            val base64Cert = certChain
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replace("\\s".toRegex(), "")
            Base64.decode(base64Cert, Base64.DEFAULT)
        } else {
            // Assume Base64 encoded DER
            Base64.decode(certChain, Base64.DEFAULT)
        }
        
        val cert = certFactory.generateCertificate(
            ByteArrayInputStream(certBytes)
        ) as X509Certificate
        
        certificates.add(cert)
        return certificates
    }

    private fun computeSPKIHash(certificate: X509Certificate): String {
        // Extract Subject Public Key Info (SPKI)
        val publicKeyBytes = certificate.publicKey.encoded
        
        // Compute SHA-256 hash
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(publicKeyBytes)
        
        // Encode as Base64
        return Base64.encodeToString(hash, Base64.NO_WRAP)
    }

    companion object {
        /**
         * Create OkHttp CertificatePinner for use with OkHttp client
         */
        fun createCertificatePinner(
            pinConfigurations: Map<String, List<String>>
        ): okhttp3.CertificatePinner {
            val builder = okhttp3.CertificatePinner.Builder()
            
            pinConfigurations.forEach { (domain, pins) ->
                pins.forEach { pin ->
                    builder.add(domain, "sha256/$pin")
                }
            }
            
            return builder.build()
        }
    }
}
