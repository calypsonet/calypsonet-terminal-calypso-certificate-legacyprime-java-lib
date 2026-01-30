# Calypsonet Terminal Calypso Certificate Legacy Prime JVM Lib

## Overview

This repository contains the Java implementation of the **Terminal Calypso Certificate Legacy Prime** API
proposed by the [Calypso Networks Association](https://www.calypsonet.org). It provides the implementation
required to create Calypso Legacy Prime certificates.

## Key Features

- **Certificate Generation**: Create CA (Certificate Authority) and Card certificates compliant with the Calypso Legacy Prime specification
- **Certificate Store**: Manage PCA (Prime Certificate Authority) public keys and CA certificates
- **Certificate Validation**: Parse and validate certificate signatures using RSA 2048-bit keys
- **Flexible Architecture**: Support for external certificate signers through SPI (Service Provider Interface)

## Quick Start

### 1. Initialize the Service

```java
CalypsoCertificateLegacyPrimeService service =
    CalypsoCertificateLegacyPrimeService.getInstance();

CalypsoCertificateLegacyPrimeApiFactory factory =
    service.getCalypsoCertificateLegacyPrimeApiFactory();

CalypsoCertificateLegacyPrimeStore store =
    factory.getCalypsoCertificateLegacyPrimeStore();
```

### 2. Load PCA Public Key

The library accepts PCA public keys from various sources:

#### From X.509 Certificate (PEM or DER format)

```java
import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

// Load X.509 certificate from PEM or DER file
CertificateFactory cf = CertificateFactory.getInstance("X.509");
try (FileInputStream fis = new FileInputStream("pca-certificate.crt")) {
    X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
    RSAPublicKey pcaPublicKey = (RSAPublicKey) cert.getPublicKey();

    // Add to store with 29-byte key reference
    store.addPcaPublicKey(pcaKeyReference, pcaPublicKey);
}
```

#### From Java KeyStore (JKS/PKCS12)

```java
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;

KeyStore keyStore = KeyStore.getInstance("PKCS12");
try (FileInputStream fis = new FileInputStream("keystore.p12")) {
    keyStore.load(fis, "password".toCharArray());

    Certificate cert = keyStore.getCertificate("pca-alias");
    RSAPublicKey pcaPublicKey = (RSAPublicKey) cert.getPublicKey();

    store.addPcaPublicKey(pcaKeyReference, pcaPublicKey);
}
```

#### From PEM-encoded Public Key

```java
import java.io.FileReader;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

// Using BouncyCastle for PEM parsing
try (PemReader pemReader = new PemReader(new FileReader("pca-public-key.pem"))) {
    PemObject pemObject = pemReader.readPemObject();
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pemObject.getContent());

    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    RSAPublicKey pcaPublicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);

    store.addPcaPublicKey(pcaKeyReference, pcaPublicKey);
}
```

#### From Raw Modulus (256 bytes)

```java
// When you only have the RSA modulus (e.g., from a HSM or proprietary format)
byte[] pcaPublicKeyModulus = new byte[256]; // 2048-bit modulus
// ... load modulus from your source ...

// The library automatically reconstructs the RSAPublicKey with exponent 65537
store.addPcaPublicKey(pcaKeyReference, pcaPublicKeyModulus);
```

### 3. Create a Certificate Signer

#### Option A: Use the Default Signer (Recommended for Development/Testing)

The library provides `DefaultCalypsoCertificateLegacyPrimeSigner`, a ready-to-use implementation for signing certificates.

```java
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;

// Generate a 2048-bit RSA key pair
KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
keyGen.initialize(2048);
KeyPair keyPair = keyGen.generateKeyPair();
RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

// Create the default signer
CalypsoCertificateLegacyPrimeSigner signer =
    new DefaultCalypsoCertificateLegacyPrimeSigner(privateKey);
```

**Loading from different sources:**

```java
// From PEM file
CalypsoCertificateLegacyPrimeSigner signer =
    DefaultCalypsoCertificateLegacyPrimeSigner.fromPemFile("private-key.pem");

// From PEM string
String pemContent = "-----BEGIN PRIVATE KEY-----\n...";
CalypsoCertificateLegacyPrimeSigner signer =
    DefaultCalypsoCertificateLegacyPrimeSigner.fromPemString(pemContent);

// From KeyStore (PKCS12/JKS)
KeyStore keyStore = KeyStore.getInstance("PKCS12");
try (FileInputStream fis = new FileInputStream("keystore.p12")) {
    keyStore.load(fis, "store-password".toCharArray());
}
CalypsoCertificateLegacyPrimeSigner signer =
    DefaultCalypsoCertificateLegacyPrimeSigner.fromKeyStore(
        keyStore, "key-alias", "key-password".toCharArray());
```

#### Option B: Implement Custom Signer (for HSM or External Providers)

For production use with Hardware Security Modules (HSM) or external signing services:

```java
CalypsoCertificateLegacyPrimeSigner customSigner = new CalypsoCertificateLegacyPrimeSigner() {
    @Override
    public byte[] generateSignedCertificate(byte[] data, byte[] recoverableData) {
        // Implement ISO/IEC 9796-2 PSS signature with your HSM or provider
        // - Algorithm: ISO9796-2 PSS with SHA-256
        // - Recoverable data: 222 bytes embedded in signature
        // - Returns: data + 256-byte signature
        return signWithHSM(data, recoverableData);
    }
};
```

### 4. Generate CA Certificate

```java
// Create generator with issuer key reference and signer
CalypsoCaCertificateLegacyPrimeGenerator caGenerator =
    factory.createCalypsoCaCertificateLegacyPrimeGenerator(
        issuerKeyReference,
        signer);  // Use signer from step 3

// Configure and generate certificate
byte[] caCertificate = caGenerator
    .withCaPublicKey(caKeyReference, caPublicKey)
    .withTargetAid(targetAid, truncationAllowed)
    .withStartDate(2025, 1, 1)
    .withEndDate(2030, 12, 31)
    .withCaRights((byte) 0x0A)  // Can sign both CA and card certificates
    .withCaScope((byte) 0xFF)   // No scope restriction
    .generate();

// The generated certificate can be added back to the store for chaining
store.addCalypsoCaCertificateLegacyPrime(caCertificate);
```

### 5. Generate Card Certificate

```java
CalypsoCardCertificateLegacyPrimeGenerator cardGenerator =
    factory.createCalypsoCardCertificateLegacyPrimeGenerator(
        caKeyReference,
        signer);  // Use CA signer (may be different from PCA signer)

byte[] cardCertificate = cardGenerator
    .withCardAid(cardAid)
    .withCardPublicKey(cardEccPublicKey)  // 64 bytes ECC secp256r1 public key
    .withCardSerialNumber(serialNumber)   // 8 bytes
    .withCardStartupInfo(startupInfo)     // 7 bytes
    .withStartDate(2025, 1, 1)
    .withEndDate(2028, 12, 31)
    .withIndex(1)  // Optional index for multiple certificates
    .generate();
```

## Complete End-to-End Example

Here's a complete example showing certificate generation from scratch:

```java
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

// Initialize service
CalypsoCertificateLegacyPrimeService service =
    CalypsoCertificateLegacyPrimeService.getInstance();
CalypsoCertificateLegacyPrimeApiFactory factory =
    service.getCalypsoCertificateLegacyPrimeApiFactory();
CalypsoCertificateLegacyPrimeStore store =
    factory.getCalypsoCertificateLegacyPrimeStore();

// 1. Generate PCA key pair
KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
keyGen.initialize(2048);
KeyPair pcaKeyPair = keyGen.generateKeyPair();
RSAPrivateKey pcaPrivateKey = (RSAPrivateKey) pcaKeyPair.getPrivate();
RSAPublicKey pcaPublicKey = (RSAPublicKey) pcaKeyPair.getPublic();

// 2. Create PCA key reference (29 bytes: AID size + AID + serial number + key ID)
byte[] pcaKeyReference = new byte[29];
pcaKeyReference[0] = 0x05; // AID size
System.arraycopy(new byte[]{0x01, 0x02, 0x03, 0x04, 0x05}, 0, pcaKeyReference, 1, 5);

// 3. Add PCA public key to store
store.addPcaPublicKey(pcaKeyReference, pcaPublicKey);

// 4. Generate CA key pair
KeyPair caKeyPair = keyGen.generateKeyPair();
RSAPrivateKey caPrivateKey = (RSAPrivateKey) caKeyPair.getPrivate();
RSAPublicKey caPublicKey = (RSAPublicKey) caKeyPair.getPublic();

byte[] caKeyReference = new byte[29];
caKeyReference[0] = 0x05;
System.arraycopy(new byte[]{0x01, 0x02, 0x03, 0x04, 0x05}, 0, caKeyReference, 1, 5);
caKeyReference[28] = 0x01; // Different key ID

// 5. Create PCA signer and generate CA certificate
CalypsoCertificateLegacyPrimeSigner pcaSigner =
    new DefaultCalypsoCertificateLegacyPrimeSigner(pcaPrivateKey);

byte[] caCertificate = factory
    .createCalypsoCaCertificateLegacyPrimeGenerator(pcaKeyReference, pcaSigner)
    .withCaPublicKey(caKeyReference, caPublicKey)
    .withStartDate(2025, 1, 1)
    .withEndDate(2035, 12, 31)
    .withCaRights((byte) 0x0A)  // Can sign both CA and card certificates
    .withCaScope((byte) 0xFF)   // No scope restriction
    .generate();

// 6. Add CA certificate to store
store.addCalypsoCaCertificateLegacyPrime(caCertificate);

// 7. Create CA signer and generate card certificate
CalypsoCertificateLegacyPrimeSigner caSigner =
    new DefaultCalypsoCertificateLegacyPrimeSigner(caPrivateKey);

byte[] cardPublicKey = new byte[64];  // ECC secp256r1 public key
// ... populate with actual card public key ...

byte[] cardCertificate = factory
    .createCalypsoCardCertificateLegacyPrimeGenerator(caKeyReference, caSigner)
    .withCardPublicKey(cardPublicKey)
    .withCardAid(new byte[]{0x01, 0x02, 0x03, 0x04, 0x05})
    .withCardSerialNumber(new byte[]{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
    .withCardStartupInfo(new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07})
    .withStartDate(2025, 3, 1)
    .withEndDate(2027, 12, 31)
    .generate();

// Done! caCertificate (384 bytes) and cardCertificate (316 bytes) are ready
```

## Main Components

| Component | Description |
|-----------|-------------|
| **CalypsoCertificateLegacyPrimeService** | Singleton entry point providing access to the API factory |
| **CalypsoCertificateLegacyPrimeApiFactory** | Factory for creating certificate generators and accessing the store |
| **CalypsoCertificateLegacyPrimeStore** | Certificate and public key repository |
| **CalypsoCaCertificateLegacyPrimeGenerator** | Builder for generating CA certificates |
| **CalypsoCardCertificateLegacyPrimeGenerator** | Builder for generating Card certificates |
| **CalypsoCertificateLegacyPrimeSigner** | SPI interface for implementing custom certificate signing |
| **DefaultCalypsoCertificateLegacyPrimeSigner** | Default implementation of the signer using ISO9796-2 PSS with BouncyCastle |

## Using the Default Signer

The `DefaultCalypsoCertificateLegacyPrimeSigner` class provides a ready-to-use implementation of certificate signing using ISO/IEC 9796-2 PSS (Probabilistic Signature Scheme) with message recovery.

### Key Features

- **ISO9796-2 PSS Implementation**: Uses BouncyCastle's implementation with SHA-256 digest
- **Message Recovery**: 222 bytes of recoverable data embedded in the signature
- **Deterministic Signatures**: Salt length of 0 ensures consistent signatures for testing
- **Multiple Key Sources**: Load private keys from PEM files, KeyStores, or Java objects
- **Thread-Safe**: Can be used concurrently (subject to BouncyCastle's thread safety)

### Security Considerations

**Important**: The default signer keeps private keys in memory. For production environments with sensitive keys, consider:

1. **Hardware Security Modules (HSM)**: Implement a custom signer that delegates to your HSM
2. **External Signing Services**: Implement a custom signer that calls remote signing APIs
3. **Key Protection**: Use operating system key stores or encrypted storage

The default signer is ideal for:
- Development and testing
- Proof-of-concept implementations
- Scenarios where keys are already protected by other means
- Generating certificates in controlled environments

### Loading Private Keys

```java
// From an RSAPrivateKey object
RSAPrivateKey privateKey = ...;
CalypsoCertificateLegacyPrimeSigner signer =
    new DefaultCalypsoCertificateLegacyPrimeSigner(privateKey);

// From a PEM file (PKCS#8 format)
CalypsoCertificateLegacyPrimeSigner signer =
    DefaultCalypsoCertificateLegacyPrimeSigner.fromPemFile("/path/to/private-key.pem");

// From a PEM string
String pemContent = "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----";
CalypsoCertificateLegacyPrimeSigner signer =
    DefaultCalypsoCertificateLegacyPrimeSigner.fromPemString(pemContent);

// From a PKCS12 KeyStore
KeyStore keyStore = KeyStore.getInstance("PKCS12");
try (FileInputStream fis = new FileInputStream("keystore.p12")) {
    keyStore.load(fis, "store-password".toCharArray());
}
CalypsoCertificateLegacyPrimeSigner signer =
    DefaultCalypsoCertificateLegacyPrimeSigner.fromKeyStore(
        keyStore, "key-alias", "key-password".toCharArray());
```

### Key Requirements

The private key must meet these requirements:
- **Algorithm**: RSA
- **Key Size**: 2048 bits
- **Public Exponent**: 65537 (the corresponding public key)

### Custom Signer Implementation

For HSM or external signing services, implement the `CalypsoCertificateLegacyPrimeSigner` interface:

```java
public class HsmSigner implements CalypsoCertificateLegacyPrimeSigner {
    private final HsmClient hsmClient;
    private final String keyId;

    public HsmSigner(HsmClient hsmClient, String keyId) {
        this.hsmClient = hsmClient;
        this.keyId = keyId;
    }

    @Override
    public byte[] generateSignedCertificate(byte[] data, byte[] recoverableData) {
        // Implement ISO9796-2 PSS signing using your HSM
        // Most HSMs support this standard
        byte[] signature = hsmClient.signISO9796_2_PSS(
            keyId,
            data,
            recoverableData,
            "SHA-256",
            0  // salt length
        );

        // Concatenate data + signature
        byte[] result = new byte[data.length + signature.length];
        System.arraycopy(data, 0, result, 0, data.length);
        System.arraycopy(signature, 0, result, data.length, signature.length);
        return result;
    }
}
```

## Certificate Structure

- **CA Certificate**: 384 bytes (128 bytes data + 256 bytes RSA signature)
- **Card Certificate**: 316 bytes (60 bytes data + 256 bytes RSA signature)
- **Public Keys**: RSA 2048-bit (exponent 65537) for CA, ECC for cards
- **Key Reference**: 29 bytes (AID size + AID value + serial number + key ID)

## Key Reference Format

The 29-byte key reference structure:
- **Byte 0**: AID size (5-16 bytes, or 0xFF for RFU)
- **Bytes 1-16**: AID value (padded with zeros if needed)
- **Bytes 17-28**: Serial number (8 bytes) + Key ID (4 bytes)

## Typical Integration Scenarios

### Scenario 1: PKI with X.509 Certificates
Load PCA root certificates from your PKI infrastructure, then use the library to generate Calypso-specific CA and card certificates while maintaining the chain of trust.

### Scenario 2: Certificate Chain Building
Load PCA public key → Generate CA certificate → Add CA to store → Generate card certificates using CA as issuer.

## About the source code

The code is built with **Gradle** and is compliant with **Java 1.8** in order to address a wide range of applications.

## Documentation & Contributions

The full documentation, including the **user guide**, **download instructions** and **contribution guidelines**, is available on the [project website](https://terminal-api.calypsonet.org/).
