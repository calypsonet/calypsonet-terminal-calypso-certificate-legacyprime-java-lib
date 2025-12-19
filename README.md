# Calypsonet Terminal Calypso Certificate Legacy Prime Java Lib

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

### 3. Generate CA Certificate

```java
// Implement the signer SPI for your specific cryptographic provider
CalypsoCertificateLegacyPrimeSigner customSigner = new CalypsoCertificateLegacyPrimeSigner() {
    @Override
    public byte[] generateSignature(byte[] dataToSign, byte[] signerKeyReference) {
        // Use your HSM, software crypto provider, or external signing service
        // to generate RSA-SHA256 PKCS#1 v1.5 signature (256 bytes)
        return signWithHSM(dataToSign, signerKeyReference);
    }
};

// Create generator with issuer key reference
CalypsoCaCertificateLegacyPrimeGenerator caGenerator =
    factory.createCalypsoCaCertificateLegacyPrimeGenerator(
        issuerKeyReference,
        customSigner);

// Configure and generate certificate
byte[] caCertificate = caGenerator
    .withCaPublicKey(caKeyReference, caPublicKey)
    .withTargetAid(targetAid, truncationAllowed)
    .withStartDate(2024, 1, 1)
    .withEndDate(2029, 12, 31)
    .withCaRights(caRights)
    .withCaScope(CaScope.NOT_RESTRICTED)
    .generate();

// The generated certificate can be added back to the store for chaining
store.addCalypsoCaCertificateLegacyPrime(caCertificate);
```

### 4. Generate Card Certificate

```java
CalypsoCardCertificateLegacyPrimeGenerator cardGenerator =
    factory.createCalypsoCardCertificateLegacyPrimeGenerator(
        caKeyReference,
        customSigner);

byte[] cardCertificate = cardGenerator
    .withCardAid(cardAid)
    .withCardPublicKey(cardEccPublicKey)  // 64 bytes ECC public key
    .withCardSerialNumber(serialNumber)   // 8 bytes
    .withCardStartupInfo(startupInfo)     // 7 bytes
    .withStartDate(2024, 1, 1)
    .withEndDate(2029, 12, 31)
    .withCardRights(cardRights)
    .generate();
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
