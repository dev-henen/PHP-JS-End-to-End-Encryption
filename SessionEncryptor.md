# SessionEncryptor Project

This project provides a secure method for encrypting and decrypting sensitive data between a client and a server using RSA encryption. The encryption is performed on the client side using JavaScript, while decryption occurs on the server side using PHP. 

## Table of Contents

- [Overview](#overview)
- [Setup](#setup)
  - [SSL Configuration](#ssl-configuration)
  - [JavaScript Setup](#javascript-setup)
  - [PHP Setup](#php-setup)
- [Usage](#usage)
  - [JavaScript Methods](#javascript-methods)
  - [PHP Methods](#php-methods)
- [Example Usage](#example-usage)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

## Overview

The `SessionEncryptor` and `Encryptor` classes work together to ensure that sensitive data is securely transmitted from the client to the server. The flow of data is as follows:

1. The server generates an RSA public-private key pair using the `SessionEncryptor` class.
2. The public key is sent to the client and stored in a cookie.
3. The client-side `Encryptor` class encrypts sensitive data using the public key.
4. The encrypted data is sent back to the server, where it is decrypted using the private key.

## Setup

### SSL Configuration

To secure the transmission of data, it's important to use SSL (HTTPS) on your server. Here's how to set it up:

1. **Generate SSL Certificates**:
   - Use a tool like OpenSSL to generate a self-signed certificate, or obtain one from a Certificate Authority (CA).
   - Example using OpenSSL:
     ```bash
     openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr
     openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
     ```
   - This will generate `server.key` (private key) and `server.crt` (certificate).

2. **Configure Your Server**:
   - **Apache**:
     Edit your Apache configuration file (`httpd.conf` or a virtual host config file) to include the following:
     ```apache
     SSLEngine on
     SSLCertificateFile "/path/to/server.crt"
     SSLCertificateKeyFile "/path/to/server.key"
     ```
   - **Nginx**:
     Edit your Nginx configuration file:
     ```nginx
     server {
         listen 443 ssl;
         ssl_certificate /path/to/server.crt;
         ssl_certificate_key /path/to/server.key;
         ...
     }
     ```

3. **Restart the Server**:
   - After making the changes, restart your web server to apply the SSL configuration.

### JavaScript Setup

1. **Include the `Encryptor` Class**:
   - Load the `encryptor.js` file in your HTML:
     ```html
     <script src="path/to/encryptor.js"></script>
     ```

2. **Load Required Libraries**:
   - The `Encryptor` class dynamically loads the necessary cryptographic library (node-forge). Ensure the internet connection is available when the page loads, or host the library locally.

### PHP Setup

1. **Include the `SessionEncryptor` Class**:
   - Place `SessionEncryptor.php` in your project directory and include it in your server-side scripts:
     ```php
     require_once 'path/to/SessionEncryptor.php';
     ```

2. **Initialize SessionEncryptor**:
   - Instantiate the `SessionEncryptor` class and start the encryption session:
     ```php
     $sessionEncryptor = new SessionEncryptor();
     ```

## Usage

### JavaScript Methods

#### `Encryptor.initialize(secretKey)`
- **Description**: Loads the required cryptographic libraries and initializes the `Encryptor` class.
- **Parameters**:
  - `secretKey` (string): The secret key used for symmetric encryption.
- **Returns**: A promise that resolves to an instance of `Encryptor`.

#### `Encryptor.encryptSecretKey(secretKey, publicKeyPem)`
- **Description**: Encrypts the secret key using the RSA public key.
- **Parameters**:
  - `secretKey` (string): The secret key to encrypt.
  - `publicKeyPem` (string): The public key in PEM format.
- **Returns**: A promise that resolves to the encrypted secret key (base64 encoded).

#### `Encryptor.encrypt(data)`
- **Description**: Encrypts sensitive data using the symmetric secret key.
- **Parameters**:
  - `data` (string): The data to encrypt.
- **Returns**: The encrypted data (base64 encoded).

#### `Encryptor.main()`
- **Description**: Main function that orchestrates the encryption process, including retrieving the public key from cookies, encrypting the secret key, and sending encrypted data to the server.

### PHP Methods

#### `SessionEncryptor->__construct()`
- **Description**: Initializes the `SessionEncryptor` class, generating a new RSA key pair and storing the private key on the server. The public key is sent to the client via a cookie.

#### `SessionEncryptor->generateKeys()`
- **Description**: Generates an RSA public-private key pair. The private key is stored in the session, and the public key is set as a cookie.

#### `SessionEncryptor->decrypt($encryptedData)`
- **Description**: Decrypts data sent from the client using the stored private key.
- **Parameters**:
  - `encryptedData` (string): The data to decrypt.
- **Returns**: The decrypted data (original plain text).

### Example Usage

#### **JavaScript Example (`encryptor.js`)**

```javascript
(async () => {
    try {
        await Encryptor.main();
    } catch (error) {
        console.error('Encryption failed:', error);
    }
})();
```

#### **PHP Example (`encryption_server.php`)**

```php
<?php
require_once 'SessionEncryptor.php';

try {
    $sessionEncryptor = new SessionEncryptor();
    $data = json_decode(file_get_contents('php://input'), true);
    
    $decryptedSecretKey = $sessionEncryptor->decrypt($data['encryptedSecretKey']);
    $decryptedData = openssl_decrypt($data['encryptedData'], 'aes-256-cbc', $decryptedSecretKey, 0, 'iviviviviviviviv');
    
    echo 'Decrypted Data: ' . $decryptedData;
} catch (Exception $e) {
    echo 'Decryption failed: ' . $e->getMessage();
}
```

### Security Considerations

- **Use HTTPS**: Always serve your website over HTTPS to prevent man-in-the-middle attacks.
- **Key Storage**: Never store the private key on the client. The private key should always be kept secure on the server.
- **Cookie Security**: Ensure cookies that store sensitive data (like the public key) are marked as `HttpOnly` and `Secure`.

### Troubleshooting

- **Invalid Key Error**: Ensure the private key is correctly generated and matches the public key sent to the client.
- **OpenSSL Configuration Errors**: If OpenSSL cannot find its configuration file, specify the correct path using the `config` parameter.
