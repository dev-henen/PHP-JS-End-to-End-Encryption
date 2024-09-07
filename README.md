# SessionEncryptor Library

## Overview

The `SessionEncryptor` library provides a secure method for encrypting and decrypting sensitive data transmitted between a client (using JavaScript) and a server (using PHP). This library leverages a combination of RSA and AES encryption techniques to ensure secure communication. The RSA encryption is used to securely transmit a symmetric AES key, which is then used to encrypt and decrypt the actual data.

The project consists of two main components:

1. **JavaScript Client (`Encryptor` Class):** Handles encryption of data on the client side.
2. **PHP Server (`SessionEncryptor` Class):** Manages key generation and decryption on the server side.

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
  - [JavaScript Example](#javascript-example)
  - [PHP Example](#php-example)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

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
   - Load the `Encryptor` class in your HTML:
     ```html
     <script src="path/to/encryptor.js"></script>
     ```

2. **Load Required Libraries**:
   - The `Encryptor` class dynamically loads the necessary cryptographic libraries (`crypto-js` and `node-forge`). Ensure the internet connection is available when the page loads, or host the library locally.

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

1. **`Encryptor.initialize(secretKey)`**
   - **Description**: Loads the required cryptographic libraries and initializes the `Encryptor` class.
   - **Parameters**:
     - `secretKey` (string): The secret key used for symmetric encryption.
   - **Returns**: A promise that resolves to an instance of `Encryptor`.

2. **`Encryptor.encryptSecretKey(secretKey, publicKeyPem)`**
   - **Description**: Encrypts the secret key using the RSA public key.
   - **Parameters**:
     - `secretKey` (string): The secret key to encrypt.
     - `publicKeyPem` (string): The public key in PEM format.
   - **Returns**: A promise that resolves to the encrypted secret key (base64 encoded).

3. **`Encryptor.encrypt(data)`**
   - **Description**: Encrypts sensitive data using the symmetric secret key.
   - **Parameters**:
     - `data` (string): The data to encrypt.
   - **Returns**: The encrypted data (base64 encoded).

4. **`Encryptor.sendSecureData(method, location, data)`**
   - **Description**: Encrypts data and sends it securely to the server.
   - **Parameters**:
     - `method` (string): HTTP method (`GET`, `POST`, etc.).
     - `location` (string): Server endpoint URL.
     - `data` (object): Data to send.
   - **Returns**: Server response.

5. **`Encryptor.getSecureData(location)`**
   - **Description**: Retrieves and decrypts data from the server.
   - **Parameters**:
     - `location` (string): Server endpoint URL.
   - **Returns**: Decrypted data.

### PHP Methods

1. **`SessionEncryptor->__construct($sslConfigPath)`**
   - **Description**: Initializes the `SessionEncryptor` class, generating a new RSA key pair and storing the private key on the server. The public key is sent to the client via a cookie.
   - **Parameters**:
     - `$sslConfigPath` (string): Path to the OpenSSL configuration file.

2. **`SessionEncryptor->decryptSecretKey($encryptedSecretKey)`**
   - **Description**: Decrypts the secret key using the private key stored in the session.
   - **Parameters**:
     - `$encryptedSecretKey` (string): The encrypted secret key (base64 encoded).
   - **Returns**: The decrypted secret key.

3. **`SessionEncryptor->decryptData($cipherText, $secretKey)`**
   - **Description**: Decrypts data using the symmetric secret key.
   - **Parameters**:
     - `$cipherText` (string): The encrypted data (base64 encoded).
     - `$secretKey` (string): The symmetric secret key.
   - **Returns**: The decrypted data.

4. **`SessionEncryptor->getPublicKey()`**
   - **Description**: Returns the public key in PEM format.
   - **Returns**: Public key (string).

5. **`SessionEncryptor->get_secured_data($method, $callback)`**
   - **Description**: Retrieves and decrypts data from the request, then calls a callback function with the decrypted data.
   - **Parameters**:
     - `$method` (string): HTTP method (`GET` or `POST`).
     - `$callback` (callable): Callback function to handle the decrypted data.

## Example Usage

### JavaScript Example

```javascript
(async () => {
    const secretKey = 'your-very-secret-key';
    const encryptor = await Encryptor.initialize(secretKey);
    
    // Sending encrypted data
    const response = await encryptor.sendSecureData('POST', '/se_test.php', { message: 'Hello, World!' });
    console.log('Server Response:', response);

    // Retrieving and decrypting data securely from the server
    try {
        const data = await encryptor.getSecureData('/ge_test.php');
        console.log('Retrieved and Decrypted Data:', data);
    } catch (error) {
        console.error('Failed to retrieve secure data:', error);
    }
})();
```

### PHP Example

```php
<?php
require 'SessionEncryptor.php';

// Initialize SessionEncryptor
$encryptor = new SessionEncryptor('c:\\xampp\\apache\\conf\\openssl.cnf');

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // Send public key to the client via a cookie
    $publicKey = $encryptor->getPublicKey();
    $encodedPublicKey = base64_encode($publicKey);
    setcookie('public_key', $encodedPublicKey, 0, "/"); // Cookie expires at end of session
    echo json_encode(['publicKey' => $encodedPublicKey]); 
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Handle the incoming secure data
    $encryptor->get_secured_data('POST', function ($decryptedData, $error) {
        if ($error) {
            echo "Error: $error";
        } else {
            echo 'Decrypted Data: ';
            print_r($decryptedData);
        }
    });
}
?>
```

## Security Considerations

- **Use HTTPS**: Always serve your website over HTTPS to prevent man-in-the-middle attacks.
- **Key Storage**: Never store the private key on the client. The private key should always be kept secure on the server.
- **Cookie Security**: Ensure cookies that store sensitive data (like the public key) are marked as `HttpOnly` and `Secure`.

## Troubleshooting

- **Invalid Key Error**: Ensure the private key is correctly generated and matches the public key sent to the client.
- **OpenSSL Configuration Errors**: If OpenSSL cannot find its configuration file, specify the correct path using the `config` parameter.
- **Decryption Issues**: If decryption fails, ensure that the encrypted data and key are correctly transmitted without modification.

This setup provides a comprehensive guide to securely encrypt and decrypt data between a client and server using JavaScript and PHP.
