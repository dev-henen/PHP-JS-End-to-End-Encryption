<?php 

class SessionEncryptor {
    private $privateKey;
    private $publicKey;

    public function __construct($sslConfigPath = null) {
        session_start();

        // Generate keys when a new session starts
        if (!isset($_SESSION['private_key']) || !isset($_SESSION['public_key'])) {
            $this->generateKeys($sslConfigPath);
            $this->storeKeysInSession();
        } else {
            $this->privateKey = $_SESSION['private_key'];
            $this->publicKey = $_SESSION['public_key'];
        }
    }

    private function generateKeys($sslConfigPath) {
        $config = [
            "digest_alg" => "sha256",
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
            "config" => $sslConfigPath
        ];
    
        $res = openssl_pkey_new($config);
        if ($res === false) {
            throw new Exception('Failed to generate private key: ' . openssl_error_string());
        }
    
        if (!openssl_pkey_export($res, $privateKey, null, $config)) {
            throw new Exception('Failed to export private key: ' . openssl_error_string());
        }
    
        $details = openssl_pkey_get_details($res);
        if ($details === false) {
            throw new Exception('Failed to get public key details: ' . openssl_error_string());
        }
    
        $publicKey = $details['key'];
    
        $this->privateKey = $privateKey;
        $this->publicKey = $publicKey;
    }

    public function decryptSecretKey($encryptedSecretKey) {
        $encryptedSecretKey = base64_decode($encryptedSecretKey);
        $privateKeyResource = openssl_pkey_get_private($this->privateKey);

        if ($privateKeyResource === false) {
            throw new Exception('Invalid private key: ' . openssl_error_string());
        }

        $decryptionSuccess = openssl_private_decrypt(
            $encryptedSecretKey,
            $decryptedSecretKey,
            $privateKeyResource,
            OPENSSL_PKCS1_OAEP_PADDING
        );

        if (!$decryptionSuccess) {
            throw new Exception('Decryption failed: ' . openssl_error_string());
        }

        return $decryptedSecretKey;
    }

    private function storeKeysInSession() {
        $_SESSION['private_key'] = $this->privateKey;
        $_SESSION['public_key'] = $this->publicKey;
    }

    public function getPublicKey() {
        return $this->publicKey;
    }

    public function decryptData($cipherText, $secretKey) {
        if (strlen($secretKey) !== 32) {
            $secretKey = hash('sha256', $secretKey, true);
        }
    
        $cipherText = base64_decode($cipherText);
        $ivSize = openssl_cipher_iv_length('aes-256-cbc');
        $iv = substr($cipherText, 0, $ivSize);
        $cipherText = substr($cipherText, $ivSize);
    
        $decrypted = openssl_decrypt($cipherText, 'aes-256-cbc', $secretKey, OPENSSL_RAW_DATA, $iv);
    
        if ($decrypted === false) {
            error_log('Decryption failed: ' . openssl_error_string());
            return 'Decryption failed';
        }
    
        return $decrypted;
    }

    public function get_secured_data($method, $callback) {
        $method = strtoupper($method);
        $input = json_decode(file_get_contents('php://input'), true);
        $encryptedSecretKey = $input['encryptedSecretKey'];
        $secretKey = $this->decryptSecretKey($encryptedSecretKey);
        $decryptedData = [];
    
        if ($method === 'POST' && isset($input['encryptedData']) && is_array($input['encryptedData'])) {
            foreach ($input['encryptedData'] as $key => $value) {
                $decryptedData[$key] = $this->decryptData($value, $secretKey);
            }
        } elseif ($method === 'GET') {
            foreach ($_GET as $key => $value) {
                $decryptedData[$key] = $this->decryptData($value, $secretKey);
            }
        } else {
            throw new Exception('Invalid method or data format.');
        }
    
        $callback($decryptedData, null);
    }

    public function sendSecureData($data, $secretKey) {
        if (strlen($secretKey) !== 32) {
            $secretKey = hash('sha256', $secretKey, true);
        }
    
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
        $encryptedData = openssl_encrypt($data, 'aes-256-cbc', $secretKey, OPENSSL_RAW_DATA, $iv);
    
        if ($encryptedData === false) {
            throw new Exception('Encryption failed: ' . openssl_error_string());
        }
    
        $encryptedPayload = base64_encode($iv . $encryptedData);
        return json_encode(['encryptedData' => $encryptedPayload]);
    }    
    
}

