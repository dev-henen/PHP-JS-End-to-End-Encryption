class Encryptor {
    constructor(secretKey) {
        this.secretKey = secretKey;
    }

    static loadScript(url) {
        return new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = url;
            script.onload = () => resolve();
            script.onerror = () => reject(new Error(`Script load error for ${url}`));
            document.head.appendChild(script);
        });
    }

    static async initialize(secretKey) {
        try {
            await Encryptor.loadScript('https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js');
            await Encryptor.loadScript('https://cdn.jsdelivr.net/npm/node-forge@0.10.0/dist/forge.min.js');
            return new Encryptor(secretKey);
        } catch (error) {
            console.error('Error loading scripts:', error);
        }
    }

    encrypt(data) {
        let key = CryptoJS.enc.Utf8.parse(this.secretKey);
    
        // Ensure the key is 32 bytes long for AES-256
        if (key.sigBytes !== 32) {
            key = CryptoJS.SHA256(this.secretKey);  // Derive a 32-byte key from the original key
        }
    
        const iv = CryptoJS.lib.WordArray.random(16); // Generate a random IV
        const encrypted = CryptoJS.AES.encrypt(data, key, {
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        });
    
        const encryptedData = iv.concat(encrypted.ciphertext).toString(CryptoJS.enc.Base64);
        
        console.log('Original data:', data);
        console.log('Encrypted data with IV:', encryptedData);
    
        return encryptedData;
    }
    
    

    static async encryptSecretKey(secretKey, publicKey) {
        const pki = forge.pki;
        const publicKeyObj = pki.publicKeyFromPem(publicKey);
        const encryptedSecretKey = publicKeyObj.encrypt(secretKey, 'RSA-OAEP');
        return forge.util.encode64(encryptedSecretKey);
    }

    static getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
        return '';
    }

    static fetchPublicKeyFromCookie() {
        const publicKeyBase64 = Encryptor.getCookie('public_key');
        
        if (!publicKeyBase64) {
            throw new Error('Public key cookie is missing.');
        }
    
        console.log('Public Key (Base64):', publicKeyBase64);  // Debugging line
    
        try {
            const decodedPublicKeyBase64 = decodeURIComponent(publicKeyBase64);
            return atob(decodedPublicKeyBase64);
        } catch (e) {
            console.error('Failed to decode public key:', e);
            throw new Error('Invalid public key encoding.');
        }
    }    
     
    async sendSecureData(method, location, data) {
        const publicKeyPem = await Encryptor.fetchPublicKeyFromCookie();
        const encryptedSecretKey = await Encryptor.encryptSecretKey(this.secretKey, publicKeyPem);
    
        const encryptedData = {};
        for (const [key, value] of Object.entries(data)) {
            encryptedData[key] = this.encrypt(value);
        }
    
        const response = await fetch(location, {
            method: method.toUpperCase(),
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                encryptedSecretKey: encryptedSecretKey,
                encryptedData: encryptedData // Send as an array/object
            })
        });
    
        const result = await response.text();
        console.log(result);
        return result;
    }

    decrypt(data) {
        try {
            const key = CryptoJS.SHA256(this.secretKey); // Ensure a 32-byte key for AES-256
            const ivSize = 16; // AES block size (128 bits = 16 bytes)
    
            // Decode the base64-encoded data from the server
            const encryptedData = CryptoJS.enc.Base64.parse(data);
    
            // Extract the IV (first 16 bytes) and ciphertext (remaining bytes)
            const iv = CryptoJS.lib.WordArray.create(encryptedData.words.slice(0, ivSize / 4), ivSize);
            const ciphertext = CryptoJS.lib.WordArray.create(encryptedData.words.slice(ivSize / 4), encryptedData.sigBytes - ivSize);
    
            // Debugging: Log IV and Ciphertext
            console.log('IV:', iv.toString(CryptoJS.enc.Hex));
            console.log('Ciphertext:', ciphertext.toString(CryptoJS.enc.Hex));
    
            // Decrypt the ciphertext using the key and IV
            const decrypted = CryptoJS.AES.decrypt(
                { ciphertext: ciphertext },
                key,
                {
                    iv: iv,
                    mode: CryptoJS.mode.CBC,
                    padding: CryptoJS.pad.Pkcs7
                }
            );
    
            // Convert decrypted data to a UTF-8 string
            const decryptedText = decrypted.toString(CryptoJS.enc.Utf8);
    
            if (!decryptedText) {
                throw new Error("Decryption failed: Empty result");
            }
    
            console.log('Decrypted Text:', decryptedText);
            return decryptedText;
        } catch (error) {
            console.error('Decryption error:', error);
            return null;
        }
    }        

    async getSecureData(location) {
        const response = await fetch(location, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            }
        });
    
        const data = await response.json();
        console.log('Raw Data from Server:', data);  // Add this line
        
        const decryptedData = {};
    
        for (const [key, value] of Object.entries(data)) {
            decryptedData[key] = this.decrypt(value);
        }
    
        console.log('Decrypted Data:', decryptedData);
        return decryptedData;
    }
    
    
}

// Example usage
(async () => {
    const secretKey = 'your-very-secret-key';
    const encryptor = await Encryptor.initialize(secretKey);
    const response = await encryptor.sendSecureData('POST', '/se_test.php', { message: 'Hello, World!' });
    console.log('Server Response:', response);

    
    try {
        // Retrieve and decrypt data securely from the server
        const data = await encryptor.getSecureData('/ge_test.php');
        
        // Use the decrypted data as needed
        console.log('Retrieved and Decrypted Data:', data);
    } catch (error) {
        console.error('Failed to retrieve secure data:', error);
    }   
    
})();
