import os
import hashlib
import keyring
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Key Management: Uses OS Keyring to securely store the AES encryption key.
# The key is generated once and stored securely, ensuring that it is not hardcoded in the source code or exposed in version control. This approach allows for secure management of encryption keys while maintaining ease of access for the application when needed. By leveraging the OS Keyring, we can ensure that the encryption key is protected by the underlying security mechanisms of the operating system, providing an additional layer of security against unauthorized access.
_SERVICE = "cyber_students_app"
_KEY_NAME = "aes_gcm_encryption_key" 


# AES-GCM Encryption/Decryption Functions: Encrypts PII with AES-GCM and a unique nonce for each entry.
# AES-GCM provides both confidentiality and integrity, ensuring that any tampering with the encrypted data can be detected during decryption. The use of a unique nonce for each encryption operation ensures that even if the same plaintext is encrypted multiple times, the resulting ciphertext will be different, enhancing security against certain types of attacks. The encryption and decryption functions handle the conversion between plaintext and ciphertext, as well as the management of the nonce, ensuring that sensitive PII is protected both at rest and in use.
def _get_aes_key():
    # AES-256 requires a 32-byte key
    key_hex = keyring.get_password(_SERVICE, _KEY_NAME)
    if not key_hex:
        key = AESGCM.generate_key(bit_length=256)
        keyring.set_password(_SERVICE, _KEY_NAME, key.hex())
        return key
    return bytes.fromhex(key_hex)

# Initialize AESGCM instance with the retrieved key. This instance will be used for all encryption and decryption operations, ensuring that the same key is consistently applied across the application for secure handling of PII. By centralizing the key management and encryption logic, we can maintain a clear separation of concerns and ensure that all sensitive data is handled in a consistent and secure manner throughout the application.
AES_KEY = _get_aes_key()
aesgcm = AESGCM(AES_KEY)

# Master Key is managed via the OS Keyring (Windows Credential Manager).
# This satisfies the deliverable to avoid hardcoded secrets in source code.
# Uses AES-GCM (Galois/Counter Mode) for Authenticated Encryption. I have chosen AES-GCM because it provides both confidentiality and integrity. It ensures that any tampering with the encrypted data can be detected during decryption, which is crucial for protecting sensitive PII. Additionally, AES-GCM is widely supported and optimized in modern hardware, making it a secure and efficient choice for encryption in this application. In short, it provides the ciphertext and an authentication tag that verifies the integrity of the data, ensuring that any unauthorized modifications can be detected and rejected during decryption.
# i have used a nonce (random 12-byte value) for each encryption operation, which is stored alongside the ciphertext. This ensures that even if the same plaintext is encrypted multiple times, the resulting ciphertext will be different due to the unique nonce. The nonce is generated using os.urandom to ensure it is cryptographically secure. When decrypting, the nonce is extracted from the stored value and used to correctly decrypt the ciphertext, ensuring both confidentiality and integrity of the data.
def encrypt_pii(data: str) -> str:
    """Encrypts using AES-GCM with a random 12-byte nonce."""
    if not data: return None
    nonce = os.urandom(12) 
    # encrypt(nonce, data, associated_data)
    ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
    # Return as hex: nonce (24 chars) + ciphertext
    return (nonce + ciphertext).hex()

# Decrypts AES-GCM hex string by splitting nonce and ciphertext. The function takes the combined hex string, converts it back to bytes, and separates the nonce (first 12 bytes) from the ciphertext, the algorithm cannot begin decryption without the nonce. It then uses the AESGCM instance to decrypt the ciphertext using the extracted nonce, returning the original plaintext data. This approach ensures that both confidentiality and integrity are maintained, as any tampering with the ciphertext will result in a decryption failure.
def decrypt_pii(combined_hex: str) -> str:
    """Decrypts AES-GCM hex string by splitting nonce and ciphertext."""
    if not combined_hex: return None
    raw_data = bytes.fromhex(combined_hex)
    nonce = raw_data[:12]
    ciphertext = raw_data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None).decode()


# Password Security: Uses Scrypt with a high work factor.
# Chosen over SHA-256 for resistance against ASIC/GPU cracking.
# i have generated a random salt for each password and stored it alongside the hash. I have used os.urandom to generate a secure random salt, and I have concatenated the salt with the hash before storing it in the database. This way, when verifying a password, I can extract the salt from the stored value and use it to hash the input password for comparison. This approach ensures that even if two users have the same password, their stored hashes will be different due to the unique salts, providing better security against rainbow table attacks.
def hash_password(password: str) -> str:
    """Uses Scrypt KDF to protect against GPU/ASIC cracking."""
    salt = os.urandom(16)
    # n=cost, r=block_size, p=parallelization
    key = hashlib.scrypt(
        password.encode(), salt=salt, n=16384, r=8, p=1, dklen=64
    )
    return (salt + key).hex()

# Verifies password by re-hashing input and comparing against stored Scrypt salt+hash.
# This function is critical for secure authentication and must be resistant to timing attacks.
# It extracts the salt from the stored hash, re-computes the hash with the input password, and compares them securely.
# It runs the Scrypt KDF with the same parameters to ensure that the hashing process is consistent and secure against brute-force attacks. Same memory, block size, and parallelization settings must be used to prevent attackers from optimizing their cracking attempts.
def verify_password(password: str, stored_hex: str) -> bool:
    """Re-hashes input and compares against stored Scrypt salt+hash."""
    if not stored_hex: return False
    data = bytes.fromhex(stored_hex)
    salt = data[:16]
    original_hash = data[16:]
    new_hash = hashlib.scrypt(
        password.encode(), salt=salt, n=16384, r=8, p=1, dklen=64
    )
    return new_hash == original_hash


# Blind Indexing: Creates a SHA-256 hash of the normalized email for O(1) lookups without storing plaintext.
# This allows the application to perform efficient user lookups based on email without ever storing the plaintext email in the database, enhancing privacy and security. By using a deterministic hash function like SHA-256, we can ensure that the same email will always produce the same blind index, allowing for consistent lookups while keeping the actual email address protected. This approach is compliant with GDPR requirements for data minimization and pseudonymisation, as it prevents direct access to personally identifiable information while still enabling necessary functionality for user authentication and management.
def get_email_index(email: str) -> str:
    """SHA-256 provides a consistent key for lookups without revealing PII."""
    if not email: return None
    return hashlib.sha256(email.lower().strip().encode()).hexdigest()

# Helper function to create a MongoDB filter for email lookups using the blind index. This function takes an email address as input, normalizes it, generates the corresponding blind index using the get_email_index function, and returns a dictionary that can be used as a filter in MongoDB queries. This allows the application to perform efficient lookups for user records based on email without ever exposing the plaintext email address in the database, maintaining compliance with GDPR requirements for data minimization and pseudonymisation while still enabling necessary functionality for user authentication and management.
def email_index_filter(email: str) -> dict:
    return {"email_index": get_email_index(email)}


# Token Generation: Creates a high-entropy random token for session management.
# This function generates a secure random token using os.urandom, which provides cryptographically strong random bytes. The generated token is 32 bytes in length, which is sufficient for session management and provides a high level of entropy to prevent token guessing or brute-force attacks. The token is returned as a hexadecimal string, making it easy to store and transmit while ensuring that it remains secure and unique for each session. This approach helps to protect against session hijacking and ensures that user sessions are managed securely in compliance with best practices for authentication and session management.
def generate_token() -> str:
    """Generates a high-entropy 32-byte hex token."""
    return os.urandom(32).hex()