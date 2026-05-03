from tornado.escape import json_decode
import json  # Import json to handle the disabilities list
from .base import BaseHandler
from ..security import hash_password, encrypt_pii, get_email_index 

class RegistrationHandler(BaseHandler):
    # This handler implements GDPR-compliant registration with encrypted PII and blind indexing.
    async def post(self):
        db = self.settings.get('db')
        if db is None:
            db = getattr(self.application, 'db', None)

        if db is None:
            self.set_status(500)
            self.write({"error": "Database connection not found"})
            return
        # Parse and validate input
        try:
            data = json_decode(self.request.body)
            # Registration logic implements "Privacy by Design" (GDPR Art. 25)
            # convert email to lowercase and strip whitespace for consistent indexing
            raw_email = str(data.get('email', '')).lower().strip()
            raw_password = data.get('password')
            raw_name = data.get('displayName')

            # GDPR FIELDS - These fields are required for the registration form, but will be encrypted before storage.
            # We use .get() with a default value to prevent crashes if a field is missing, but in a real application you would want to validate that required fields are present and properly formatted.
            full_name = data.get('fullName', '')
            address = data.get('address', '')
            dob = data.get('dob', '')
            phone = data.get('phone', '')
            disabilities = data.get('disabilities', []) # Expected as a list

            # Validation for required fields (you could expand this with regex for email, password strength, etc.) I don't want to overcomplicate the example, but in a production application you would want to add more robust validation here.
            if not raw_email or not raw_password or not raw_name:
                self.set_status(400)
                return self.write({"error": "You must provide an email address, password and display name!"})

            # Transform/Encrypt all sensitive PII
            hashed_password = hash_password(raw_password)
            # Use AES-256-GCM (Authenticated Encryption) for all PII.
            # This ensures Confidentiality and Integrity (detects tampering).
            encrypted_email = encrypt_pii(raw_email)
            encrypted_name = encrypt_pii(raw_name)
            # Create a SHA-256 Blind Index for searchable privacy.
            # Allows O(1) user lookups without storing plaintext email in the database.
            email_index = get_email_index(raw_email)

            # Encrypt the new GDPR fields using AES-GCM. Each field is encrypted separately to allow for selective decryption when accessed, and to ensure that all sensitive information is protected at rest in the database. The disabilities list is first converted to a JSON string before encryption, allowing us to store complex data structures securely while still maintaining the ability to retrieve and use this information when necessary. 
            enc_full_name = encrypt_pii(full_name)
            enc_address = encrypt_pii(address)
            enc_dob = encrypt_pii(dob)
            enc_phone = encrypt_pii(phone)
            # Special Category Data (Health/Disabilities) handled via Encrypted JSON.
            # Meets higher protection standards required by GDPR Article 9.
            enc_disabilities = encrypt_pii(json.dumps(disabilities))

        except Exception as e:
            self.set_status(400)
            return self.write({"error": str(e)})

        # Check if user exists
        user = await db.users.find_one({'email_index': email_index})
        if user is not None:
            self.set_status(409)
            return self.write({"error": "A user with the given email address already exists!"})

        # Store the new user with encrypted PII and blind index. The password is hashed using Scrypt for secure storage, and all personally identifiable information (PII) is encrypted using AES-GCM to ensure confidentiality and integrity. The email is also indexed using a SHA-256 blind index to allow for efficient lookups without exposing the plaintext email address in the database, maintaining compliance with GDPR requirements for data minimization and pseudonymisation. The disabilities list is stored as encrypted JSON to securely handle sensitive health data, which is classified as special category data under GDPR Article 9, ensuring that it is protected with the highest level of security measures. By implementing these security measures, we can ensure that user data is handled in a secure and compliant manner, protecting the privacy of our users while still allowing for necessary functionality in the application.
        await db.users.insert_one({
            'email': encrypted_email,
            'email_index': email_index,
            'password': hashed_password,
            'displayName': encrypted_name,
            'fullName': enc_full_name,        # AES-GCM Encrypted
            'address': enc_address,          # AES-GCM Encrypted
            'dob': enc_dob,                  # AES-GCM Encrypted
            'phone': enc_phone,              # AES-GCM Encrypted
            'disabilities': enc_disabilities, # AES-GCM Encrypted (Health Data)
            'token': None,
            'expiresIn': 0
        })

        # Respond with the encrypted email and display name (for demonstration). In a real application, we might want to return a success message or the decrypted display name instead, but this shows that the data is stored in encrypted form. The response includes the encrypted email and display name to demonstrate that the data is stored securely in the database, while the actual values are not exposed in plaintext. This approach ensures that sensitive information is protected at rest while still allowing the application to confirm that the registration was successful. In a production application, we would likely want to return a more user-friendly response, such as a success message or the decrypted display name, while still ensuring that sensitive data is not exposed unnecessarily in the response.
        self.set_status(200)
        self.response.update({
            'email': encrypted_email,
            'displayName': encrypted_name
        })

        self.write_json()