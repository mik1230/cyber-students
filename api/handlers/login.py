from tornado.escape import json_decode
from .base import BaseHandler
from datetime import datetime, timezone
from ..security import hash_password, encrypt_pii, get_email_index, verify_password, decrypt_pii, generate_token 

class LoginHandler(BaseHandler):
    
    async def post(self):
    # Try getting DB from settings first 
        db = self.settings.get('db')
    
    # If it wasn't in settings, try the application object 
        if db is None:
            db = getattr(self.application, 'db', None)

    # If it's still None, then we actually have a problem
        if db is None:
            self.set_status(500)
            self.write({"error": "Database connection not found"})
            return
        # Parse and validate input with error handling
        try:
            data = json_decode(self.request.body)
            # Normalize email input for consistent SHA-256 indexing
            email_input = str(data.get('email', '')).lower().strip()
            password_input = data.get('password')
            
            # Basic validation to ensure email and password are provided.   
            if not email_input or not password_input:
                self.set_status(400)
                self.write({"error": "You must provide an email and password!"})
                return
        except Exception:
            self.set_status(400)
            self.write({"error": "Invalid request format"})
            return

        # Find the user by the SHA-256 blind index of the email. This allows us to look up users without storing plaintext emails, maintaining GDPR compliance. The get_email_index function generates a consistent hash for the email, enabling efficient lookups while keeping the actual email address protected in the database. This approach ensures that we can authenticate users based on their email without ever exposing the plaintext email address in our database, enhancing security and privacy. By using a blind index, we can perform O(1) lookups for user records while still adhering to GDPR requirements for data minimization and pseudonymisation, ensuring that personally identifiable information is handled securely and responsibly.
        user = await db.users.find_one({'email_index': get_email_index(email_input)})

        # verify_password uses Scrypt KDF.  
        # Memory-hard hashing protects against hardware-accelerated brute-force attacks. 
        # By using Scrypt with a high work factor, we can significantly increase the time and resources required for an attacker to crack passwords, even if they have access to powerful hardware. This makes it much more difficult for attackers to compromise user accounts through brute-force methods, enhancing the overall security of the authentication system. The verify_password function re-hashes the input password using the same salt and parameters as the original hash, allowing us to securely compare the two hashes without exposing sensitive information or being vulnerable to timing attacks.
        if user and verify_password(password_input, user['password']):
            
            # Generate high-entropy (just a high level of randomness) raw token and encrypt it at rest.
            # Prevents session hijacking even if the database is leaked.
            raw_token = generate_token()
            # Encrypt token using AES-GCM before database storage
            secure_token = encrypt_pii(raw_token)

        # Set token expiry to 1 hour from now. This satisfies GDPR "Storage Limitation" by ensuring that old sessions are automatically invalidated, reducing the risk of long-term token misuse if a database leak occurs. By setting an expiration time on the session token, we can limit the window of opportunity for attackers to use stolen tokens, enhancing the security of user sessions while still providing a reasonable duration for users to remain logged in without frequent re-authentication.
            expiry_timestamp = datetime.now(timezone.utc).timestamp() + 3600
            
            # Update database with session details
            await db.users.update_one(
                {"_id": user["_id"]},
                {"$set": {
                    "token": secure_token, 
                    "expiresIn": expiry_timestamp
                }}
            )

            # Final Success Response with UNENCRYPTED token and decrypted display name. The raw token is sent back to the user for use in subsequent authenticated requests, while the display name is decrypted for user interface purposes. This approach ensures that sensitive information is protected at rest in the database while still allowing the application to provide necessary functionality and a good user experience. By returning the raw token, we enable users to authenticate future requests, while decrypting the display name allows us to personalize the user interface without exposing sensitive data in the database. The response includes the raw token for client-side use and the decrypted display name for a personalized user experience, while ensuring that all sensitive information is handled securely in compliance with GDPR requirements for data protection and user privacy.
            # Decrypt the AES-GCM displayName for the user interface
            return self.write({
                "status": "success",
                "token": raw_token,
                "displayName": decrypt_pii(user.get('displayName'))
            })
        
        else:
            # Authentication failed: Respond with a generic error message to avoid giving clues about which part of the credentials was incorrect. This is a security best practice to prevent user enumeration attacks, where attackers can determine valid email addresses based on error messages. By using a generic error message, we can enhance the security of the authentication system while still providing feedback to users that their login attempt was unsuccessful.
            # Note: Using 401 (Unauthorised) is standard for auth failures, I updated this from 403 (Forbidden) to be more semantically correct, as 403 is typically used when authentication succeeded but the user does not have permission to access a resource, while 401 indicates that authentication failed, which is the case here.
            self.set_status(401)
            self.write({"error": "The email address and password are invalid!"})