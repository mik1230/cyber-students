from datetime import datetime, timezone
from .base import BaseHandler
from ..security import decrypt_pii # Import the decryption function

class AuthHandler(BaseHandler):

    async def prepare(self):
        
        super(AuthHandler, self).prepare()
     
        if self.request.method == 'OPTIONS':
            return
        
       
        token_header = self.request.headers.get('X-Token')
        if not token_header:
            self.current_user = None
            self.send_error(400, message='You must provide a token!')
            return

        # Find the user with a non-null token (we will verify the token value in the next step). This allows us to quickly check if the provided token matches any active session in the database, while still keeping the actual token values encrypted at rest for security and GDPR compliance. By querying for users with a non-null token, we can efficiently determine if the token is valid without exposing sensitive information in our database queries. We will then decrypt the token and compare it to the provided token in the next steps to complete the authentication process, ensuring that we maintain a secure and compliant authentication system. This approach allows us to verify the authenticity of the token while keeping sensitive data protected in accordance with GDPR requirements for data security and privacy. By implementing this logic in the prepare method, we can ensure that all requests to handlers that inherit from AuthHandler are properly authenticated before any handler-specific logic is executed, providing a consistent and secure authentication mechanism across the application.
        user = await self.db.users.find_one({
            'token': {'$ne': None} 
        })

        if user is None:
            self.current_user = None
            self.send_error(403, message='Your token is invalid!')
            return

        # Decrypt the stored token for comparison. Since we store tokens encrypted in the database for security, we need to decrypt it before we can compare it to the token provided in the request header. This step is crucial for verifying that the token is valid and matches an active session, while still ensuring that sensitive information is protected at rest in the database. By decrypting the token, we can securely compare it to the provided token without exposing sensitive data in our database queries, maintaining compliance with GDPR requirements for data security and privacy. If decryption fails for any reason (e.g., tampering, corruption), we treat the token as invalid and respond with an appropriate error message, enhancing the security of our authentication system.
        try:
            stored_token_plaintext = decrypt_pii(user['token'])
        except Exception:
            self.current_user = None
            self.send_error(403, message='Token decryption failed!')
            return

        # Compare the decrypted token with the token provided in the request header. This is the final step in verifying the authenticity of the token, ensuring that it matches an active session in our database. By comparing the decrypted token to the provided token, we can confirm that the request is authenticated and proceed with processing it, while still maintaining a secure and compliant authentication system. If the tokens do not match, we treat it as an authentication failure and respond with an appropriate error message, preventing unauthorized access to protected resources. This approach allows us to securely verify the token while keeping sensitive information protected in accordance with GDPR requirements for data security and privacy, ensuring that our authentication system is robust and compliant with relevant regulations.
        if stored_token_plaintext != token_header:
            self.current_user = None
            self.send_error(403, message='Your token is invalid!')
            return

        
        current_time = datetime.now(timezone.utc).timestamp()
        if current_time > user.get('expiresIn', 0):
            self.current_user = None
            self.send_error(403, message='Your token has expired!')
            return

        # If we reach this point, the token is valid and has not expired, so we can set the current_user to the authenticated user record for use in subsequent request handling. This allows us to access user information in our request handlers without needing to perform additional database lookups, as we have already verified the user's identity and session validity in the prepare method. By setting self.current_user, we can provide a convenient way for request handlers to access authenticated user information while still maintaining a secure and compliant authentication system that adheres to GDPR requirements for data protection and privacy. This approach ensures that we can efficiently handle authenticated requests while keeping sensitive information protected and maintaining compliance with relevant regulations.
        self.current_user = user