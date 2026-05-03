from tornado.web import authenticated
from .auth import AuthHandler
from ..security import decrypt_pii
import json

class UserHandler(AuthHandler):

    @authenticated
    def get(self):
        # This handler implements the Data Subject's "Right of Access" (GDPR Art. 15).
        # Data is stored in ciphertext "at rest" and only decrypted "in use" 
        # after the student's session is cryptographically verified.
        user = self.current_user
        
        self.set_status(200)
        
        # 1. Decrypt the PII for the response
        # We use .get() to prevent crashes if a field is missing, and decrypt_pii to ensure data is only decrypted when accessed.
        self.response['email'] = decrypt_pii(user['email'])
        self.response['displayName'] = decrypt_pii(user['displayName'])
        
        # 2. Add the new GDPR fields (Decrypted)
        # Use .get() to prevent crashes if a field is missing and decrypt_pii to ensure data is only decrypted when accessed.
        self.response['fullName'] = decrypt_pii(user.get('fullName', ''))
        self.response['address'] = decrypt_pii(user.get('address', ''))
        
        # 3. Handle the disabilities list, which is stored as encrypted JSON. We need to decrypt it and then parse the JSON to return it as a list.
        try:
            decrypted_disabilities = decrypt_pii(user.get('disabilities', ''))
            self.response['disabilities'] = json.loads(decrypted_disabilities)
        except:
            self.response['disabilities'] = []

        self.write_json()