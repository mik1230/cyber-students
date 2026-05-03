from json import dumps
from tornado.escape import json_decode
from tornado.httputil import HTTPHeaders
from tornado.web import Application
from .base import BaseTest

# Import all handlers to test the full flow
from api.handlers.registration import RegistrationHandler
from api.handlers.login import LoginHandler
from api.handlers.user import UserHandler

class UserHandlerTest(BaseTest):

    @classmethod
    def setUpClass(cls):
        # The test app needs all routes to perform the Setup-Act-Assert flow
        cls.my_app = Application([
            (r'/students/api/registration', RegistrationHandler),
            (r'/students/api/login', LoginHandler),
            (r'/students/api/user', UserHandler)
        ])
        super().setUpClass()

    def test_user_profile_decryption(self):
        """Verify the server decrypts sensitive GDPR data for authorized students"""
        email = 'test@test.com'
        password = 'testPassword'
        
        # 1. SETUP: Register via API (creates encrypted/hashed data)
        reg_body = {
            'email': email,
            'password': password,
            'displayName': 'Tester',
            'fullName': 'Michael Test',
            'address': '123 Cyber Ave',
            'dob': '1995-05-05',
            'phone': '0891234567',
            'disabilities': ['Visual Impairment']
        }
        self.fetch('/students/api/registration', method='POST', body=dumps(reg_body))

        # 2. SETUP: Login to get a real session token
        login_resp = self.fetch('/students/api/login', method='POST', body=dumps({
            'email': email, 'password': password
        }))
        token = json_decode(login_resp.body)['token']

        # 3. ACT: Fetch the profile using the secure token
        headers = HTTPHeaders({'X-Token': token})
        response = self.fetch('/students/api/user', headers=headers)
        
        # 4. ASSERT: The server should return DECRYPTED values
        self.assertEqual(200, response.code)
        body = json_decode(response.body)
        
        # Check that the decryption engine is working correctly
        self.assertEqual(email, body['email'])
        self.assertEqual('Michael Test', body['fullName'])
        self.assertIn('Visual Impairment', str(body['disabilities']))

    def test_user_unauthorized(self):
        """Verify that missing or invalid tokens are rejected"""
        response = self.fetch('/students/api/user')
        self.assertEqual(400, response.code) # Or 401, depending on your logic