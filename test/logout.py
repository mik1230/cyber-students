from json import dumps
from tornado.escape import json_decode
from tornado.httputil import HTTPHeaders
from tornado.web import Application
from .base import BaseTest

# Import the handlers needed for the full flow
from api.handlers.registration import RegistrationHandler
from api.handlers.login import LoginHandler
from api.handlers.logout import LogoutHandler

class LogoutHandlerTest(BaseTest):

    @classmethod
    def setUpClass(cls):
        # Ensure the routes match exactly what is in your api/app.py
        cls.my_app = Application([
            (r'/students/api/registration', RegistrationHandler),
            (r'/students/api/login', LoginHandler),
            (r'/students/api/logout', LogoutHandler)
        ])
        super().setUpClass()

    def test_logout(self):
        """Full flow: Register, Login, then Logout"""
        email = 'logout_test@test.com'
        password = 'password123'
        
        # 1. Register the user
        reg_body = {'email': email, 'password': password, 'displayName': 'LogoutUser'}
        self.fetch('/students/api/registration', method='POST', body=dumps(reg_body))

        # 2. Login to get the encrypted token
        login_resp = self.fetch('/students/api/login', method='POST', body=dumps({'email': email, 'password': password}))
        token = json_decode(login_resp.body)['token']

        # 3. Logout using that token
        headers = HTTPHeaders({'X-Token': token})
        response = self.fetch('/students/api/logout', method='POST', headers=headers, body="")
        self.assertEqual(200, response.code)

    def test_logout_without_token(self):
        # Should return 400 as per your AuthHandler logic
        response = self.fetch('/students/api/logout', method='POST', body="")
        self.assertEqual(400, response.code)

    def test_logout_wrong_token(self):
        # Should return 403 as per your AuthHandler logic
        headers = HTTPHeaders({'X-Token': 'this_token_does_not_exist'})
        response = self.fetch('/students/api/logout', method='POST', headers=headers, body="")
        self.assertEqual(403, response.code)

    def test_logout_twice(self):
        """Verify a token can't be used twice"""
        email = 'logout_twice@test.com'
        password = 'password123'
        
        # Setup: Register and Login
        self.fetch('/students/api/registration', method='POST', body=dumps({'email': email, 'password': password, 'displayName': 'Twice'}))
        login_resp = self.fetch('/students/api/login', method='POST', body=dumps({'email': email, 'password': password}))
        token = json_decode(login_resp.body)['token']
        headers = HTTPHeaders({'X-Token': token})

        # First logout (Should succeed)
        resp1 = self.fetch('/students/api/logout', method='POST', headers=headers, body="")
        self.assertEqual(200, resp1.code)

        # Second logout (Should fail 403 because token is now cleared in DB)
        resp2 = self.fetch('/students/api/logout', method='POST', headers=headers, body="")
        self.assertEqual(403, resp2.code)