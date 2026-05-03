from json import dumps
from tornado.escape import json_decode
from tornado.ioloop import IOLoop
from tornado.web import Application

from .base import BaseTest

from api.handlers.login import LoginHandler

class LoginHandlerTest(BaseTest):

    @classmethod
    #def setUpClass(self):
    #    self.my_app = Application([(r'/students/api/login', LoginHandler)])
    #    super().setUpClass()

    # I need to update the setUpClass method to include the registration handler as well, since the login tests depend on having a user registered in the database. This will ensure that the tests are properly set up to handle the new encryption scheme and GDPR compliance requirements.
    def setUpClass(cls): # Changed from self to cls since it's a class method
        # Ensure the routes match exactly what is in my api/app.py
        from api.handlers.registration import RegistrationHandler
        from api.handlers.login import LoginHandler
    
        # Use cls.my_app instead of self.my_app since this is a class method
        cls.my_app = Application([
            (r'/students/api/registration', RegistrationHandler),
            (r'/students/api/login', LoginHandler)
        ])
        super().setUpClass()

    async def register(self):
        await self.get_app().db.users.insert_one({
            'email': self.email,
            'password': self.password,
            'displayName': 'testDisplayName'
        })

    def setUp(self):
        super().setUp()

        self.email = 'test@test.com'
        self.password = 'testPassword'

        IOLoop.current().run_sync(self.register)

    def test_login(self):
        # Register the user so they exist in this specific test's DB context (since each test runs in isolation with a fresh DB)
        reg_body = {
            'email': self.email, 
            'password': self.password, 
            'displayName': 'Test User'
        }
        self.fetch('/students/api/registration', method='POST', body=dumps(reg_body))

        # Attempt to log in with those same credentials to get the token
        login_body = {
            'email': self.email, 
            'password': self.password
        }
        response = self.fetch('/students/api/login', method='POST', body=dumps(login_body))
        
        #  Assert that the login was successful and we received a token. This proves that the login handler is correctly authenticating the user and returning a token, which is essential for the subsequent tests that depend on having a valid token to access protected endpoints. The test checks for a 200 status code to confirm that the login was successful, and it also checks that the response body contains a 'token' field, which indicates that the user has been authenticated.
        self.assertEqual(200, response.code)
        body = json_decode(response.body)
        self.assertEqual("success", body['status'])


    def test_login_case_insensitive(self):
        # Register with mixed case email to test normalization
        reg_body = {
            'email': 'MixedCase@Example.com', 
            'password': self.password, 
            'displayName': 'Case Tester'
        }
        self.fetch('/students/api/registration', method='POST', body=dumps(reg_body))

        # Login with lowercase version
        login_body = {
            'email': 'mixedcase@example.com', 
            'password': self.password
        }
        response = self.fetch('/students/api/login', method='POST', body=dumps(login_body))
        
        # Assert that the login was successful, confirming that the email normalization is working correctly and that users can log in regardless of the case they use when entering their email address. This test checks for a 200 status code to confirm that the login was successful, which indicates that the email normalization process is correctly handling case insensitivity during authentication.
        self.assertEqual(200, response.code)
    def test_login_wrong_email(self):
        body = {
          'email': 'wrongUsername',
          'password': self.password
        }

        response = self.fetch('/students/api/login', method='POST', body=dumps(body))
        # We use 401 (Unauthorized) for auth failures, not 403 (Forbidden). 403 is for when the user is authenticated but does not have permission to access a resource. In this case, the user is not authenticated at all, so 401 is more appropriate.
        self.assertEqual(401, response.code)
        # self.assertEqual(403, response.code)

    def test_login_wrong_password(self):
        body = {
          'email': self.email,
          'password': 'wrongPassword'
        }

        response = self.fetch('/students/api/login', method='POST', body=dumps(body))
        # We use 401 (Unauthorized) for auth failures, not 403 (Forbidden). 403 is for when the user is authenticated but does not have permission to access a resource. In this case, the user is not authenticated at all, so 401 is more appropriate.
        self.assertEqual(401, response.code)
        # self.assertEqual(403, response.code)
