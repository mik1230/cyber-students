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
    def setUpClass(cls): # Changed from self to cls
        from api.handlers.registration import RegistrationHandler
        from api.handlers.login import LoginHandler
    
        # Use cls.my_app instead of self.my_app
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
        # 1. SETUP: Register the user so they exist in this specific test's DB
        reg_body = {
            'email': self.email, 
            'password': self.password, 
            'displayName': 'Test User'
        }
        self.fetch('/students/api/registration', method='POST', body=dumps(reg_body))

        # 2. ACT: Attempt to log in with those same credentials
        login_body = {
            'email': self.email, 
            'password': self.password
        }
        response = self.fetch('/students/api/login', method='POST', body=dumps(login_body))
        
        # 3. ASSERT: This should now be 200
        self.assertEqual(200, response.code)
        body = json_decode(response.body)
        self.assertEqual("success", body['status'])

    def test_login_case_insensitive(self):
        # 1. SETUP: Register with mixed case
        reg_body = {
            'email': 'MixedCase@Example.com', 
            'password': self.password, 
            'displayName': 'Case Tester'
        }
        self.fetch('/students/api/registration', method='POST', body=dumps(reg_body))

        # 2. ACT: Login with lowercase version
        login_body = {
            'email': 'mixedcase@example.com', 
            'password': self.password
        }
        response = self.fetch('/students/api/login', method='POST', body=dumps(login_body))
        
        # 3. ASSERT: This proves your .lower().strip() normalization is working
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
