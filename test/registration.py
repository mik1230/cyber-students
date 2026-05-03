from json import dumps
from tornado.escape import json_decode
from tornado.ioloop import IOLoop
from tornado.web import Application

from api.handlers.registration import RegistrationHandler

from .base import BaseTest

import urllib.parse

class RegistrationHandlerTest(BaseTest):

    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r'/students/api/registration', RegistrationHandler)])
        super().setUpClass()
    # I need to update the setUpClass method to include the new fields in the registration handler. This will ensure that the tests are properly set up to handle the new encryption scheme and GDPR compliance requirements.
    def test_registration(self):
        email = "mike@test.com"
        # New GDPR fields
        full_name = "Michael B"
        disabilities = ["Dyslexia", "Visual Impairment"]
        
        body = {
            'email': email,
            'password': 'password123',
            'displayName': 'Mikey',
            'fullName': full_name,
            'address': '123 Carlow Lane',
            'dob': '1990-01-01',
            'phone': '0871234567',
            'disabilities': disabilities
        }

        response = self.fetch('/students/api/registration', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)
        
        body_2 = json_decode(response.body)

        # Verify basic fields are encrypted
        self.assertNotEqual(email, body_2['email'])
        
        # Verify the new sensitive fields are NOT plaintext
        # We check that the fullName is not returned in plaintext, and that the email is still present (but encrypted) to confirm that the response structure is correct.
        self.assertIn('email', body_2)
        self.assertNotEqual(full_name, body_2.get('fullName'))

    def test_registration_without_display_name(self):
        email = 'test@test.com'

        body = {
          'email': email,
          'password': 'testPassword'
        }

        response = self.fetch('/students/api/registration', method='POST', body=dumps(body))
        # We use 400 (Bad Request) for validation errors, which is more appropriate than 200 since the request is not valid without a display name. The test should check for the presence of the error message in the response to confirm that the validation is working correctly.
        self.assertEqual(400, response.code)
        # self.assertEqual(200, response.code)

        # I could remove this test as it is no longer valid with the new encryption scheme. The test should be updated to check for the presence of the encrypted values instead of the plaintext values.
        body_2 = json_decode(response.body)
        self.assertIn('error', body_2)
        
        # no need to check for body_2['email'] or body_2['displayName'] since the request should have failed and not returned those fields at all. Instead, we check for the presence of the error message in the response.

        # self.assertEqual(email, body_2['email'])
        # self.assertEqual(email, body_2['displayName'])

    def test_registration_twice(self):
        body = {
          'email': 'test@test.com',
          'password': 'testPassword',
          'displayName': 'testDisplayName'
        }

        response = self.fetch('/students/api/registration', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        response_2 = self.fetch('/students/api/registration', method='POST', body=dumps(body))
        self.assertEqual(409, response_2.code)
