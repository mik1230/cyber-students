from concurrent.futures import ThreadPoolExecutor
from motor.motor_tornado import MotorClient
from tornado.web import Application

from .conf import MONGODB_HOST, MONGODB_DBNAME, WORKERS

from .handlers.welcome import WelcomeHandler
from .handlers.registration import RegistrationHandler
from .handlers.login import LoginHandler
from .handlers.logout import LogoutHandler
from .handlers.user import UserHandler

class Application(Application):

    def __init__(self):
        self.db = MotorClient(**MONGODB_HOST)[MONGODB_DBNAME]

        self.executor = ThreadPoolExecutor(WORKERS)

        handlers = [
            (r'/students/?', WelcomeHandler),
            (r'/students/api/?', WelcomeHandler),
            (r'/students/api/registration', RegistrationHandler),
            (r'/students/api/login', LoginHandler),
            (r'/students/api/logout', LogoutHandler),
            (r'/students/api/user', UserHandler)
        ]
        # The settings dictionary is passed to the Application constructor and can be accessed within handlers via          self.settings.get('db') for the database connection and self.settings.get('executor') for the thread pool executor. This allows handlers to easily access shared resources like the database and executor without needing to manage their own connections or thread pools, promoting code reuse and separation of concerns within the application.
        settings = {
            "db": self.db,  
            "executor": self.executor,
            "debug": True
        }

        super(Application, self).__init__(handlers, **settings)

        
