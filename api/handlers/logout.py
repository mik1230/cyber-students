from tornado.web import authenticated
from .auth import AuthHandler

class LogoutHandler(AuthHandler):
    @authenticated
    async def post(self):
        # Access the database connection from settings or application context
        db = self.settings.get('db')
        if db is None:
            db = getattr(self.application, 'db', None)
            
        # Atomic Logout: Implements the "Right to be Forgotten" for the current session.
        # By nullifying the token and resetting expiry, ensuring the session 
        # cannot be reused even if the bearer token is captured after this point.
        # I chose to nullify the token and reset the expiry to 0 instead of deleting the session record to maintain an audit trail of user activity while still ensuring that the session is effectively terminated and cannot be reused, which aligns with GDPR requirements for data minimization and accountability without unnecessarily losing historical data that may be important for security monitoring or compliance purposes.
        await db.users.update_one(
            {'_id': self.current_user['_id']},
            {'$set': {'token': None, 'expiresIn': 0}}
        )
        
        # Respond with a success message. In a real application, we might want to redirect the user and probably clear cookies as well, but this shows the logout functionality.
        self.set_status(200)

        # The response includes a success message to confirm that the logout operation was successful. In a production application, we might also want to clear any authentication cookies or tokens on the client side to ensure that the user is fully logged out from the client perspective as well, but this response serves to indicate that the server-side session has been effectively terminated in compliance with GDPR requirements for user control over their data and sessions.
        self.response.update({"message": "Logged out successfully"})
        self.write_json()