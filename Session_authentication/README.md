# 0x07. Session authentication

## Resources:books:
Read or watch:
* [REST API Authentication Mechanisms - Only the session auth part](https://intranet.hbtn.io/rltoken/2BkSCmFq5HYwztDCQuAwvg)
* [HTTP Cookie](https://intranet.hbtn.io/rltoken/NMb6uXgVOVq0Tv7x_dbLEA)
* [Flask](https://intranet.hbtn.io/rltoken/D0AUceSjWti95ffW06MTHQ)
* [Flask Cookie](https://intranet.hbtn.io/rltoken/-TgSvgacXt556tD3bMFXcg)

---
## Learning Objectives:bulb:
What you should learn from this project:

* What authentication means
* What session authentication means
* What Cookies are
* How to send Cookies
* How to parse Cookies 

---

### [0. Et moi et moi et moi!](./api/v1/app.py)
* Copy all your work of the 0x06. Basic authentication project in this new folder.


### [1. Empty session](./api/v1/auth/session_auth.py)
* Create a class SessionAuth that inherits from Auth. For the moment this class will be empty. It’s the first step for creating a new authentication mechanism:


### [2. Create a session](./api/v1/auth/session_auth.py)
* Update SessionAuth class:


### [3. User ID from Session ID](./api/v1/auth/session_auth.py)
* Update SessionAuth class:


### [4. Session cookie](./api/v1/auth/auth.py)
* Update api/v1/auth/auth.py by adding the method def session_cookie(self, request=None): that returns a cookie value from a request:


### [5. Before request](./api/v1/app.py)
* Update the @app.before_request method in api/v1/app.py:


### [6. Use Session ID for identifying a User](./api/v1/auth/session_auth.py)
* Update SessionAuth class:


### [7. New view for Session Authentication](./api/v1/views/session_auth.py)
* Create a new Flask view that handles all routes for the Session authentication.


### [8. Logout](./api/v1/auth/session_auth.py)
* Update the class SessionAuth by adding a new method def destroy_session(self, request=None): that deletes the user session / logout:


### [9. Expiration?](./api/v1/auth/session_exp_auth.py)
* Actually you have 2 authentication systems:


### [10. Sessions in database](./api/v1/auth/session_db_auth.py)
* Since the beginning, all Session IDs are stored in memory. It means, if your application stops, all Session IDs are lost.

---

## Author
* **Henriette Tuombe** - [henriettetuombe(https://github.com/henriettetuombe)
