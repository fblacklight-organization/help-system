from dataclasses import dataclass
from typing import Optional

from django.utils.translation import gettext_lazy as _
from requests_oauthlib import OAuth2Session
from django.conf import settings
import jwt

@dataclass
class OAuth2:
    _oauth2_session: OAuth2Session = None

    @property
    def oauth2_session(self) -> OAuth2Session:
        if not self._oauth2_session:
            self._oauth2_session = OAuth2Session(
                client_id=settings.OAUTH2_CLIENT_ID,
                redirect_uri=settings.OAUTH2_REDIRECT_URI,
                scope=settings.OAUTH2_SCOPE,
            )
        return self._oauth2_session
    
    def get_authorization_url(self) -> tuple[str, str]:
        return self.oauth2_session.authorization_url(
            settings.OAUTH2_AUTH_URL,
        )

    def fetch_token(self, code: str) -> str:
        token = self.oauth2_session.fetch_token(
            token_url=settings.OAUTH2_TOKEN_URL,
            client_id=settings.OAUTH2_CLIENT_ID,
            client_secret=settings.OAUTH2_CLIENT_SECRET,
            code=code,
        )
        return token
    
    def _get_token_content(self) -> dict:
        return jwt.decode(
            jwt=self.oauth2_session.token['id_token'], 
            key=settings.OAUTH2_CLIENT_SECRET, 
            audience=settings.OAUTH2_CLIENT_ID,
            algorithms=["HS256"]
        )
    def get_registration_info(self) -> dict | None:
        return self._get_token_content()["registration"]

    def get_user_info(self) -> dict:
        return self.oauth2_session.get(
            settings.OAUTH2_USERINFO_URL).json()