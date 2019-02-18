# QtGoogleOAuth
A Qt implementation of Google OAuth2

This lib includes

1. An improvement (`AutoOAuth2`) of Qt's original 
   [`QOAuth2AuthorizationCodeFlow`](https://doc.qt.io/qt-5/qoauth2authorizationcodeflow.html)
   with combined httpserver as reply handler and automatic token refresh. 

2. Implementation of [Google's OAuth 2.0](https://developers.google.com/identity/protocols/OAuth2InstalledApp)
   (`GOAuth2`) on top of `AutoOAuth2` 
   
3. A simple test application. 
