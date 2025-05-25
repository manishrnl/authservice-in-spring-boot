package org.example.controller;

import org.example.entities.RefreshToken;
import org.example.request.AuthRequestDTO;
import org.example.request.RefreshTokenRequestDTO;
import org.example.response.JwtResponseDTO;
import org.example.service.JwtService;
import org.example.service.RefreshTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TokenController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private JwtService jwtService;

    @PostMapping("auth/v1/login")
    public ResponseEntity AuthenticateAndGetToken(@RequestBody AuthRequestDTO authRequestDTO) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequestDTO.getUsername(), authRequestDTO.getPassword()));
        if (authentication.isAuthenticated()) {
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(authRequestDTO.getUsername());
            return new ResponseEntity<>(JwtResponseDTO.builder()
                    .accessToken(jwtService.GenerateToken(authRequestDTO.getUsername()))
                    .token(refreshToken.getToken())
                    .build(), HttpStatus.OK);

        } else {
            return new ResponseEntity<>("Unable to Login user.",
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("auth/v1/refreshToken")
    public JwtResponseDTO refreshToken(@RequestBody RefreshTokenRequestDTO refreshTokenRequestDTO) {
        return refreshTokenService.findAllByToken(refreshTokenRequestDTO.getToken())
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUserInfo)
                .map(userInfo -> {
                    String accessToken = jwtService.GenerateToken(userInfo.getUsername());
                    return JwtResponseDTO.builder()
                            .accessToken(accessToken)
                            .token(refreshTokenRequestDTO.getToken()).build();
                }).orElseThrow(() -> new RuntimeException("Refresh Token is not in DB..!!"));
    }

}

/*EXPLANATION OF AuthenticateAndGetToken Method:

Authentication authentication = authenticationManager.authenticate(...)
Calls Spring Security’s AuthenticationManager to authenticate the user using credentials.

Internally, it delegates to an AuthenticationProvider (commonly a DaoAuthenticationProvider)
 to validate the user credentials against a user store (usually a database via a
  UserDetailsService).

new UsernamePasswordAuthenticationToken(...)
This is an implementation of Spring Security’s Authentication interface.

It’s used to represent unauthenticated credentials (initial login attempt).

It contains:

Principal → the username

Credentials → the password

Example:

java
Copy
Edit
new UsernamePasswordAuthenticationToken("john_doe", "password123")
What happens internally:
The token is passed to the authentication provider.

The provider:

Uses UserDetailsService to load the user by username.

Compares the given password (after encoding it) with the stored password.

If valid, it returns a fully authenticated Authentication object (with user roles, etc.).

If invalid, it throws an AuthenticationException.

✅ Success → Authentication.isAuthenticated() == true
❌ Failure → Exception is thrown and not caught here (would propagate as HTTP 401/403 by default)

if (authentication.isAuthenticated())
Checks whether the Authentication object returned is marked as authenticated.

Usually redundant after authenticate(...), because:

If credentials are invalid, an exception would be thrown earlier.

But it's a safe check in case of custom AuthenticationManager behavior.

RefreshToken refreshToken = refreshTokenService.createRefreshToken(authRequestDTO.getUsername());
Calls a custom method to generate and store a new refresh token.

Likely:

Creates a UUID token string

Stores it in a database table with the associated username and expiration date

Returns the RefreshToken object containing the token string

🔁 Refresh tokens are long-lived tokens used to get new JWTs without re-entering credentials.

return new ResponseEntity<>(JwtResponseDTO.builder() ...
If authentication is successful:

A new JwtResponseDTO is built and returned as the response body.

A Spring ResponseEntity is returned with:

HTTP 200 OK

Body: JSON with:

A JWT accessToken (short-lived)

A refreshToken (long-lived)

jwtService.GenerateToken(authRequestDTO.getUsername())
Calls a custom service method to generate a JWT token using the provided username.

Internally:

Adds claims (like username, roles)

Sets expiry (e.g. 15 mins)

Signs it using a secret key (HS256 or RS256)

Returns a compact string

🔐 JWT is stateless: it allows the client to make authenticated requests without needing a session or DB call.

.token(refreshToken.getToken())
Retrieves the raw string from the RefreshToken object and includes it in the response DTO.

return new ResponseEntity<>(..., HttpStatus.OK);
Returns HTTP 200 OK along with the token payload.

✅ Final Response Example:

json
Copy
Edit
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR...",
  "token": "c1c8a2b4-1234-4321-bbd9-9c2a9e12b345"
}
else { return new ResponseEntity<>("Unable to Login user.", HttpStatus.INTERNAL_SERVER_ERROR); }
This block only runs if authentication.isAuthenticated() is false.

But in practice:

Invalid credentials throw exceptions (e.g. BadCredentialsException)

So this branch is unlikely to be reached unless you override behavior

🔒 Summary: How it Authenticates
Step	What Happens
1	Receives JSON body with username and password
2	Calls AuthenticationManager.authenticate(...)
3	Spring uses UserDetailsService to load user
4	Password is verified (via PasswordEncoder)
5	If valid → continues; if invalid → throws
6	Creates refresh token
7	Generates JWT token
8	Returns both tokens in response

Would you like an explanation of how to handle login failures more gracefully (e.g., returning 401 with proper messages)




*/