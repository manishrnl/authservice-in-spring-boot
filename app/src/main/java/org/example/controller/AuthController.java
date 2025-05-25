package org.example.controller;

import lombok.AllArgsConstructor;
import org.example.entities.RefreshToken;
import org.example.model.UserInfoDto;
import org.example.response.JwtResponseDTO;
import org.example.service.JwtService;
import org.example.service.RefreshTokenService;
import org.example.service.UserDetailsServiceImpl;
import org.example.utils.ValidateEmailPass;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@AllArgsConstructor
@RestController
public class AuthController {

    @Autowired
    private JwtService jwtService;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private final ValidateEmailPass validateEmailPass;

    @Autowired
    private UserDetailsServiceImpl userDetailsServiceImpl;

    @PostMapping("auth/v1/signup")
    public ResponseEntity SignUp(@RequestBody UserInfoDto userInfoDto) {

        try {
            // To check if Password and Email are valid
            Boolean isEmailValid = validateEmailPass.validateEmail(userInfoDto.getEmail());
            Boolean isPasswordValid =
                    validateEmailPass.validatePassword(userInfoDto.getPassword());
            Boolean isSignUped = userDetailsServiceImpl.signupUser(userInfoDto);

            if (!isSignUped) {
                return new ResponseEntity<>("Users with username : \"" + userInfoDto.getUsername() +
                        "\" already Exist.Try Signing up with different userNames",
                        HttpStatus.BAD_REQUEST);
            }

            if (!isPasswordValid) {
                return new ResponseEntity<>("", HttpStatus.BAD_REQUEST);
            }
            if (!isEmailValid) {
                return new ResponseEntity<>("",
                        HttpStatus.BAD_REQUEST);
            }
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(userInfoDto.getUsername());
            String jwtToken = jwtService.GenerateToken(userInfoDto.getUsername());
            return new ResponseEntity<>(
                    JwtResponseDTO
                            .builder()
                            .accessToken(jwtToken)
                            .token(refreshToken.getToken())
                            .build(), HttpStatus.OK);
        } catch (Exception ex) {
            return new ResponseEntity<>(" AuthController.Signup: Exception in AuthController While creating account " + ex.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}



/*
 How tokens is created and returned in AuthController after saving it to databases :

RefreshToken refreshToken = refreshTokenService.createRefreshToken(userInfoDto.getUsername());
String jwtToken = jwtService.GenerateToken(userInfoDto.getUsername());
return new ResponseEntity<>(JwtResponseDTO.builder()
        .accessToken(jwtToken)
        .token(refreshToken.getToken())
        .build(), HttpStatus.OK);
🔹 Step-by-Step Explanation:
✅ 1. refreshTokenService.createRefreshToken(username)
This method is responsible for:

Creating a new refresh token for the specified username.

Saving it to the database.

Returning the RefreshToken object, which includes a .getToken() method to retrieve the actual token string.

🔍 Typical implementation involves:

public RefreshToken createRefreshToken(String username) {
    RefreshToken refreshToken = new RefreshToken();
    refreshToken.setToken(UUID.randomUUID().toString()); // Generates a unique token
    refreshToken.setExpiryDate(Instant.now().plus(30, ChronoUnit.DAYS)); // Set expiry
    refreshToken.setUsername(username);
    refreshTokenRepository.save(refreshToken); // Saves token in DB
    return refreshToken;
}
🗂 Where It Saves:
The RefreshToken entity is saved in the database using a RefreshTokenRepository (likely extends JpaRepository<RefreshToken, Long>).

Fields typically include: id, token, expiryDate, and username or user relationship.

✅ 2. jwtService.GenerateToken(username)
This method generates a JWT (JSON Web Token) for the given username.

🔍 Typical steps inside this method:

public String GenerateToken(String username) {
    return Jwts.builder()
        .setSubject(username)
        .setIssuedAt(new Date())
        .setExpiration(new Date(System.currentTimeMillis() + JWT_EXPIRATION_MS))
        .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
        .compact();
}
🔐 How It Works:
Uses Java JWT library (like io.jsonwebtoken.Jwts) to create a signed token.

Encodes claims like subject (username), issuedAt, and expiration.

Signs the token with a secret key using HMAC or RSA.

Returns the JWT string (like: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9…)

✅ 3. Returning Tokens to Client

JwtResponseDTO.builder()
    .accessToken(jwtToken)
    .token(refreshToken.getToken())
    .build()
This builds a response DTO containing:

accessToken → the JWT (short-lived, e.g. 15 min – 2 hours)

token → the refresh token (long-lived, e.g. 30 days)

Then it wraps this DTO in a ResponseEntity with HttpStatus.OK (200), and sends it back to the client.

✅ Example Output:

{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token": "d9f1b7dc-1a1a-4c89-9e34-838b8c7d1ef4"
}
🧠 Summary:
 */