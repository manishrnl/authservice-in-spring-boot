package org.example.controller;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
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
    private UserDetailsServiceImpl userDetailsService;

    @PostMapping("auth/v1/signup")
    public ResponseEntity SignUp(@RequestBody UserInfoDto userInfoDto) {

        try {
            // To check if Password and Email are valid
            Boolean isEmailValid = validateEmailPass.validateEmail(userInfoDto.getEmail());
            Boolean isPasswordMatched = validateEmailPass.validatePassword(userInfoDto.getPassword());
            Boolean isSignUped = userDetailsService.signupUser(userInfoDto);

            if (!isSignUped) {
                return new ResponseEntity<>("Users with username : \"" + userInfoDto.getUsername() +
                        "\" already Exist.Try Signing up with different userNames",
                        HttpStatus.BAD_REQUEST);
            }

            if (!isPasswordMatched) {
                return new ResponseEntity<>("", HttpStatus.BAD_REQUEST);
            }
            if (!isEmailValid) {
                return new ResponseEntity<>("",
                        HttpStatus.BAD_REQUEST);
            }
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(userInfoDto.getUsername());
            String jwtToken = jwtService.GenerateToken(userInfoDto.getUsername());
            return new ResponseEntity<>(JwtResponseDTO.builder().accessToken(jwtToken).token(refreshToken.getToken()).build(), HttpStatus.OK);
        } catch (Exception ex) {
            return new ResponseEntity<>("Exception in User Service : " + ex.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
