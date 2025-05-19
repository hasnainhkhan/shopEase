package com.thecodereveal.shopease.auth.controller;

import com.thecodereveal.shopease.auth.config.JWTTokenHelper;
import com.thecodereveal.shopease.auth.dto.LoginRequest;
import com.thecodereveal.shopease.auth.dto.RegistrationRequest;
import com.thecodereveal.shopease.auth.dto.RegistrationResponse;
import com.thecodereveal.shopease.auth.dto.UserToken;
import com.thecodereveal.shopease.auth.entities.User;
import com.thecodereveal.shopease.auth.services.RegistrationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@CrossOrigin
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JWTTokenHelper jwtTokenHelper;

    @PostMapping("/login")
    public ResponseEntity<UserToken> login(@RequestBody LoginRequest loginRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUserName(),
                            loginRequest.getPassword()
                    )
            );

            if (authentication.isAuthenticated()) {
                User user = (User) authentication.getPrincipal();

                if (!user.isEnabled()) {
                    return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
                }

                String token = jwtTokenHelper.generateToken(user.getUsername());

                UserToken userToken = new UserToken();
                userToken.setToken(token);
                userToken.setUserName(user.getUsername());

                return new ResponseEntity<>(userToken, HttpStatus.OK);
            }

        } catch (BadCredentialsException e) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }

        return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
    }

    @PostMapping("/register")
    public ResponseEntity<RegistrationResponse> register(@RequestBody RegistrationRequest request) {
        RegistrationResponse registrationResponse = registrationService.createUser(request);

        return new ResponseEntity<>(registrationResponse,
                registrationResponse.getCode() == 200 ? HttpStatus.OK : HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verifyCode(@RequestBody Map<String, String> map) {
        String userName = map.get("userName");
        String code = map.get("code");

        User user = (User) userDetailsService.loadUserByUsername(userName);
        if (user != null && user.getVerificationCode().equals(code)) {
            registrationService.verifyUser(userName);
            return new ResponseEntity<>(HttpStatus.OK);
        }

        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }
}
