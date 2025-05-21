package org.example.service;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.example.entities.UserInfo;
import org.example.model.UserInfoDto;
import org.example.repository.UserRepository;
import org.example.utils.ValidateEmailPass;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.UUID;

@Component
@AllArgsConstructor
@Data
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private final UserRepository userRepository;

    @Autowired
    private final PasswordEncoder passwordEncoder;


    @Autowired
    private final ValidateEmailPass validateEmailPass;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserInfo userInfo = userRepository.findByUsername(username);
        if (userInfo == null) {
            throw new UsernameNotFoundException("UserDetailsServiceImpl" +
                    ".loadByUserName  Could Not Found User with username: " + username);
        }
        return new CustomUserDetails(userInfo);
    }


    public UserInfo checkIfUserAlreadyExists(UserInfoDto userInfoDto) {
        return userRepository.findByUsername(userInfoDto.getUsername());
    }


    public Boolean signupUser(UserInfoDto userInfoDto) {

        if (checkIfUserAlreadyExists(userInfoDto) != null) {
            return false;
        }

        String userId = UUID.randomUUID().toString();

        try {

            String hashedPassword = passwordEncoder.encode(userInfoDto.getPassword());
            userRepository.save(new UserInfo(
                    userId,
                    userInfoDto.getUsername(),
                    hashedPassword,
                    new HashSet<>()
            ));

            System.out.println("User signed up successfully");
            return true;

        } catch (IllegalArgumentException ex) {
            System.out.println("Validation failed: " + ex.getMessage());
        }

        return false;
    }

}

