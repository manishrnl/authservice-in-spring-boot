package org.example.utils;

import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class ValidateEmailPass {


    public Boolean validateEmail(String email) {
        if (email == null || email.isEmpty()) {
            throw new IllegalArgumentException("Email cannot be null or empty");
        }

        if (email.length() < 10) {
            throw new IllegalArgumentException("Email too short. Email must be at least 10 characters long");
        }

        if (email.length() > 50) {
            throw new IllegalArgumentException("Email length must be less than 50 characters");
        }

        // Basic email structure check
        String emailRegex = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$";
        if (!email.matches(emailRegex)) {
            throw new IllegalArgumentException("Invalid email format. Must be like \"abc@gmail.com\"");
        }

        // Extract domain and TLD to validate further
        String domainPart = email.substring(email.indexOf('@') + 1); // e.g., gmail.com
        String[] parts = domainPart.split("\\.");

        if (parts.length < 2) {
            throw new IllegalArgumentException("Email must contain a valid domain and top-level domain");
        }

        String domain = parts[0];
        String tld = parts[1];

        // Acceptable domains and TLDs
        List<String> validDomains = List.of(
                "gmail", "yahoo", "outlook", "hotmail", "edu", "gov", "company", "university", "business"
        );

        List<String> validTLDs = List.of(
                "com", "org", "net", "edu", "gov", "mil", "co", "ac", "in", "uk", "us", "au", "ca", "de", "fr", "jp", "cn", "it", "nl", "ru"
        );

        if (!validDomains.contains(domain)) {
            throw new IllegalArgumentException("Email must contain a valid domain name from: " + validDomains);
        }

        if (!validTLDs.contains(tld)) {
            throw new IllegalArgumentException("Email must contain a valid top-level domain from: " + validTLDs);
        }

        return true;
    }


    public Boolean validatePassword(String password) {
        if (password == null || password.length() < 12) {
            throw new IllegalArgumentException("Password must be at least 12 characters long");
        }

        if (!password.matches(".*[a-z].*")) {
            throw new IllegalArgumentException("Password must contain at least one lowercase letter");
        }

        if (!password.matches(".*[A-Z].*")) {
            throw new IllegalArgumentException("Password must contain at least one uppercase letter");
        }

        if (!password.matches(".*\\d.*")) {
            throw new IllegalArgumentException("Password must contain at least one digit");
        }

        if (!password.matches(".*[@$!%*?&].*")) {
            throw new IllegalArgumentException("Password must contain at least one special " +
                    "character among (@, $, !, %, *, ?, &)");
        }
        return true;
    }

}
