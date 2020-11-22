package com.service.auth.config;

import com.service.auth.domain.User;
import com.service.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;

@RequiredArgsConstructor
@Component
public class AuthorizationChecker {
    private UserRepository userRepository;

    public boolean check(HttpServletRequest request, Authentication authentication) {
        Object principalObj = authentication.getPrincipal();

        if (!(principalObj instanceof User)) {
            return false;
        }
        return true;
    }
}
