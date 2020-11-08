package com.service.auth.user;

import com.service.auth.domain.User;
import com.service.auth.repository.UserRepository;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.Collections;

@RunWith(SpringRunner.class)
@SpringBootTest
public class UserRepositoryTest {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    public void insertNewUserTest() {
        userRepository.save(User.builder()
                .uid("hello")
                .password(passwordEncoder.encode("1234"))
                .name("hello")
                .roles(Collections.singletonList("ROLE_USER"))
                .build());
    }
}