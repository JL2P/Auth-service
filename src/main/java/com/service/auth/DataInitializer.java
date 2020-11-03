//package com.service.auth;
//
//import com.service.auth.domain.User;
//import com.service.auth.repository.UserRepository;
//import lombok.RequiredArgsConstructor;
//import org.springframework.boot.ApplicationArguments;
//import org.springframework.boot.ApplicationRunner;
//import org.springframework.security.crypto.factory.PasswordEncoderFactories;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Component;
//
//import javax.annotation.Resource;
//import java.util.Date;
//
//@RequiredArgsConstructor
//@Component
//public class DataInitializer implements ApplicationRunner {
//
//    private final UserRepository userRepository;
//
//    @Override
//    public void run(ApplicationArguments args) throws Exception {
//
//        User newUser = new User();
//        PasswordEncoder passwordEncoder;
//        passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
//        newUser.setUsername("taes");
//        newUser.setPassword(passwordEncoder.encode("luke"));
//        newUser.setUserType(0);
//        newUser.setDate(new Date());
//        userRepository.save(newUser);
//    }
//}