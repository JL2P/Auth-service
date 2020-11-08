package com.service.auth.domain.service;

import com.service.auth.domain.User;
import com.service.auth.exception.UserExistException;
import com.service.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@RequiredArgsConstructor
@Service
public class UserService {

    private final UserRepository userRepository;

    public void addUser(User user){
        Optional<User> todoOpt = userRepository.findByUid(user.getUid());
        if(todoOpt.isPresent()) throw new UserExistException("user is exists");

        userRepository.save(user);
    }
}
