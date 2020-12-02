package com.service.auth.domain.service;

import com.service.auth.domain.User;
import com.service.auth.exception.UserExistException;
import com.service.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.NoSuchElementException;
import java.util.Optional;

@RequiredArgsConstructor
@Service
public class UserService {

    private final UserRepository userRepository;

    public void addUser(User user){
        Optional<User> userOpt = userRepository.findByUid(user.getUid());
        if(userOpt.isPresent()) throw new UserExistException("user is exists");

        userRepository.save(user);
    }

    public boolean existCheckUser(String uid){
        Optional<User> todoOpt = userRepository.findByUid(uid);
        return todoOpt.isEmpty();
    }

    public void deleteUser(String accountId){
        User userOpt = userRepository.findByName(accountId).orElseThrow(()-> new NoSuchElementException());
        userRepository.delete(userOpt);
    }

}
