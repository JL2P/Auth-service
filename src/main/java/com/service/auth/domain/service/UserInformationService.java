//package com.service.auth.domain.service;
//
//import com.service.auth.domain.User;
//
//import com.service.auth.domain.UserInformation;
//import com.service.auth.repository.UserRepository;
//import lombok.RequiredArgsConstructor;
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.stereotype.Service;
//
//import javax.annotation.Resource;
//import java.util.ArrayList;
//import java.util.List;
//
//@RequiredArgsConstructor
//@Service("UserInformationService")
//public
//class UserInformationService implements UserDetailsService {
//
//    private final UserRepository userRepository;
//
//    @Override
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//
//        User user = userRepository.findByUsername(username);
//
//        // 저장된 ID가 없을때 throw 시켜줍니다.
//        if(user == null) {
//            throw new UsernameNotFoundException("wrongId"); // 저장된 ID 없음
//        }
//        return makeLoginUser(user);
//    }
//
//    // UserInformation 값 주입 해 줍니다.
//    public UserInformation makeLoginUser(User user) {
//
//        UserInformation loginUser  = new UserInformation();
//
//        List<GrantedAuthority> Authoritylist = new ArrayList<>();
//        switch(user.getUserType()) {
//            case 0 :
//                // admin
//                Authoritylist.add(new SimpleGrantedAuthority("ADMIN"));
//            case 1 :
//                // user
//                Authoritylist.add(new SimpleGrantedAuthority("USER"));
//                break;
//        }
//
//        loginUser.setUsername(user.getUsername());
//        loginUser.setPassword(user.getPassword());
//        loginUser.setAuthorities(Authoritylist);
//
//        return loginUser;
//    }
//}
