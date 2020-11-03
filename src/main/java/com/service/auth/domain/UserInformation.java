//package com.service.auth.domain;
//
//import lombok.Data;
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.core.userdetails.UserDetails;
//
//import java.util.List;
//
//@Data
//public
//class UserInformation implements UserDetails {
//
//    private String username;
//    private String password;
//    private List<GrantedAuthority> authorities;
//
//    @Override
//    public boolean isAccountNonExpired() {
//        // TODO Auto-generated method stub
//        return true;
//    }
//
//    @Override
//    public boolean isAccountNonLocked() {
//        // TODO Auto-generated method stub
//        return true;
//    }
//
//    @Override
//    public boolean isCredentialsNonExpired() {
//        // TODO Auto-generated method stub
//        return true;
//    }
//
//    @Override
//    public boolean isEnabled() {
//        // TODO Auto-generated method stub
//        return true;
//    }
//}