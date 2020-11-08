package com.service.auth.web.dto;

import com.service.auth.domain.User;
import lombok.Getter;
import lombok.NoArgsConstructor;
import java.util.Collections;

@NoArgsConstructor
@Getter
public class SignupDto {

    private String uid;         //email
    private String password;    //password
    private String name;        //name

    public User toEntity(String encodingPassoword) {
        return User.builder()
                .uid(this.uid)
                .password(encodingPassoword)
                .name(this.name)
                .roles(Collections.singletonList("ROLE_USER"))
                .build();
    }
}