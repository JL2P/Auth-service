package com.service.auth.web.dto;

import lombok.*;

@Getter
@Setter
@ToString
public class KakaoProfile {
    private Long id;
    private Properties properties;

    @Getter
    @ToString
    private class Properties {
        private String nickname;
        private String thumbnail_image;
        private String profile_image;
    }

    public String getNickname(){
        return this.properties.getNickname();
    }
}