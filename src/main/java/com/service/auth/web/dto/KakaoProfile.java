package com.service.auth.web.dto;

import lombok.*;

@Getter
@Setter
@ToString
public class KakaoProfile {
    private Long id;
    private Properties properties;
    private Kakao_account kakao_account;

    @Getter
    @ToString
    private class Properties {
        private String nickname;
        private String thumbnail_image;
        private String profile_image;
    }

    @Getter
    @ToString
    private class Kakao_account{
        private String email;
        private Profile profile;

        @Getter
        private class Profile{
            private String profile_image_url;
        }
    }

    public String getNickname(){
        return this.properties.getNickname();
    }
    public String getEmail(){
        return this.kakao_account.getEmail();
    }
    public String getImgUrl(){
        return this.kakao_account.profile.getProfile_image_url();
    }
}