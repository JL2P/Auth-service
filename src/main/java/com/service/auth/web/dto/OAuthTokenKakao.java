package com.service.auth.web.dto;

import com.service.auth.web.OAuthToken;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OAuthTokenKakao extends OAuthToken {
    private String email;
    private String accountId;
    private String imgUrl;
}
