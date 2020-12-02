package com.service.auth.web.dto;

import com.service.auth.web.OAuthToken;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class OAuthTokenGoogle extends OAuthToken {
    private String email;
    private String accountId;
}