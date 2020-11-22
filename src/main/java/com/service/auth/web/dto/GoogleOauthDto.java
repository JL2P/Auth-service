package com.service.auth.web.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@NoArgsConstructor
@ToString
@Setter
@Getter
public class GoogleOauthDto {
    private GoogleAttributesDto attributes;
}
