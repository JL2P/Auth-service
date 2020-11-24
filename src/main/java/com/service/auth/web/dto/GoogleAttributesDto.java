package com.service.auth.web.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@NoArgsConstructor
@ToString
@Setter
@Getter
public class GoogleAttributesDto {
    private String name;
    private String given_name;
    private String family_name;
    private String picture;
    private String email;
}
