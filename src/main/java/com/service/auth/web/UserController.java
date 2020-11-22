package com.service.auth.web;

import com.google.gson.Gson;
import com.service.auth.domain.service.UserService;
import com.service.auth.web.dto.GoogleOauthDto;
import com.service.auth.web.dto.LoginDto;
import com.service.auth.web.dto.SignupDto;
import io.swagger.annotations.Api;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;

import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;


@Api(tags = {"2. User"})
@RequiredArgsConstructor
@RestController
@RequestMapping("/api/auth")
public class UserController {
    private final Gson gson;
    private final RestTemplate restTemplate;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    @Value("${security.oauth2.client.client-id}")
    private String clientId;
    @Value("${security.oauth2.client.client-secret}")
    private String clientSecret;
    @Value("${security.oauth2.jwt.signkey}")
    private String signKey;

    //Redirect하기 위한 URL
    //Oauth2인증 Url이 /oauth2/authorization/google 이어서 프론트쪽에서 cors발생 할 것 같기 때문
    @GetMapping("/signin/google")
    public ResponseEntity<Object> redirect() throws URISyntaxException {
        URI redirectUri = new URI("http://localhost:9000/oauth2/authorization/google");
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setLocation(redirectUri);
        return new ResponseEntity<>(httpHeaders, HttpStatus.SEE_OTHER);
    }

    @GetMapping("/google")
    public OAuthToken googleLogin( Authentication authentication){
        Gson gson = new Gson();
        String json = gson.toJson(authentication.getPrincipal());
        GoogleOauthDto googleOauthDto = gson.fromJson(json, GoogleOauthDto.class);

        String credentials = clientId+":"+clientSecret;
        String encodedCredentials = new String(Base64.encodeBase64(credentials.getBytes()));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add("Authorization", "Basic " + encodedCredentials);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("username", googleOauthDto.getAttributes().getEmail());
        params.add("password", signKey);
        params.add("grant_type", "password");
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        ResponseEntity<String> response = restTemplate.postForEntity("http://localhost:9000/oauth/token", request, String.class);

        if (response.getStatusCode() == HttpStatus.OK) {
            return gson.fromJson(response.getBody(), OAuthToken.class);
        }
        return null;
    }

    @PostMapping("/signup")
    public OAuthToken addUser(@RequestBody SignupDto signupDto){
        userService.addUser(signupDto.toEntity(passwordEncoder.encode(signupDto.getPassword())));

        String credentials = clientId+":"+clientSecret;
        String encodedCredentials = new String(Base64.encodeBase64(credentials.getBytes()));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add("Authorization", "Basic " + encodedCredentials);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("username", signupDto.getUid());
        params.add("password", signupDto.getPassword());
        params.add("grant_type", "password");
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        ResponseEntity<String> response = restTemplate.postForEntity("http://localhost:9000/oauth/token", request, String.class);
        if (response.getStatusCode() == HttpStatus.OK) {
            return gson.fromJson(response.getBody(), OAuthToken.class);
        }
        return null;
    }

    @PostMapping("/signin")
    public OAuthToken callbackSocial(@RequestBody LoginDto loginDto) {

        String credentials = clientId+":"+clientSecret;
        String encodedCredentials = new String(Base64.encodeBase64(credentials.getBytes()));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add("Authorization", "Basic " + encodedCredentials);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("username", loginDto.getEmail());
        params.add("password", loginDto.getPassword());
        params.add("grant_type", "password");
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        ResponseEntity<String> response = restTemplate.postForEntity("http://localhost:9000/oauth/token", request, String.class);
        if (response.getStatusCode() == HttpStatus.OK) {
            return gson.fromJson(response.getBody(), OAuthToken.class);
        }
        return null;
    }
}
