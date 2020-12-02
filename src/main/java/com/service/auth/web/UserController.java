package com.service.auth.web;

import com.google.gson.Gson;
import com.service.auth.domain.User;
import com.service.auth.domain.service.KakaoService;
import com.service.auth.domain.service.UserService;
import com.service.auth.web.dto.*;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.*;

import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.util.Collections;


@Api(tags = {"2. User"})
@RequiredArgsConstructor
@RestController
@RequestMapping("/api/auth")
public class UserController {
    private final Gson gson;
    private final RestTemplate restTemplate;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final Environment env;
    private final KakaoService kakaoService;

    @Value("${security.oauth2.client.client-id}")
    private String clientId;
    @Value("${security.oauth2.client.client-secret}")
    private String clientSecret;
    @Value("${security.oauth2.jwt.signkey}")
    private String signKey;


    @Value("${spring.url.base}")
    private String baseUrl;

    @Value("${spring.social.kakao.client_id}")
    private String kakaoClientId;

    @Value("${spring.social.kakao.redirect}")
    private String kakaoRedirect;

    /**
     * 카카오 로그인 페이지
     */
    @ApiOperation(value = "카카오 로그인 페이지")
    @GetMapping(value="/social/login/kakao")
    public ResponseEntity<Object> socialLogin(ModelAndView mav) throws URISyntaxException {

        StringBuilder loginUrl = new StringBuilder()
                .append(env.getProperty("spring.social.kakao.url.login"))
                .append("?client_id=").append(kakaoClientId)
                .append("&response_type=code")
                .append("&redirect_uri=").append(baseUrl).append(kakaoRedirect);

        URI redirectUri = new URI(loginUrl.toString());
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setLocation(redirectUri);
        return new ResponseEntity<>(httpHeaders, HttpStatus.SEE_OTHER);
    }

    /**
     * 카카오 인증 완료 후 리다이렉트 화면
     */
    @ApiOperation(value = "카카오 인증 완료 후 리다이렉트")
    @GetMapping(value = "/kakao")
    public ResponseEntity<Object> redirectKakao(ModelAndView mav, @RequestParam String code) throws URISyntaxException {

        // Set header : Content-type: application/x-www-form-urlencoded
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        // Set parameter
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("client_id", kakaoClientId);
        params.add("redirect_uri", baseUrl + kakaoRedirect);
        params.add("code", code);
        // Set http entity
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        ResponseEntity<String> response = restTemplate.postForEntity(env.getProperty("spring.social.kakao.url.token"), request, String.class);
        RetKakaoAuth retKakaoAuth = null;
        if (response.getStatusCode() == HttpStatus.OK) {
            retKakaoAuth=  gson.fromJson(response.getBody(), RetKakaoAuth.class);
        }

//        System.out.println("http://localhost:3000/signin/"+retKakaoAuth.getAccess_token());
//        URI redirectUri = new URI("http://localhost:3000/signin/"+retKakaoAuth.getAccess_token());
        URI redirectUri = new URI("http://myplanit.co.kr/signin/"+retKakaoAuth.getAccess_token());
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setLocation(redirectUri);
        return new ResponseEntity<>(httpHeaders, HttpStatus.SEE_OTHER);
    }

    @ApiOperation(value = "카카오 회원 가입")
    @PostMapping("/signin/kakao/{token}")
    public OAuthTokenKakao kakaoLoign(@PathVariable String token){
        KakaoProfile kakaoProfile = kakaoService.getKakaoProfile(token);
        String uid = "";
        String name = "";

        if(kakaoProfile.getEmail() != null){
            uid = kakaoProfile.getEmail();
            int idx = uid.indexOf("@");
            name = uid.substring(0, idx);
        }else{
            uid =  kakaoProfile.getNickname()+"@kakao.com";
            name = kakaoProfile.getNickname();
        }

        //유저가 존재하지 않을 경우
        if(userService.existCheckUser(uid)){
            User newUser = User.builder()
                    .uid(uid)
                    .password(passwordEncoder.encode(signKey))
                    .name(name)
                    .roles(Collections.singletonList("ROLE_USER"))
                    .build();

            userService.addUser(newUser);
        }

        String credentials = clientId+":"+clientSecret;
        String encodedCredentials = new String(Base64.encodeBase64(credentials.getBytes()));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add("Authorization", "Basic " + encodedCredentials);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("username", uid);
        params.add("password", signKey);
        params.add("grant_type", "password");
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        ResponseEntity<String> response = restTemplate.postForEntity("http://localhost:9000/oauth/token", request, String.class);
        if (response.getStatusCode() == HttpStatus.OK) {
            OAuthTokenKakao oAuthTokenKakao =  gson.fromJson(response.getBody(), OAuthTokenKakao.class);
            oAuthTokenKakao.setAccountId(name);
            oAuthTokenKakao.setEmail(uid);
            oAuthTokenKakao.setImgUrl(kakaoProfile.getImgUrl());
            return oAuthTokenKakao;
        }
        return null;
    }




    //Redirect하기 위한 URL
    //Oauth2인증 Url이 /oauth2/authorization/google 이어서 프론트쪽에서 cors발생 할 것 같기 때문
    @ApiOperation(value = "구글 로그인")
    @GetMapping("/signin/google")
    public ResponseEntity<Object> redirect() throws URISyntaxException {

        URI redirectUri = new URI("http://myplanit.co.kr/oauth2/authorization/google");
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setLocation(redirectUri);
        return new ResponseEntity<>(httpHeaders, HttpStatus.SEE_OTHER);
    }

    @ApiOperation(value = "구글 로그인 리다이렉트 URL")
    @GetMapping("/google")
    public void googleLogin( Authentication authentication, HttpServletResponse re_response) throws IOException {
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

//        if (response.getStatusCode() == HttpStatus.OK) {
//            return gson.fromJson(response.getBody(), OAuthToken.class);
//        }
//        return null;
          re_response.sendRedirect("http://myplanit.co.kr/signin/"+googleOauthDto.getAttributes().getEmail());
    }

    @ApiOperation(value = "서비스 자체 회원 가입")
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

    @ApiOperation(value = "서비스 자체 로그인")
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

    @ApiOperation(value = "서비스 탈퇴")
    @DeleteMapping("/{accountId}")
    public String signout(@PathVariable String accountId){
        userService.deleteUser(accountId);
        return "sucess";
    }

}
