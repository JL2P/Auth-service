package com.service.auth.config;

import com.service.auth.domain.service.CustomAuthenticationProvider;
import com.service.auth.domain.service.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomAuthenticationProvider authenticationProvider;

    @Override
    protected void configure(AuthenticationManagerBuilder auth){
        auth.authenticationProvider(authenticationProvider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .headers().frameOptions().disable()
                .and()
                .authorizeRequests()
                .antMatchers(
                        "/api/auth/signin",
                        "/api/auth/signup",
                        "/api-docs/**",
                        "/api/auth/signin/google",
                        "/api/auth/google",
                        "/oauth2/authorization/**",
                        "/api/auth/**",
                        "/oauth/token")
                .permitAll()
//                .anyRequest().access("@authorizationChecker.check(request, authentication)")
                .and()
                .oauth2Login()
                    .userInfoEndpoint()
                        .userService(customOAuth2UserService)
                .and()
                .defaultSuccessUrl("http://localhost:4000/api/auth/google");
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception{
        return super.authenticationManagerBean();
    }

    @Override // ignore check swagger resource
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers("/v2/api-docs", "/swagger-resources/**",
                "/swagger-ui.html", "/webjars/**", "/swagger/**");

    }
}
