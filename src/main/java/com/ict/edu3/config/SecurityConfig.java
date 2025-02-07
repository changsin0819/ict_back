package com.ict.edu3.config;

import java.util.Arrays;

import org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.ict.edu3.security.JwtRequestFilter;
import com.ict.edu3.security.JwtUtil;
import com.ict.edu3.service.CustomerOAuth2UserService;
import com.ict.edu3.service.MemberService;
import com.ict.edu3.service.MyUserDetailService;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Configuration
public class SecurityConfig {
    private final JwtRequestFilter jwtRequestFilter;
    private final JwtUtil jwtUtil;
    private final MyUserDetailService userDetailService;
    private final MemberService memberService;

    public SecurityConfig(JwtRequestFilter jwtRequestFilter, JwtUtil jwtUtil, MyUserDetailService userDetailService, MemberService memberService){
        log.info("SecurityConfig 호출");
        this.jwtRequestFilter = jwtRequestFilter;
        this.jwtUtil = jwtUtil;
        this.userDetailService = userDetailService;
        this.memberService = memberService;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        log.info("SecurityFilterChain 호출\n");
        http
                // CORS 설정 적용
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                // CSRF 보호 비활성화 (JWT 사용시 일반적으로 사용)
                .csrf(csrf -> csrf.disable())
                // 요청별 권한 설정
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/upload/**").permitAll() // URL 경로(이미지 업로드)
                        .requestMatchers("/oauth2/**").permitAll() // URL 경로(소셜로그인)
                        .requestMatchers("/api/oauth2/**").permitAll() // URL 경로(소셜로그인)
                        .requestMatchers("/api/oauth2/authorization/**").permitAll() // URL 경로(소셜로그인)
                        // 특정 URL에 인증없이 허용
                        .requestMatchers("/api/members/register", "/api/members/login")
                        .permitAll()
                        // 나머지는 인증 필요
                        .anyRequest().authenticated())

                // oath2Login 설정
                // successHandler => 로그인 성공 시 호출
                // userInfoEndpoint => 인증과정에서 인증된 사용자에 대한 정보를 제공 하는 API 엔드포인트
                // (사용자 정보를 가져오는 역할을 한다.)
                // build.gradle
                // implementation 'org.springframework.boot:spring-boot-starter-oauth2-client'
                .oauth2Login(oauth2 -> oauth2
                        .successHandler(oAuth2AuthenticationSuccessHandler())
                        .userInfoEndpoint(userInfo -> userInfo.userService(oAuth2UserService())))

                // 사용자 요청이 오면 먼저 jwtRequestFilter가 실행되어 JWT 토큰을 검증한 후
                // 이상이 없으면 SpringSecurity의 인증된 사용자로 처리
                .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // 소셜 로그인 동의항목 처리
    @Bean
    OAuth2AuthorizationSuccessHandler oAuth2AuthenticationSuccessHandler(){
        return new OAuth2AuthorizationSuccessHandler(jwtUtil, userDetailService, memberService);
    }

    @Bean
    OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService(){
        return new CustomerOAuth2UserService();
    }

    // cross origin 설정
    @Bean
    CorsConfigurationSource corsConfigurationSource(){
        CorsConfiguration corsConfig = new CorsConfiguration();

        // 허용할 Origin 설정
        corsConfig.setAllowedOrigins(Arrays.asList("http://localhost:3000","http://35.216.18.100:3000/"));
        // 허용할 http 메서드 설정
        corsConfig.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        // 허용할 헤더 설정
        corsConfig.setAllowedHeaders(Arrays.asList("*"));
        // 인증정보 허용
        corsConfig.setAllowCredentials(true);

        // 모든 엔드포인트에 대해 설정 적용
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig);
        
        return source;
    }

    // 비밀번호 암호화
    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    // 사용자 신원 인증 처리 인터페이스
    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception{
        return authConfig.getAuthenticationManager();
    }
}
