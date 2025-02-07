package com.ict.edu3.config;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import com.ict.edu3.security.JwtUtil;
import com.ict.edu3.service.MemberService;
import com.ict.edu3.service.MyUserDetailService;
import com.ict.edu3.vo.MembersVO;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class OAuth2AuthorizationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final JwtUtil jwtUtil;
    private final MyUserDetailService userDetailService;
    private final MemberService memberService;
    
    public OAuth2AuthorizationSuccessHandler(JwtUtil jwtUtil, MyUserDetailService userDetailService, MemberService memberService){
        this.jwtUtil = jwtUtil;
        this.userDetailService = userDetailService;
        this.memberService = memberService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        try {
            log.info("OAuth2AuthorizationSuccessHandler");
            // 현재 인증 객체가 OAuth2 기반으로 인증 되었는지 확인하는 코드
            // OAuth2 (IETF에서 개발된 공개 표준 인증 프로토콜콜)
            if(authentication instanceof OAuth2AuthenticationToken){
                OAuth2AuthenticationToken oAuth2AuthenticationToken = (OAuth2AuthenticationToken) authentication;
                // 로그인 제공자 받기
                String provider = oAuth2AuthenticationToken.getAuthorizedClientRegistrationId();
                // CustomerOAuth2UserService에서 저장한 정보 호출
                OAuth2User oAuth2User = oAuth2AuthenticationToken.getPrincipal();
                String id    = oAuth2User.getAttribute("id");
                String email = oAuth2User.getAttribute("email");
                String name  = oAuth2User.getAttribute("name");
                String token = jwtUtil.generateAccessToken(id);

                
                // DB 저장
                // id로 DB에 있는지 검사
                MembersVO mvo = memberService.getMemberDetail(id);
                if(mvo == null){
                    // 있으면 token 넘기기
                    // 없으면 생성하고 넘기기
                    MembersVO mvo2 = new MembersVO();
                    mvo2.setM_id(id);
                    mvo2.setM_name(name);
                    mvo2.setSns_provider(provider);
                    if(provider.equals("kakao")){
                        mvo2.setSns_email_kakao(email);
                    }else if(provider.equals("naver")){
                        mvo2.setSns_email_naver(email);
                    }else if(provider.equals("google")){
                        mvo2.setSns_email_google(email);
                    }

                    memberService.insertUser(mvo2);
                }
                
                

                // 쿠키에 토큰 저장
                Cookie cookie = new Cookie("authToken", token);
                cookie.setHttpOnly(false); // js 에서 접근 불가
                cookie.setSecure(false); // https 에서만 가능 나중에 true
                cookie.setPath("/"); // 전체 도메인에서 사용가능
                response.addCookie(cookie); 

                response.sendRedirect("http://35.216.18.100:3000/");
                

                // 리다이렉트
            
                // String redirectUrl = String.format(
                //     "http://localhost:3000/login?provider=%s%token=%s&id=%s&name=%s&email=%s"
                //     , URLEncoder.encode(povider, StandardCharsets.UTF_8)
                //     , URLEncoder.encode(token, StandardCharsets.UTF_8)
                //     , URLEncoder.encode(id, StandardCharsets.UTF_8)
                //     , URLEncoder.encode(name, StandardCharsets.UTF_8)
                //     , URLEncoder.encode(email, StandardCharsets.UTF_8));

                // 단점은 보안
                // String redirectUrl = String.format(
                //     "http://localhost:3000/login?%token=%s"
                //     , URLEncoder.encode(token, StandardCharsets.UTF_8));


                // response.sendRedirect(redirectUrl);

            }
        } catch (Exception e) {
            log.info("error :" + e);
            response.sendRedirect("/login?error");
        }
    }
}
