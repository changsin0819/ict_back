package com.ict.edu3.service;

import java.util.Map;

import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;


@Slf4j
@Service
// SNS 에게 사용자 정보 요청을 처리하고, 사용자 정보를 수신한다. OAuth2User 생성하고 리턴한다.
public class CustomerOAuth2UserService extends DefaultOAuth2UserService{
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException{
        // 부모 클래스의 loadUser 메서드를 호출하여 기본 사용자 정보를 가져온다.
        OAuth2User oAuth2User = super.loadUser(userRequest);
        
        // 사용자 속성 가져오기
        Map<String, Object> attributes = oAuth2User.getAttributes();
        
        // 어떤 제공자인지 구분하기
        String provider = userRequest.getClientRegistration().getRegistrationId();
        if(provider.equals("kakao")){
            Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
            if(kakaoAccount==null){
                throw new OAuth2AuthenticationException("kakao error");
            }
            
            Map<String, Object> properties = (Map<String, Object>) attributes.get("properties");
            if(properties == null){
                throw new OAuth2AuthenticationException("kakao error");
            }
            // 카카오에서 관리하는 id값
            String id = String.valueOf(attributes.get("id"));
            String email = (String) kakaoAccount.get("email");
            String name = (String) properties.get("nickname");
            
            
            log.info("카카오 id {}",id);
            log.info("카카오 email {}",email);
            log.info("카카오 name {}",name);

            return new DefaultOAuth2User(oAuth2User.getAuthorities()
                                            ,Map.of(
                                                "email",email
                                                ,"id",id
                                                ,"name",name)
                                            ,"email");
        }else if(provider.equals("naver")){
            Map<String, Object> response = (Map<String, Object>) attributes.get("response");
            if(response==null){
                throw new OAuth2AuthenticationException("kakao error");
            }
            String name = (String) response.get("name");
            String email = (String) response.get("email");
            String id = (String) response.get("id");

            log.info("네이버 id {}",id);
            log.info("네이버 email {}",email);
            log.info("네이버 name {}",name);

            return new DefaultOAuth2User(oAuth2User.getAuthorities()
                                            ,Map.of(
                                                "email",email
                                                ,"id",id
                                                ,"name",name)
                                            ,"email");
        }else if(provider.equals("google")){
            String name = (String)attributes.get("name");
            String email = (String)attributes.get("email");
            String id = (String)attributes.get("sub");

            log.info("구글 id {}",id);
            log.info("구글 email {}",email);
            log.info("구글 name {}",name);

            return new DefaultOAuth2User(oAuth2User.getAuthorities()
                                            ,Map.of(
                                                "email",email
                                                ,"id",id
                                                ,"name",name)
                                            ,"email");
        }
        return oAuth2User;
    }
}
