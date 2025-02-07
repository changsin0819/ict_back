package com.ict.edu3.vo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class MembersVO {
    private String m_idx        // 회원 고유번호 (자동 증가)
    ,m_id                       // 사용자 ID (고유값, 필수)
    ,m_pw                       // 암호화된 비밀번호 (필수)
    ,m_name                     // 사용자 이름 (필수)
    ,m_age                      // 나이 (선택)
    ,m_reg                      // 가입일 (기본값: 현재 시간)
    ,sns_email_naver            // 네이버 이메일 (선택)
    ,sns_email_kakao            // 카카오 이메일 (선택)
    ,sns_email_google           // 구글 이메일 (선택)
    ,sns_provider;              // SNS 제공자 정보 (선택)
}
