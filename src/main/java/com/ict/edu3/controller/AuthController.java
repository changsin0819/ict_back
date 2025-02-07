package com.ict.edu3.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.ict.edu3.security.JwtUtil;
import com.ict.edu3.service.MemberService;
import com.ict.edu3.service.MyUserDetailService;
import com.ict.edu3.vo.DataVO;
import com.ict.edu3.vo.MembersVO;

import jakarta.servlet.http.Cookie;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

@Slf4j
@RestController
@RequestMapping("/api/members")
@RequiredArgsConstructor
public class AuthController {
    // 필드 주입 (변경 가능)
    // @Autowired
    // private PasswordEncoder passwordEncoder;

    // 생성자 주입 (변경 불가능)
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final MyUserDetailService userDetailService;
    private final MemberService memberService;

    // 회원가입
    @PostMapping("/register")
    public DataVO register(@RequestBody MembersVO mvo) {
        DataVO dataVO = new DataVO();
        try {
            log.info("회원가입 실행");
            // 비밀번호 암호화
            mvo.setM_pw(passwordEncoder.encode(mvo.getM_pw()));
            // 데이터베이스에 전송
            userDetailService.registerUser(mvo);
            
            dataVO.setSuccess(true);
            dataVO.setMessage("회원가입 성공");
        } catch (Exception e) {
            log.info("회원가입 실패");
            dataVO.setSuccess(false);
            dataVO.setMessage("회원가입 실패");
        }
        return dataVO;
        
    }

    // 로그인
    @PostMapping("/login")
    public DataVO loginUser(@RequestBody MembersVO mvo) {
        DataVO dataVO = new DataVO();
        try {
            log.info("로그인 실행");
            // ID로 사용자 정보 확인
            UserDetails userDetails = userDetailService.loadUserByUsername(mvo.getM_id());
            // Password가 일치하는지 확인
            if(!passwordEncoder.matches(mvo.getM_pw(), userDetails.getPassword())){
                return new DataVO(false, null, "비밀번호가 일치하지 않습니다.");
            }

            // JWT 토큰 생성
            String accessToken = jwtUtil.generateAccessToken(mvo.getM_id());
            String refreshToken = jwtUtil.generateRefreshToken(mvo.getM_id());

            // refreshToken DB에 저장하기
            memberService.saveRefreshToken(userDetails.getUsername(), refreshToken, jwtUtil.extractExpiration(refreshToken));
            
            Map<String, String> tokens = new HashMap<>();
		        tokens.put("accessToken", accessToken);
		        tokens.put("refreshToken",refreshToken);
            
            dataVO.setData(tokens);
            dataVO.setSuccess(true);
            dataVO.setMessage("로그인 성공");
        } catch (Exception e) {
            log.info("로그인 실패");
            dataVO.setSuccess(false);
            dataVO.setMessage("로그인 실패");
        }
        return dataVO;
    }
    
    // 회원목록
    @GetMapping("/memberlist")
    public DataVO getMemberList(@RequestHeader(value = "Authorization", required = false) String token) {
        DataVO dataVO = new DataVO();
        try {
            // jwtrequestfilter 에서 검증 한 것을 한번 더 검증증
            if (token == null || !token.startsWith("Bearer ")){
                throw new Exception("토큰이 유효하지 않습니다");
            }
            // 토큰 검증
            String userId = jwtUtil.validateAndExtractUserId(token.substring(7));
            log.info("회원 목록 요청 - 사용자 ID : {} " , userId);

            List<MembersVO> list = memberService.getMemberList();
            
            dataVO.setSuccess(true);
            dataVO.setData(list);
        } catch (Exception e) {
            log.info("회원 목록 조회 실패 : {} ", e.getMessage());
            dataVO.setSuccess(false);
            dataVO.setMessage(e.getMessage());
        }


        return dataVO;
    }

    // 회원상세정보
    @GetMapping("/memberDetail")
	    public DataVO getMemberDetail(@RequestParam("id") String id
									 ,@RequestHeader(value = "Authorization", required = false) String token) {
			DataVO dataVO = new DataVO();
			try {
                log.info("id" + id);
                if (token == null || !token.startsWith("Bearer ")){
                    throw new Exception("토큰이 유효하지 않습니다");
                }

                
                // 토큰으로 유저 검증
				String userId = jwtUtil.validateAndExtractUserId(token.substring(7));  

				if(!userId.equals(id)){
					dataVO.setSuccess(false);
					throw new IllegalArgumentException("로그인한 ID가 아닙니다");
				}

				MembersVO member= memberService.getMemberDetail(id);
				if(member == null){
					throw new IllegalArgumentException("사용자가 없습니다");
				}
				dataVO.setSuccess(true);
				dataVO.setData(member);

			} catch (Exception e) {
				dataVO.setSuccess(false);
				dataVO.setMessage(e.getMessage());
			}
	        return dataVO;
	    }
    // 로그아웃
    @GetMapping("/logout")
		public DataVO getMethodName(@RequestHeader(value = "Authorization", required = false) String token) {
			DataVO dataVO = new DataVO();
			try {
                if (token == null || !token.startsWith("Bearer ")){
                    throw new Exception("토큰이 유효하지 않습니다");
                }
				// 토큰으로 유저 검증
                String userId = jwtUtil.validateAndExtractUserId(token.substring(7));
                memberService.deleteRefreshToken(userId);

                // 쿠키에 있는 토큰 삭제
                // Cookie cookie = new Cookie("authToken", null);
                // cookie.setMaxAge(0); // 즉시 삭제
                // cookie.setPath("/");    // 전체 도메인에서 사용가능능
                // response.addCookie(cookie);

				dataVO.setSuccess(true);
			} catch (Exception e) {
				dataVO.setSuccess(false);
				dataVO.setMessage(e.getMessage());
			}
			return dataVO;
		}
}
