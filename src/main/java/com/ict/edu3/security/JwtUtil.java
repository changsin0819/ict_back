package com.ict.edu3.security;


import java.nio.charset.StandardCharsets;
import java.util.Date;

import javax.crypto.SecretKey;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;


@Component
public class JwtUtil {
    @Value("${jwt.secret}")
    private String secret;
    @Value("${jwt.access-token-validity}")
    private long accessTokenValidity;
    @Value("${jwt.refresh-token-validity}")
    private long refreshTokenValidity;


    private SecretKey getKey(){
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // Access Token 생성
    public String generateAccessToken(String userId) {
        return generateToken(userId, accessTokenValidity);
    }
    // Refresh Token 생성
    public String generateRefreshToken(String userId) {
        return generateToken(userId, refreshTokenValidity);
    }

    // 토큰생성
    public String generateToken(String userId, long validity) {
        return Jwts.builder()
                .setSubject(userId)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + accessTokenValidity))
                .signWith(getKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // 토큰이 만료 되었는지 확인
    public boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }

    // 토큰의 만료시간을 반환
    public Date extractExpiration(String token){
        return extractAllClaims(token).getExpiration();
    }

    // 받은 토큰으로 모든 정보 반환하기
    public Claims extractAllClaims(String token){
        return Jwts.parserBuilder()
                .setSigningKey(getKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // 토큰에서 ID만 추출
    public String validateAndExtractUserId(String token){
        return extractAllClaims(token).getSubject();
    }

    // 토큰과 사용자 정보가 일치하는지 검사
    public boolean validateToken(String token, UserDetails userDetails){
        try {
            // 토큰에서 id 추출
            final String userId = validateAndExtractUserId(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
