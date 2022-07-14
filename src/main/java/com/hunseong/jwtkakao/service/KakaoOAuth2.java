package com.hunseong.jwtkakao.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.hunseong.jwtkakao.domain.KakaoUserInfo;
import com.hunseong.jwtkakao.domain.ProfileResult;
import com.hunseong.jwtkakao.domain.TokenResult;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

/**
 * @author : Hunseong-Park
 * @date : 2022-07-14
 */
@Slf4j
@Component
public class KakaoOAuth2 {
    public KakaoUserInfo getUserInfo(String authorizedCode) throws JsonProcessingException {
        // 1. 인가코드 -> 액세스 토큰
        String accessToken = getAccessToken(authorizedCode);
        // 2. 액세스 토큰 -> 카카오 사용자 정보
        return getUserInfoByToken(accessToken);
    }

    private String getAccessToken(String authorizedCode) throws JsonProcessingException {
        // HttpHeader 오브젝트 생성
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");

        // HttpBody 오브젝트 생성
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("client_id", "");
        params.add("redirect_uri", "http://localhost:8080/api/oauth/kakao");
        params.add("code", authorizedCode);
        params.add("client_secret", "");

        // HttpHeader와 HttpBody를 하나의 오브젝트에 담기
        RestTemplate rt = new RestTemplate();
        HttpEntity<MultiValueMap<String, String>> kakaoTokenRequest =
                new HttpEntity<>(params, headers);

        // Http 요청하기 - Post방식으로 - 그리고 response 변수의 응답 받음.
        ResponseEntity<String> response = rt.exchange(
                "https://kauth.kakao.com/oauth/token",
                HttpMethod.POST,
                kakaoTokenRequest,
                String.class
        );

        // JSON -> 액세스 토큰 파싱
        String tokenJson = response.getBody();
        ObjectMapper objectMapper = new ObjectMapper();
        TokenResult tokenResult = objectMapper.readValue(tokenJson, TokenResult.class);

        return tokenResult.getAccess_token();
    }

    private KakaoUserInfo getUserInfoByToken(String accessToken) throws JsonProcessingException {
        // HttpHeader 오브젝트 생성
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + accessToken);
        headers.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");

        // HttpHeader와 HttpBody를 하나의 오브젝트에 담기
        RestTemplate rt = new RestTemplate();
        HttpEntity<MultiValueMap<String, String>> kakaoProfileRequest = new HttpEntity<>(headers);

        // Http 요청하기 - Post방식으로 - 그리고 response 변수의 응답 받음.
        ResponseEntity<String> response = rt.exchange(
                "https://kapi.kakao.com/v2/user/me",
                HttpMethod.POST,
                kakaoProfileRequest,
                String.class
        );

        ObjectMapper objectMapper = new ObjectMapper();
        ProfileResult profileResult = objectMapper.readValue(response.getBody(), ProfileResult.class);

        Long oid = profileResult.getId();
        String email = (String) profileResult.getKakao_account().get("email");

        return new KakaoUserInfo(oid, email);
    }
}