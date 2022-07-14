package com.hunseong.jwtkakao.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * @author : Hunseong-Park
 * @date : 2022-07-14
 */
@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class TokenResult {

    private String token_type;
    private String access_token;
    private Long expires_in;
    private String refresh_token;
    private Long refresh_token_expires_in;
    private String scope;
}
