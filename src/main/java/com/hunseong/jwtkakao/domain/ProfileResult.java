package com.hunseong.jwtkakao.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Map;

/**
 * @author : Hunseong-Park
 * @date : 2022-07-14
 */
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class ProfileResult {

    private Long id;
    private String connected_at;
    private Map<String, Object> kakao_account;
}
