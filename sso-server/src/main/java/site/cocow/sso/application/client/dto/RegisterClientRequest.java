package site.cocow.sso.application.client.dto;

import java.util.Set;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import site.cocow.sso.domain.client.Client;

/**
 * 注册客户端请求
 */
@JsonIgnoreProperties(ignoreUnknown = false)
public record RegisterClientRequest(
        String clientName,
        Client.ClientType clientType,
        Set<String> redirectUris,
        Set<String> scopes
        ) {

}
