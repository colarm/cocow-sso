package site.cocow.sso.application.client.dto;

import java.util.Set;

import site.cocow.sso.domain.client.Client;

/**
 * 注册客户端请求
 */
public record RegisterClientRequest(
        String clientName,
        Client.ClientType clientType,
        Set<String> redirectUris,
        Set<String> scopes
        ) {

}
