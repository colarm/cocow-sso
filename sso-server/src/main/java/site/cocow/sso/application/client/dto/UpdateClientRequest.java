package site.cocow.sso.application.client.dto;

import java.util.Set;

/**
 * 更新客户端请求
 */
public record UpdateClientRequest(
        String clientName,
        Set<String> redirectUris,
        Set<String> scopes
        ) {

}
