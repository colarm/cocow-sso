package site.cocow.sso.application.client.dto;

import java.util.Set;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * 更新客户端请求
 */
@JsonIgnoreProperties(ignoreUnknown = false)
public record UpdateClientRequest(
        String clientName,
        Set<String> redirectUris,
        Set<String> scopes
        ) {

}
