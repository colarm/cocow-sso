package site.cocow.sso.application.oauth.dto;

import java.util.List;
import java.util.Map;

/**
 * JWKS (JSON Web Key Set) 响应
 */
public record JwksResponse(List<Map<String, Object>> keys) {

}
