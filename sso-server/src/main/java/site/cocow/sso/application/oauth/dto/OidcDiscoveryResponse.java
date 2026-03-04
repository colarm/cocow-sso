package site.cocow.sso.application.oauth.dto;

import java.util.List;

/**
 * OIDC 发现端点响应
 */
public record OidcDiscoveryResponse(
        String issuer,
        String authorizationEndpoint,
        String tokenEndpoint,
        String userinfoEndpoint,
        String jwksUri,
        List<String> responseTypesSupported,
        List<String> subjectTypesSupported,
        List<String> idTokenSigningAlgValuesSupported,
        List<String> scopesSupported,
        List<String> grantTypesSupported,
        List<String> codeChallengeMethodsSupported
        ) {

}
