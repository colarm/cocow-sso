package site.cocow.sso.application.oauth.dto;

/**
 * Token请求
 */
public record TokenRequest(
        String grantType,
        String code,
        String redirectUri,
        String clientId,
        String clientSecret,
        String codeVerifier,
        String refreshToken
        ) {

}
