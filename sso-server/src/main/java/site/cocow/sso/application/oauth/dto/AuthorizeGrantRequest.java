package site.cocow.sso.application.oauth.dto;

/**
 * 前端同意授权后提交的请求体
 */
public record AuthorizeGrantRequest(
        String responseType,
        String clientId,
        String redirectUri,
        String scope,
        String state,
        String codeChallenge,
        String codeChallengeMethod
        ) {

}
