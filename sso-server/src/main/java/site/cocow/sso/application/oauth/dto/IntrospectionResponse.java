package site.cocow.sso.application.oauth.dto;

import java.time.LocalDateTime;

/**
 * Token自省响应
 */
public record IntrospectionResponse(
        boolean active,
        String clientId,
        String sub,
        String scope,
        String exp
        ) {

    public static IntrospectionResponse inactive() {
        return new IntrospectionResponse(false, "", "", "", "");
    }

    public static IntrospectionResponse active(String clientId, String userId, String scope, LocalDateTime expiresAt) {
        return new IntrospectionResponse(
                true,
                clientId != null ? clientId : "",
                userId != null ? userId : "",
                scope != null ? scope : "",
                expiresAt != null ? expiresAt.toString() : ""
        );
    }
}
