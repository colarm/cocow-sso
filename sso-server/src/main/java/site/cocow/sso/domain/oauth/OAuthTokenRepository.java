package site.cocow.sso.domain.oauth;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * OAuth2 Token 仓库
 */
@Repository
public interface OAuthTokenRepository extends JpaRepository<OAuthToken, Long> {

    /**
     * 根据 access token 查找
     */
    Optional<OAuthToken> findByAccessToken(String accessToken);

    /**
     * 根据 refresh token 查找
     */
    Optional<OAuthToken> findByRefreshToken(String refreshToken);

    /**
     * 查找用户在特定客户端的所有 Token
     */
    List<OAuthToken> findByClientIdAndUserId(String clientId, Long userId);

    /**
     * 删除过期的 Access Token
     */
    void deleteByAccessTokenExpiresAtBefore(LocalDateTime dateTime);
}
