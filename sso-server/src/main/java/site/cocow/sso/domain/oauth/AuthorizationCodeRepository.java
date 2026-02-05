package site.cocow.sso.domain.oauth;

import java.time.LocalDateTime;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * OAuth2 授权码仓库
 */
@Repository
public interface AuthorizationCodeRepository extends JpaRepository<AuthorizationCode, Long> {

    /**
     * 根据授权码查找
     */
    Optional<AuthorizationCode> findByCode(String code);

    /**
     * 删除过期的授权码
     */
    void deleteByExpiresAtBefore(LocalDateTime dateTime);
}
