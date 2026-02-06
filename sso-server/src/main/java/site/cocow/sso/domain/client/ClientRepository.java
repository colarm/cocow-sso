package site.cocow.sso.domain.client;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * OAuth2 客户端仓库
 */
@Repository
public interface ClientRepository extends JpaRepository<Client, Long> {

    /**
     * 根据 clientId 查找客户端
     */
    Optional<Client> findByClientId(String clientId);

    /**
     * 检查 clientId 是否存在
     */
    boolean existsByClientId(String clientId);
}
