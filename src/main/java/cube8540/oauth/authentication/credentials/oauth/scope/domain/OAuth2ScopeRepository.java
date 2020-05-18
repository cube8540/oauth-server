package cube8540.oauth.authentication.credentials.oauth.scope.domain;

import cube8540.oauth.authentication.credentials.AuthorityCode;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuth2ScopeRepository extends JpaRepository<OAuth2Scope, AuthorityCode> {

    Long countByCode(AuthorityCode scopeId);

}
