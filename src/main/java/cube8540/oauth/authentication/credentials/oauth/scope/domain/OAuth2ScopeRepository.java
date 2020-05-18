package cube8540.oauth.authentication.credentials.oauth.scope.domain;

import cube8540.oauth.authentication.credentials.domain.AuthorityCode;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;

public interface OAuth2ScopeRepository extends JpaRepository<OAuth2Scope, AuthorityCode> {

    List<OAuth2Scope> findByIdIn(Collection<AuthorityCode> scopeIds);

    Long countById(AuthorityCode scopeId);

}
