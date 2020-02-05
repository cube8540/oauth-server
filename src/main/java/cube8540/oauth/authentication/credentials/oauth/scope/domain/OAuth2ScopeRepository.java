package cube8540.oauth.authentication.credentials.oauth.scope.domain;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;

public interface OAuth2ScopeRepository extends JpaRepository<OAuth2Scope, OAuth2ScopeId> {

    List<OAuth2Scope> findByIdIn(Collection<OAuth2ScopeId> scopeIds);

}
