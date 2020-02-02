package cube8540.oauth.authentication.credentials.oauth.code.domain;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AuthorizationCodeRepository extends JpaRepository<OAuth2AuthorizationCode, AuthorizationCode> {

    @Override
    @EntityGraph(attributePaths = {"approvedScopes"}, type = EntityGraph.EntityGraphType.LOAD)
    Optional<OAuth2AuthorizationCode> findById(AuthorizationCode code);
}
