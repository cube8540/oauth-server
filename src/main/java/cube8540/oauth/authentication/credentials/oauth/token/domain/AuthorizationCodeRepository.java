package cube8540.oauth.authentication.credentials.oauth.token.domain;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AuthorizationCodeRepository extends JpaRepository<OAuth2AuthorizationCode, String> {

    @Override
    @EntityGraph(attributePaths = {"approvedScopes"}, type = EntityGraph.EntityGraphType.LOAD)
    Optional<OAuth2AuthorizationCode> findById(String code);
}
