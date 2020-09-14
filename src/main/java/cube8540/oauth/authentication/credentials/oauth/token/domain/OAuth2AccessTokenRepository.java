package cube8540.oauth.authentication.credentials.oauth.token.domain;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OAuth2AccessTokenRepository extends JpaRepository<OAuth2AuthorizedAccessToken, OAuth2TokenId> {

    @EntityGraph(attributePaths = {"scopes", "refreshToken", "additionalInformation"})
    Optional<OAuth2AuthorizedAccessToken> findByComposeUniqueKey(OAuth2ComposeUniqueKey composeUniqueKey);

}
