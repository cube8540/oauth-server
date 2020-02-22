package cube8540.oauth.authentication.credentials.oauth.token.domain;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.users.domain.UserEmail;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OAuth2AccessTokenRepository extends JpaRepository<OAuth2AuthorizedAccessToken, OAuth2TokenId> {

    @EntityGraph(attributePaths = {"scope", "refreshToken", "additionalInformation"})
    Optional<OAuth2AuthorizedAccessToken> findByClientAndEmail(OAuth2ClientId clientId, UserEmail email);

}
