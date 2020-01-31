package cube8540.oauth.authentication.credentials.oauth.client.domain;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OAuth2ClientRepository extends JpaRepository<OAuth2Client, OAuth2ClientId> {

    @EntityGraph(attributePaths = {"redirectURI", "grantType", "scope"})
    Optional<OAuth2Client> findByClientId(OAuth2ClientId oAuth2ClientId);
}
