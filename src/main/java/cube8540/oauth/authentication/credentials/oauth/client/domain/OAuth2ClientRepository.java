package cube8540.oauth.authentication.credentials.oauth.client.domain;

import cube8540.oauth.authentication.users.domain.UserEmail;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OAuth2ClientRepository extends JpaRepository<OAuth2Client, OAuth2ClientId> {

    Long countByClientId(OAuth2ClientId clientId);

    @EntityGraph(attributePaths = {"redirectUris", "grantTypes", "scopes"})
    Optional<OAuth2Client> findByClientId(OAuth2ClientId clientId);

    Page<OAuth2Client> findByOwner(UserEmail owner, Pageable pageable);
}
