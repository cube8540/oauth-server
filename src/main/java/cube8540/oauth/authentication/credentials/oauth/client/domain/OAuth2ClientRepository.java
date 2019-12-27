package cube8540.oauth.authentication.credentials.oauth.client.domain;

import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuth2ClientRepository extends JpaRepository<OAuth2Client, OAuth2ClientId> {
}
