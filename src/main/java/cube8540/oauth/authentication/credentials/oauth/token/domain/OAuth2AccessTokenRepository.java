package cube8540.oauth.authentication.credentials.oauth.token.domain;

import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuth2AccessTokenRepository extends JpaRepository<OAuth2AuthorizedAccessToken, OAuth2TokenId> {
}
