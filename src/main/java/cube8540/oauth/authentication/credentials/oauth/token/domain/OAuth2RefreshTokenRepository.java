package cube8540.oauth.authentication.credentials.oauth.token.domain;

import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuth2RefreshTokenRepository extends JpaRepository<OAuth2AuthorizedRefreshToken, OAuth2TokenId> {
}
