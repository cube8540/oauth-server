package cube8540.oauth.authentication.credentials.oauth.code.domain;

import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthorizationCodeRepository extends JpaRepository<OAuth2AuthorizationCode, AuthorizationCode> {
}
