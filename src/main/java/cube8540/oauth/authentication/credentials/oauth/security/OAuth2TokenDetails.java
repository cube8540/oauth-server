package cube8540.oauth.authentication.credentials.oauth.security;

import java.time.LocalDateTime;

public interface OAuth2TokenDetails {

    String getTokenValue();

    LocalDateTime getExpiration();

    boolean isExpired();

    long getExpiresIn();

}
