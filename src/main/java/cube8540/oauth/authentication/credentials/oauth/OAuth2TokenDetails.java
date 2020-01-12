package cube8540.oauth.authentication.credentials.oauth;

import java.time.LocalDateTime;

public interface OAuth2TokenDetails {

    String tokenValue();

    LocalDateTime expiration();

    boolean isExpired();

    int expiresIn();

}
