package cube8540.oauth.authentication.credentials.oauth.token.infra;

import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenId;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenIdGenerator;

import java.util.UUID;

public class DefaultTokenIdGenerator implements OAuth2TokenIdGenerator {
    @Override
    public OAuth2TokenId generateTokenValue() {
        String tokenValue = UUID.randomUUID().toString().replace("-", "");
        return new OAuth2TokenId(tokenValue);
    }
}
