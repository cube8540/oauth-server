package cube8540.oauth.authentication.credentials.oauth.token.infra;

import cube8540.oauth.authentication.credentials.AuthorityCode;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2ComposeUniqueKey;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2ComposeUniqueKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class WithScopeComposeUniqueKeyGenerator implements OAuth2ComposeUniqueKeyGenerator {

    protected static final String USERNAME_KEY = "username";
    protected static final String CLIENT_KEY = "clientId";
    protected static final String SCOPE_KEY = "scopes";

    @Override
    public OAuth2ComposeUniqueKey generateKey(OAuth2AuthorizedAccessToken token) {
        Map<String, String> values = new LinkedHashMap<>();

        if (!AuthorizationGrantType.CLIENT_CREDENTIALS.equals(token.getTokenGrantType())) {
            values.put(USERNAME_KEY, token.getUsername().getValue());
        }
        values.put(CLIENT_KEY, token.getClient().getValue());
        values.put(SCOPE_KEY, token.getScopes().stream().map(AuthorityCode::getValue)
                .sorted().collect(Collectors.toList()).toString());
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            byte[] bytes = digest.digest(values.toString().getBytes(StandardCharsets.UTF_8));
            return new OAuth2ComposeUniqueKey(String.format("%032x", new BigInteger(1, bytes)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
