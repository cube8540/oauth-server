package cube8540.oauth.authentication.credentials.oauth.token.infra;

import cube8540.oauth.authentication.credentials.AuthorityCode;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2ComposeUniqueKey;
import cube8540.oauth.authentication.credentials.oauth.token.domain.PrincipalUsername;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static cube8540.oauth.authentication.credentials.oauth.token.infra.WithScopeComposeUniqueKeyGenerator.CLIENT_KEY;
import static cube8540.oauth.authentication.credentials.oauth.token.infra.WithScopeComposeUniqueKeyGenerator.SCOPE_KEY;
import static cube8540.oauth.authentication.credentials.oauth.token.infra.WithScopeComposeUniqueKeyGenerator.USERNAME_KEY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 토큰 복합키 생성기 테스트")
class WithScopeComposeUniqueKeyGeneratorTest {

    private static final String RAW_USERNAME = "USERNAME";
    private static final PrincipalUsername PRINCIPAL_USERNAME= new PrincipalUsername(RAW_USERNAME);

    private static final String RAW_CLIENT_ID = "CLIENT-ID";
    private static final OAuth2ClientId CLIENT_ID = new OAuth2ClientId(RAW_CLIENT_ID);

    private static final String RAW_SCOPES_1 = "SCOPES_1";
    private static final String RAW_SCOPES_2 = "SCOPES_2";
    private static final Set<AuthorityCode> SCOPES = new LinkedHashSet<>(Arrays.asList(new AuthorityCode(RAW_SCOPES_2), new AuthorityCode(RAW_SCOPES_1)));

    @Test
    @DisplayName("복합키 생성")
    void generateComposeKey() {
        Map<String, String> values = new LinkedHashMap<>();
        List<String> scopeValues = SCOPES.stream().map(AuthorityCode::getValue).collect(Collectors.toList())
                .stream().sorted().collect(Collectors.toList());
        OAuth2AuthorizedAccessToken accessToken = mock(OAuth2AuthorizedAccessToken.class);

        when(accessToken.getUsername()).thenReturn(PRINCIPAL_USERNAME);
        when(accessToken.getClient()).thenReturn(CLIENT_ID);
        when(accessToken.getScopes()).thenReturn(SCOPES);
        values.put(USERNAME_KEY, RAW_USERNAME);
        values.put(CLIENT_KEY, RAW_CLIENT_ID);
        values.put(SCOPE_KEY, scopeValues.toString());

        WithScopeComposeUniqueKeyGenerator keyGenerator = new WithScopeComposeUniqueKeyGenerator();
        OAuth2ComposeUniqueKey result = keyGenerator.generateKey(accessToken);
        assertEquals(md5(values.toString()), result.getValue());
    }

    @Test
    @DisplayName("토큰의 인증 타입이 Client Credentials 일 때 복합키 생성")
    void generateComposeKeyWhenTokenGrantTypeIsClientCredentials() {
        Map<String, String> values = new LinkedHashMap<>();
        List<String> scopeValues = SCOPES.stream().map(AuthorityCode::getValue).collect(Collectors.toList())
                .stream().sorted().collect(Collectors.toList());
        OAuth2AuthorizedAccessToken accessToken = mock(OAuth2AuthorizedAccessToken.class);

        when(accessToken.getTokenGrantType()).thenReturn(AuthorizationGrantType.CLIENT_CREDENTIALS);
        when(accessToken.getClient()).thenReturn(CLIENT_ID);
        when(accessToken.getScopes()).thenReturn(SCOPES);
        values.put(CLIENT_KEY, RAW_CLIENT_ID);
        values.put(SCOPE_KEY, scopeValues.toString());

        WithScopeComposeUniqueKeyGenerator keyGenerator = new WithScopeComposeUniqueKeyGenerator();
        OAuth2ComposeUniqueKey result = keyGenerator.generateKey(accessToken);
        assertEquals(md5(values.toString()), result.getValue());
    }

    private static String md5(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            byte[] bytes = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return String.format("%032x", new BigInteger(1, bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}