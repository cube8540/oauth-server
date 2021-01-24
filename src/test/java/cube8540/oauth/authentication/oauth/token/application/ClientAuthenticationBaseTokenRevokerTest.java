package cube8540.oauth.authentication.oauth.token.application;

import cube8540.oauth.authentication.oauth.error.InvalidClientException;
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenNotFoundException;
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizedAccessToken;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.ACCESS_TOKEN_ID;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_ACCESS_TOKEN_ID;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_CLIENT_ID;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_DIFFERENT_CLIENT;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeAccessToken;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeAccessTokenRepository;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeAuthentication;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeEmptyAccessTokenRepository;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("클라이언트 인증 기준 토큰 삭제 서비스")
class ClientAuthenticationBaseTokenRevokerTest {

    @Test
    @DisplayName("저장소에 등록 되어 있지 않은 토큰 삭제")
    void revokeNotRegisteredAccessToken() {
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        ClientAuthenticationBaseTokenRevoker revoker = new ClientAuthenticationBaseTokenRevoker(repository);

        assertThrows(OAuth2AccessTokenNotFoundException.class, () -> revoker.revoke(RAW_ACCESS_TOKEN_ID));
    }

    @Test
    @DisplayName("요청자와 토큰의 주인이 다를시")
    void whenRequesterAndOwnerOfTokenAreDifferent() {
        OAuth2AuthorizedAccessToken accessToken = makeAccessToken();
        OAuth2AccessTokenRepository repository = makeAccessTokenRepository(ACCESS_TOKEN_ID, accessToken);
        Authentication authentication = makeAuthentication(RAW_DIFFERENT_CLIENT);
        ClientAuthenticationBaseTokenRevoker revoker = new ClientAuthenticationBaseTokenRevoker(repository);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String errorCode = assertThrows(InvalidClientException.class, () -> revoker.revoke(RAW_ACCESS_TOKEN_ID)).getError().getErrorCode();
        assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, errorCode);
    }

    @Test
    @DisplayName("액세스 토큰 삭제")
    void revokeAccessToken() {
        OAuth2AuthorizedAccessToken accessToken = makeAccessToken();
        OAuth2AccessTokenRepository repository = makeAccessTokenRepository(ACCESS_TOKEN_ID, accessToken);
        Authentication authentication = makeAuthentication(RAW_CLIENT_ID);
        ClientAuthenticationBaseTokenRevoker revoker = new ClientAuthenticationBaseTokenRevoker(repository);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        revoker.revoke(RAW_ACCESS_TOKEN_ID);
        verify(repository, times(1)).delete(accessToken);
    }
}
