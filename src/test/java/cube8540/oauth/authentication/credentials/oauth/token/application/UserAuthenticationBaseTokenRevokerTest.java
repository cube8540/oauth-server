package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.exception.TokenAccessDeniedException;
import cube8540.oauth.authentication.credentials.oauth.token.domain.exception.TokenNotFoundException;
import cube8540.oauth.authentication.error.message.ErrorCodes;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.ACCESS_TOKEN_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_ACCESS_TOKEN_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_DIFFERENT_USERNAME;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_USERNAME;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeAccessToken;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeAccessTokenRepository;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeAuthentication;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeEmptyAccessTokenRepository;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("유저 인증 기준 토큰 삭제 서비스")
class UserAuthenticationBaseTokenRevokerTest {

    @Test
    @DisplayName("저장소에 등록 되어 있지 않은 토큰 삭제")
    void revokeNotRegisteredTokenInRepository() {
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        UserAuthenticationBaseTokenRevoker revoker = new UserAuthenticationBaseTokenRevoker(repository);

        assertThrows(TokenNotFoundException.class, () -> revoker.revoke(RAW_ACCESS_TOKEN_ID));
    }

    @Test
    @DisplayName("요청자와 토큰의 주인이 다를시")
    void whenRequesterAndOwnerOfTokenAreDifferent() {
        OAuth2AuthorizedAccessToken accessToken = makeAccessToken();
        OAuth2AccessTokenRepository repository = makeAccessTokenRepository(ACCESS_TOKEN_ID, accessToken);
        Authentication authentication = makeAuthentication(RAW_DIFFERENT_USERNAME);
        UserAuthenticationBaseTokenRevoker revoker = new UserAuthenticationBaseTokenRevoker(repository);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String errorCode = assertThrows(TokenAccessDeniedException.class, () -> revoker.revoke(RAW_ACCESS_TOKEN_ID)).getCode();
        assertEquals(ErrorCodes.ACCESS_DENIED, errorCode);
    }

    @Test
    @DisplayName("액세스 토큰 삭제")
    void revokeAccessToken() {
        OAuth2AuthorizedAccessToken accessToken = makeAccessToken();
        OAuth2AccessTokenRepository repository = makeAccessTokenRepository(ACCESS_TOKEN_ID, accessToken);
        Authentication authentication = makeAuthentication(RAW_USERNAME);
        UserAuthenticationBaseTokenRevoker revoker = new UserAuthenticationBaseTokenRevoker(repository);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        revoker.revoke(RAW_ACCESS_TOKEN_ID);
        verify(repository, times(1)).delete(accessToken);
    }
}