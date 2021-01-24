package cube8540.oauth.authentication.oauth.token.application;

import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.oauth.token.domain.TokenNotFoundException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.ACCESS_TOKEN_ID;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_ACCESS_TOKEN_ID;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_USERNAME;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeAccessToken;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeAccessTokenRepository;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeAuthentication;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeEmptyAccessTokenRepository;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("유저 인증 기준 토큰 삭제 서비스")
class DefaultTokenRevokerTest {

    @Test
    @DisplayName("저장소에 등록 되어 있지 않은 토큰 삭제")
    void revokeNotRegisteredTokenInRepository() {
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        DefaultTokenRevoker revoker = new DefaultTokenRevoker(repository);

        assertThrows(TokenNotFoundException.class, () -> revoker.revoke(RAW_ACCESS_TOKEN_ID));
    }

    @Test
    @DisplayName("액세스 토큰 삭제")
    void revokeAccessToken() {
        OAuth2AuthorizedAccessToken accessToken = makeAccessToken();
        OAuth2AccessTokenRepository repository = makeAccessTokenRepository(ACCESS_TOKEN_ID, accessToken);
        Authentication authentication = makeAuthentication(RAW_USERNAME);
        DefaultTokenRevoker revoker = new DefaultTokenRevoker(repository);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        revoker.revoke(RAW_ACCESS_TOKEN_ID);
        verify(repository, times(1)).delete(accessToken);
    }
}