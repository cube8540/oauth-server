package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.token.domain.read.Oauth2AccessTokenReadRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.read.model.AccessTokenDetailsWithClient;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;

import java.util.ArrayList;
import java.util.List;

import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_USERNAME;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeAccessTokenReadRepository;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeAuthentication;
import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("엑세스 토큰 리드 서비스 테스트")
class DefaultAccessTokenReadServiceTest {

    @Test
    @DisplayName("인증 받은 유저의 액세스 토큰 검색")
    void getAuthenticatedUserAccessToken() {
        List<AccessTokenDetailsWithClient> accessTokenDetailsWithClients = new ArrayList<>();
        Oauth2AccessTokenReadRepository repository = makeAccessTokenReadRepository(RAW_USERNAME, accessTokenDetailsWithClients);
        Authentication authentication = makeAuthentication(RAW_USERNAME);
        DefaultAccessTokenReadService service = new DefaultAccessTokenReadService(repository);

        List<AccessTokenDetailsWithClient> tokens = service.getAuthorizeAccessTokens(authentication);
        assertEquals(accessTokenDetailsWithClients, tokens);
    }

}