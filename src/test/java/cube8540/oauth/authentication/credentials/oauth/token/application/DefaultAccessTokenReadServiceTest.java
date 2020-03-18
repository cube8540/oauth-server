package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.token.domain.read.Oauth2AccessTokenReadRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.read.model.AccessTokenDetailsWithClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;

import java.util.ArrayList;
import java.util.List;

import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_USERNAME;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockAuthentication;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockOAuth2AccessTokenReadRepository;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("엑세스 토큰 리드 서비스 테스트")
class DefaultAccessTokenReadServiceTest {

    @Nested
    @DisplayName("인증 받은 유저의 엑세스 토큰 검색")
    class GetAuthenticationUserAccessTokens {
        private DefaultAccessTokenReadService service;
        private Oauth2AccessTokenReadRepository repository;
        private Authentication authentication;
        private List<AccessTokenDetailsWithClient> accessTokenDetailsWithClients;

        @BeforeEach
        void setup() {
            this.authentication = mockAuthentication(RAW_USERNAME);
            this.accessTokenDetailsWithClients = new ArrayList<>();
            this.repository = mockOAuth2AccessTokenReadRepository().readAccessTokenWithClientByUsername(RAW_USERNAME, accessTokenDetailsWithClients).build();
            this.service = new DefaultAccessTokenReadService(repository);
            this.accessTokenDetailsWithClients = new ArrayList<>();
        }

        @Test
        @DisplayName("매개 변수로 받은 인증정보의 주체명으로 검색을 해야 한다.")
        void shouldSearchByAuthenticationPrincipal() {
            service.getAuthorizeAccessTokens(authentication);

            verify(repository, times(1)).readAccessTokenWithClientByUsername(RAW_USERNAME);
        }

        @Test
        @DisplayName("리파지토리에서 검색된 리스트를 반환해야 한다.")
        void shouldReturnsRepositoryResult() {
            List<AccessTokenDetailsWithClient> tokens = service.getAuthorizeAccessTokens(authentication);

            assertEquals(accessTokenDetailsWithClients, tokens);
        }
    }

}