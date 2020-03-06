package cube8540.oauth.authentication.credentials.oauth.client.application;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientRepository;
import cube8540.oauth.authentication.credentials.oauth.client.error.ClientNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.mockOAuth2ClientRepository;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("OAuth2 클라이언트 디테일즈 서비스 테스트")
class DefaultOAuth2ClientDetailsServiceTest {

    @Nested
    @DisplayName("클라이언트 검색")
    class LoadClientDetails {

        @Nested
        @DisplayName("클라이언트를 찾을 수 없을시")
        class WhenNotFoundClient {
            private DefaultOAuth2ClientDetailsService service;

            @BeforeEach
            void setup() {
                OAuth2ClientRepository repository = mockOAuth2ClientRepository().emptyClient().build();
                this.service = new DefaultOAuth2ClientDetailsService(repository);
            }

            @Test
            @DisplayName("OAuth2ClientNotFoundException 이 발생해야 한다.")
            void shouldThrowsClientNotFoundException() {
                assertThrows(ClientNotFoundException.class, () -> service.loadClientDetailsByClientId(RAW_CLIENT_ID));
            }
        }
    }

}