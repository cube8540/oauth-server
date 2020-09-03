package cube8540.oauth.authentication.credentials.oauth.client.application;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientRepository;
import cube8540.oauth.authentication.credentials.oauth.error.OAuth2ClientRegistrationException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.makeEmptyClientRepository;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("OAuth2 클라이언트 디테일즈 서비스 테스트")
class DefaultOAuth2ClientDetailsServiceTest {

    @Test
    @DisplayName("저장소에 등롣 되지 않은 클라이언트 검색")
    void searchNotRegisteredClientInRepository() {
        OAuth2ClientRepository repository = makeEmptyClientRepository();
        DefaultOAuth2ClientDetailsService service = new DefaultOAuth2ClientDetailsService(repository);

        assertThrows(OAuth2ClientRegistrationException.class, () -> service.loadClientDetailsByClientId(RAW_CLIENT_ID));
    }

}