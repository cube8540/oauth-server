package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.security.AuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.token.domain.AuthorizationCodeGenerator;
import cube8540.oauth.authentication.credentials.oauth.token.domain.AuthorizationCodeRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizationCode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.Optional;

import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.CLIENT_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_AUTHORIZATION_CODE;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.REDIRECT_URI;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.SCOPES;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.USERNAME;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeAuthorizationCode;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeAuthorizationCodeRepository;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeAuthorizationRequest;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeCodeGenerator;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeEmptyAuthorizationCodeRepository;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("기본 인가 코드 서비스 테스트")
class CompositionAuthorizationCodeServiceTest {

    @Test
    @DisplayName("저장소에 등록 되지 않은 인가 코드 검색")
    void consumeNotRegisteredAuthorizationCodeInRepository() {
        AuthorizationCodeRepository repository = makeEmptyAuthorizationCodeRepository();
        CompositionAuthorizationCodeService service = new CompositionAuthorizationCodeService(repository);

        Optional<OAuth2AuthorizationCode> result = service.consume(RAW_AUTHORIZATION_CODE);
        assertEquals(Optional.empty(), result);
        verify(repository, never()).delete(any());
    }

    @Test
    @DisplayName("인가 코드 검색")
    void consumeAuthorizationCode() {
        OAuth2AuthorizationCode code = makeAuthorizationCode();
        AuthorizationCodeRepository repository = makeAuthorizationCodeRepository(RAW_AUTHORIZATION_CODE, code);
        CompositionAuthorizationCodeService service = new CompositionAuthorizationCodeService(repository);

        Optional<OAuth2AuthorizationCode> result = service.consume(RAW_AUTHORIZATION_CODE);
        assertTrue(result.isPresent());
        assertEquals(code, result.get());
        verify(repository, times(1)).delete(code);
    }

    @Test
    @DisplayName("새 인가 코드 생성")
    void generateNewAuthorizationCode() {
        ArgumentCaptor<OAuth2AuthorizationCode> codeArgumentCaptor = ArgumentCaptor.forClass(OAuth2AuthorizationCode.class);
        AuthorizationCodeRepository repository = makeEmptyAuthorizationCodeRepository();
        AuthorizationRequest request = makeAuthorizationRequest();
        AuthorizationCodeGenerator generator = makeCodeGenerator(RAW_AUTHORIZATION_CODE);
        CompositionAuthorizationCodeService service = new CompositionAuthorizationCodeService(repository);

        service.setCodeGenerator(generator);

        service.generateNewAuthorizationCode(request);
        verify(repository, times(1)).save(codeArgumentCaptor.capture());
        assertEquals(RAW_AUTHORIZATION_CODE, codeArgumentCaptor.getValue().getCode());
        assertEquals(CLIENT_ID, codeArgumentCaptor.getValue().getClientId());
        assertEquals(SCOPES, codeArgumentCaptor.getValue().getApprovedScopes());
        assertEquals(REDIRECT_URI, codeArgumentCaptor.getValue().getRedirectURI());
        assertEquals(USERNAME, codeArgumentCaptor.getValue().getUsername());
    }
}
