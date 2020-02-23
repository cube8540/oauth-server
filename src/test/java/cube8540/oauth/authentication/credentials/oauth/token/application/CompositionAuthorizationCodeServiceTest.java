package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.AuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.token.domain.AuthorizationCode;
import cube8540.oauth.authentication.credentials.oauth.token.domain.AuthorizationCodeGenerator;
import cube8540.oauth.authentication.credentials.oauth.token.domain.AuthorizationCodeRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizationCode;
import cube8540.oauth.authentication.users.domain.UserEmail;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.net.URI;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("기본 인증 코드 서비스 테스트")
class CompositionAuthorizationCodeServiceTest {

    private static final String RAW_CODE = "CODE";
    private static final AuthorizationCode CODE = new AuthorizationCode(RAW_CODE);

    private static final String RAW_CLIENT_ID = "CLIENT";
    private static final OAuth2ClientId CLIENT_ID = new OAuth2ClientId(RAW_CLIENT_ID);

    private static final String RAW_EMAIL = "email@email.com";
    private static final UserEmail EMAIL = new UserEmail(RAW_EMAIL);

    private static final URI REDIRECT_URI = URI.create("http://localhost");

    private static final String STATE = "STATE";

    private static final Set<String> RAW_SCOPES = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3"));
    private static final Set<OAuth2ScopeId> SCOPES = RAW_SCOPES.stream().map(OAuth2ScopeId::new).collect(Collectors.toSet());

    private AuthorizationCodeRepository codeRepository;
    private CompositionAuthorizationCodeService codeService;

    @BeforeEach
    void setup() {
        this.codeRepository = mock(AuthorizationCodeRepository.class);
        this.codeService = new CompositionAuthorizationCodeService(codeRepository);
    }

    @Nested
    @DisplayName("코드 컨슘 테스트")
    class Consume {

        @Nested
        @DisplayName("저장소에 코드가 없을시")
        class WhenCodeNotFound {

            @BeforeEach
            void setup() {
                when(codeRepository.findById(CODE)).thenReturn(Optional.empty());
            }

            @Test
            @DisplayName("Optional.empty가 반환되어야 한다.")
            void shouldReturnsOptionalEmpty() {
                Optional<OAuth2AuthorizationCode> result = codeService.consume(CODE);

                assertEquals(Optional.empty(), result);
            }

            @Test
            @DisplayName("어떤 코드도 삭제하지 않는다.")
            void shouldNotRemovedAnything() {
                codeService.consume(CODE);

                verify(codeRepository, never()).delete(any());
            }
        }

        @Nested
        @DisplayName("저장소에서 코드를 찾았을시")
        class WhenCodeFound {

            private OAuth2AuthorizationCode authorizationCode;

            @BeforeEach
            void setup() {
                this.authorizationCode = mock(OAuth2AuthorizationCode.class);

                when(codeRepository.findById(CODE)).thenReturn(Optional.of(authorizationCode));
            }

            @Test
            @DisplayName("저장소에서 반환된 인증 코드를 포함한 Optional이 반환되어야 한다.")
            void shouldReturnsOptionalIncludingAuthorizationCode() {
                Optional<OAuth2AuthorizationCode> result = codeService.consume(CODE);

                assertEquals(Optional.of(authorizationCode), result);
            }

            @Test
            @DisplayName("저장소에서 반환된 인증 코드를 삭제해야 한다.")
            void shouldRemovedAuthorizationCode() {
                codeService.consume(CODE);

                verify(codeRepository, times(1)).delete(authorizationCode);
            }
        }
    }

    @Nested
    @DisplayName("새 인증 코드 생성")
    class GeneratorAuthorizationCode {
        private AuthorizationRequest authorizationRequest;

        @BeforeEach
        void setup() {
            AuthorizationCodeGenerator generator = mock(AuthorizationCodeGenerator.class);

            this.authorizationRequest = mock(AuthorizationRequest.class);

            when(generator.generate()).thenReturn(CODE);
            when(authorizationRequest.getRequestScopes()).thenReturn(RAW_SCOPES);
            when(authorizationRequest.getClientId()).thenReturn(RAW_CLIENT_ID);
            when(authorizationRequest.getRedirectUri()).thenReturn(REDIRECT_URI);
            when(authorizationRequest.getUsername()).thenReturn(RAW_EMAIL);
            when(authorizationRequest.getState()).thenReturn(STATE);

            codeService.setCodeGenerator(generator);
        }

        @Test
        @DisplayName("인증 코드 생성기에서 생성한 인증 코드를 저장소에 저장해야 한다.")
        void shouldSaveAuthorizationCodeCreatedByGenerator() {
            ArgumentCaptor<OAuth2AuthorizationCode> codeArgumentCaptor = ArgumentCaptor.forClass(OAuth2AuthorizationCode.class);

            codeService.generateNewAuthorizationCode(authorizationRequest);
            verify(codeRepository, times(1)).save(codeArgumentCaptor.capture());
            assertEquals(CODE, codeArgumentCaptor.getValue().getCode());
        }

        @Test
        @DisplayName("인증 코드의 클라이언트 아이디는 인증 요청 객체에 담긴 클라이언트 아이디어아 한다.")
        void shouldClientIdIsAuthorizationRequestClientId() {
            ArgumentCaptor<OAuth2AuthorizationCode> codeArgumentCaptor = ArgumentCaptor.forClass(OAuth2AuthorizationCode.class);

            codeService.generateNewAuthorizationCode(authorizationRequest);
            verify(codeRepository, times(1)).save(codeArgumentCaptor.capture());
            assertEquals(CLIENT_ID, codeArgumentCaptor.getValue().getClientId());
        }

        @Test
        @DisplayName("인증 코드의 스코프는 인증 요청 객체에 담긴 스코프어야 한다.")
        void shouldScopeIsAuthorizationRequestScope() {
            ArgumentCaptor<OAuth2AuthorizationCode> codeArgumentCaptor = ArgumentCaptor.forClass(OAuth2AuthorizationCode.class);

            codeService.generateNewAuthorizationCode(authorizationRequest);
            verify(codeRepository, times(1)).save(codeArgumentCaptor.capture());
            assertEquals(SCOPES, codeArgumentCaptor.getValue().getApprovedScopes());
        }

        @Test
        @DisplayName("인증 코드의 리다이렉트 URI는 인증 요청 객체에 담긴 URI어야 한다.")
        void shouldRedirectUriIsAuthorizationRequestRedirectURI() {
            ArgumentCaptor<OAuth2AuthorizationCode> codeArgumentCaptor = ArgumentCaptor.forClass(OAuth2AuthorizationCode.class);

            codeService.generateNewAuthorizationCode(authorizationRequest);
            verify(codeRepository, times(1)).save(codeArgumentCaptor.capture());
            assertEquals(REDIRECT_URI, codeArgumentCaptor.getValue().getRedirectURI());
        }

        @Test
        @DisplayName("인증 코드의 STATE는 인증 요청 객체에 담긴 STATE어야 한다.")
        void shouldStateIsAuthorizationRequestState() {
            ArgumentCaptor<OAuth2AuthorizationCode> codeArgumentCaptor = ArgumentCaptor.forClass(OAuth2AuthorizationCode.class);

            codeService.generateNewAuthorizationCode(authorizationRequest);
            verify(codeRepository, times(1)).save(codeArgumentCaptor.capture());
            assertEquals(STATE, codeArgumentCaptor.getValue().getState());
        }

        @Test
        @DisplayName("인증 코드의 유저 이메일은 인증 요청 객체에 담긴 유저 이메일이어야 한다.")
        void shouldEmailIsAuthorizationRequestEmail() {
            ArgumentCaptor<OAuth2AuthorizationCode> codeArgumentCaptor = ArgumentCaptor.forClass(OAuth2AuthorizationCode.class);

            codeService.generateNewAuthorizationCode(authorizationRequest);
            verify(codeRepository, times(1)).save(codeArgumentCaptor.capture());
            assertEquals(EMAIL, codeArgumentCaptor.getValue().getUsername());
        }
    }
}