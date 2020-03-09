package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.AuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.token.domain.AuthorizationCodeRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizationCode;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("기본 인증 코드 서비스 테스트")
class CompositionAuthorizationCodeServiceTest {

    @Nested
    @DisplayName("코드 컨슘 테스트")
    class Consume {

        @Nested
        @DisplayName("저장소에 코드가 없을시")
        class WhenCodeNotFound {
            private AuthorizationCodeRepository repository;
            private CompositionAuthorizationCodeService service;

            @BeforeEach
            void setup() {
                this.repository = OAuth2TokenApplicationTestHelper.mockAuthorizationCodeRepository().emptyCode().build();
                this.service = new CompositionAuthorizationCodeService(repository);
            }

            @Test
            @DisplayName("Optional.empty 가 반환되어야 한다.")
            void shouldReturnsOptionalEmpty() {
                Optional<OAuth2AuthorizationCode> result = this.service.consume(OAuth2TokenApplicationTestHelper.AUTHORIZATION_CODE);

                assertEquals(Optional.empty(), result);
            }

            @Test
            @DisplayName("어떤 코드도 삭제하지 않는다.")
            void shouldNotRemovedAnything() {
                this.service.consume(OAuth2TokenApplicationTestHelper.AUTHORIZATION_CODE);

                verify(repository, never()).delete(any());
            }
        }

        @Nested
        @DisplayName("저장소에서 코드를 찾았을시")
        class WhenCodeFound {
            private OAuth2AuthorizationCode authorizationCode;
            private AuthorizationCodeRepository repository;
            private CompositionAuthorizationCodeService service;

            @BeforeEach
            void setup() {
                this.authorizationCode = OAuth2TokenApplicationTestHelper.mockAuthorizationCode().configDefault().build();
                this.repository = OAuth2TokenApplicationTestHelper.mockAuthorizationCodeRepository().registerCode(authorizationCode).build();
                this.service = new CompositionAuthorizationCodeService(repository);
            }

            @Test
            @DisplayName("저장소에서 반환된 인증 코드를 포함한 Optional 이 반환되어야 한다.")
            void shouldReturnsOptionalIncludingAuthorizationCode() {
                Optional<OAuth2AuthorizationCode> result = service.consume(OAuth2TokenApplicationTestHelper.AUTHORIZATION_CODE);

                assertEquals(Optional.of(authorizationCode), result);
            }

            @Test
            @DisplayName("저장소에서 반환된 인증 코드를 삭제해야 한다.")
            void shouldRemovedAuthorizationCode() {
                this.service.consume(OAuth2TokenApplicationTestHelper.AUTHORIZATION_CODE);

                verify(repository, times(1)).delete(authorizationCode);
            }
        }
    }

    @Nested
    @DisplayName("새 인증 코드 생성")
    class GeneratorAuthorizationCode {
        private AuthorizationCodeRepository repository;
        private AuthorizationRequest authorizationRequest;
        private CompositionAuthorizationCodeService service;

        @BeforeEach
        void setup() {
            this.authorizationRequest = OAuth2TokenApplicationTestHelper.mockAuthorizationRequest().configDefault().build();
            this.repository = OAuth2TokenApplicationTestHelper.mockAuthorizationCodeRepository().build();
            this.service = new CompositionAuthorizationCodeService(repository);
            this.service.setCodeGenerator(OAuth2TokenApplicationTestHelper.mockCodeGenerator(OAuth2TokenApplicationTestHelper.AUTHORIZATION_CODE));
        }

        @Test
        @DisplayName("인증 코드 생성기에서 생성한 인증 코드를 저장소에 저장해야 한다.")
        void shouldSaveAuthorizationCodeCreatedByGenerator() {
            ArgumentCaptor<OAuth2AuthorizationCode> codeArgumentCaptor = ArgumentCaptor.forClass(OAuth2AuthorizationCode.class);

            this.service.generateNewAuthorizationCode(authorizationRequest);
            verify(this.repository, times(1)).save(codeArgumentCaptor.capture());
            Assertions.assertEquals(OAuth2TokenApplicationTestHelper.AUTHORIZATION_CODE, codeArgumentCaptor.getValue().getCode());
        }

        @Test
        @DisplayName("인증 코드의 클라이언트 아이디는 인증 요청 객체에 담긴 클라이언트 아이디어아 한다.")
        void shouldClientIdIsAuthorizationRequestClientId() {
            ArgumentCaptor<OAuth2AuthorizationCode> codeArgumentCaptor = ArgumentCaptor.forClass(OAuth2AuthorizationCode.class);

            this.service.generateNewAuthorizationCode(authorizationRequest);
            verify(this.repository, times(1)).save(codeArgumentCaptor.capture());
            Assertions.assertEquals(OAuth2TokenApplicationTestHelper.CLIENT_ID, codeArgumentCaptor.getValue().getClientId());
        }

        @Test
        @DisplayName("인증 코드의 스코프는 인증 요청 객체에 담긴 스코프어야 한다.")
        void shouldScopeIsAuthorizationRequestScope() {
            ArgumentCaptor<OAuth2AuthorizationCode> codeArgumentCaptor = ArgumentCaptor.forClass(OAuth2AuthorizationCode.class);

            this.service.generateNewAuthorizationCode(authorizationRequest);
            verify(this.repository, times(1)).save(codeArgumentCaptor.capture());
            Assertions.assertEquals(OAuth2TokenApplicationTestHelper.SCOPES, codeArgumentCaptor.getValue().getApprovedScopes());
        }

        @Test
        @DisplayName("인증 코드의 리다이렉트 URI 는 인증 요청 객체에 담긴 URI 어야 한다.")
        void shouldRedirectUriIsAuthorizationRequestRedirectURI() {
            ArgumentCaptor<OAuth2AuthorizationCode> codeArgumentCaptor = ArgumentCaptor.forClass(OAuth2AuthorizationCode.class);

            this.service.generateNewAuthorizationCode(authorizationRequest);
            verify(this.repository, times(1)).save(codeArgumentCaptor.capture());
            Assertions.assertEquals(OAuth2TokenApplicationTestHelper.REDIRECT_URI, codeArgumentCaptor.getValue().getRedirectURI());
        }

        @Test
        @DisplayName("인증 코드의 STATE 는 인증 요청 객체에 담긴 STATE 어야 한다.")
        void shouldStateIsAuthorizationRequestState() {
            ArgumentCaptor<OAuth2AuthorizationCode> codeArgumentCaptor = ArgumentCaptor.forClass(OAuth2AuthorizationCode.class);

            this.service.generateNewAuthorizationCode(authorizationRequest);
            verify(this.repository, times(1)).save(codeArgumentCaptor.capture());
            Assertions.assertEquals(OAuth2TokenApplicationTestHelper.STATE, codeArgumentCaptor.getValue().getState());
        }

        @Test
        @DisplayName("인증 코드의 유저 이메일은 인증 요청 객체에 담긴 유저 이메일이어야 한다.")
        void shouldEmailIsAuthorizationRequestEmail() {
            ArgumentCaptor<OAuth2AuthorizationCode> codeArgumentCaptor = ArgumentCaptor.forClass(OAuth2AuthorizationCode.class);

            this.service.generateNewAuthorizationCode(authorizationRequest);
            verify(this.repository, times(1)).save(codeArgumentCaptor.capture());
            Assertions.assertEquals(OAuth2TokenApplicationTestHelper.USERNAME, codeArgumentCaptor.getValue().getUsername());
        }
    }
}
