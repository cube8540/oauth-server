package cube8540.oauth.authentication.credentials.oauth.token.domain;

import cube8540.oauth.authentication.AuthenticationApplication;
import cube8540.oauth.authentication.credentials.oauth.AuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidClientException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.error.RedirectMismatchException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import java.time.Clock;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("OAuth2 인증 코드 도메인 테스트")
class OAuth2AuthorizationCodeTest {

    @Nested
    @DisplayName("새 인가 코드 생성")
    class CreateNewCode {
        private OAuth2AuthorizationCode code;

        @BeforeEach
        void setup() {
            Clock createdClock = Clock.fixed(OAuth2AuthorizationCodeTestHelper.NOW.toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
            OAuth2AuthorizationCode.setClock(createdClock);

            this.code = new OAuth2AuthorizationCode(OAuth2AuthorizationCodeTestHelper.configDefaultCodeGenerator());
        }

        @Test
        @DisplayName("생성기에서 반환된 코드를 저장해야 한다.")
        void shouldSaveCodeCreatedByGenerator() {
            Assertions.assertEquals(OAuth2AuthorizationCodeTestHelper.CODE, code.getCode());
        }

        @Test
        @DisplayName("만료일은 현재시간으로 부터 + 5분 이어야 한다.")
        void shouldExpirationDateTimeIsNowPlus5Minute() {
            Assertions.assertEquals(OAuth2AuthorizationCodeTestHelper.EXPIRATION_DATETIME, code.getExpirationDateTime());
        }
    }

    @Nested
    @DisplayName("요청 정보 저장")
    class SaveAuthorizationRequest {
        private OAuth2AuthorizationCode code;
        private AuthorizationRequest request;

        @BeforeEach
        void setup() {
            this.request = OAuth2AuthorizationCodeTestHelper.mockAuthorizationRequest().configDefaultSetup().build();
            this.code = new OAuth2AuthorizationCode(OAuth2AuthorizationCodeTestHelper.configDefaultCodeGenerator());
        }

        @Test
        @DisplayName("인자로 받은 클라이언트 아이디를 저장해야 한다.")
        void shouldSaveGivenClientId() {
            this.code.setAuthorizationRequest(request);

            Assertions.assertEquals(OAuth2AuthorizationCodeTestHelper.CLIENT_ID, this.code.getClientId());
        }

        @Test
        @DisplayName("인자로 받은 유저 이메일을 저장해야 한다.")
        void shouldSaveGivenUserEmail() {
            this.code.setAuthorizationRequest(request);

            Assertions.assertEquals(OAuth2AuthorizationCodeTestHelper.USERNAME, this.code.getUsername());
        }

        @Test
        @DisplayName("인자로 받은 STATE 속성을 저장해야 한다.")
        void shouldSaveGivenStateProperty() {
            this.code.setAuthorizationRequest(request);

            Assertions.assertEquals(OAuth2AuthorizationCodeTestHelper.STATE, this.code.getState());
        }

        @Test
        @DisplayName("인자로 받은 리다이렉트 주소를 저장해야 한다.")
        void shouldSaveGivenRedirectUri() {
            this.code.setAuthorizationRequest(request);

            Assertions.assertEquals(OAuth2AuthorizationCodeTestHelper.REDIRECT_URI, this.code.getRedirectURI());
        }

        @Test
        @DisplayName("인자로 받은 스코프를 저장해야 한다.")
        void shouldSaveGivenScopes() {
            this.code.setAuthorizationRequest(request);

            Assertions.assertEquals(OAuth2AuthorizationCodeTestHelper.SCOPES, this.code.getApprovedScopes());
        }
    }

    @Nested
    @DisplayName("인증 코드 유효성 검사")
    class AuthorizationCodeValidate {

        @Nested
        @DisplayName("현재시간이 코드의 만료일을 넘었을시")
        class WhenNowGraterThenExpirationDateTime {
            private AuthorizationRequest storedRequest;
            private OAuth2AuthorizationCode code;

            @BeforeEach
            void setup() {
                Clock createdClock = Clock.fixed(OAuth2AuthorizationCodeTestHelper.NOW.toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
                OAuth2AuthorizationCode.setClock(createdClock);

                this.storedRequest = OAuth2AuthorizationCodeTestHelper.mockAuthorizationRequest().configDefaultSetup().build();
                this.code = new OAuth2AuthorizationCode(OAuth2AuthorizationCodeTestHelper.configDefaultCodeGenerator());

                Clock clock = Clock.fixed(OAuth2AuthorizationCodeTestHelper.EXPIRATION_DATETIME.plusNanos(1).toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
                OAuth2AuthorizationCode.setClock(clock);
            }

            @Test
            @DisplayName("InvalidGrantException 이 발생해야 한다.")
            void shouldThrowsInvalidGrantException() {
                assertThrows(InvalidGrantException.class, () -> code.validateWithAuthorizationRequest(storedRequest));
            }

            @Test
            @DisplayName("에러 코드는 INVALID_GRANT 이어야 한다.")
            void shouldErrorCodeIsInvalidGrant() {
                OAuth2Error error = assertThrows(InvalidGrantException.class, () -> code.validateWithAuthorizationRequest(storedRequest))
                        .getError();
                assertEquals(OAuth2ErrorCodes.INVALID_GRANT, error.getErrorCode());
            }
        }

        @Nested
        @DisplayName("State 값이 일치 하지 않을시")
        class WhenStateMismatch {
            private AuthorizationRequest request;
            private OAuth2AuthorizationCode code;

            @BeforeEach
            void setup() {
                AuthorizationRequest storedRequest = OAuth2AuthorizationCodeTestHelper.mockAuthorizationRequest().configDefaultSetup().build();

                this.request = OAuth2AuthorizationCodeTestHelper.mockAuthorizationRequest().configDefaultSetup().configMismatchesState().build();
                this.code = new OAuth2AuthorizationCode(OAuth2AuthorizationCodeTestHelper.configDefaultCodeGenerator());
                this.code.setAuthorizationRequest(storedRequest);

                Clock clock = Clock.fixed(OAuth2AuthorizationCodeTestHelper.EXPIRATION_DATETIME.minusNanos(1).toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
                OAuth2AuthorizationCode.setClock(clock);
            }

            @Test
            @DisplayName("InvalidGrantException 이 발생해야 하며 에러 코드는 INVALID_GRANT 이어야 한다.")
            void shouldThrowsInvalidGrantExceptionAndErrorCodeIsInvalidGrant() {
                OAuth2Error error = assertThrows(InvalidGrantException.class, () -> code.validateWithAuthorizationRequest(request))
                        .getError();
                assertEquals(OAuth2ErrorCodes.INVALID_GRANT, error.getErrorCode());
            }
        }

        @Nested
        @DisplayName("리다이렉트 주소가 일치하지 않을시")
        class WhenRedirectUriMismatch {

            @Nested
            @DisplayName("리다이렉트 주소가 null 일시")
            class WhenRedirectUriIsNull {
                private AuthorizationRequest request;
                private OAuth2AuthorizationCode code;

                @BeforeEach
                void setup() {
                    AuthorizationRequest storedRequest = OAuth2AuthorizationCodeTestHelper.mockAuthorizationRequest().configDefaultSetup().configRedirectUriNull().build();

                    this.request = OAuth2AuthorizationCodeTestHelper.mockAuthorizationRequest().configDefaultSetup().configMismatchesRedirectUri().build();
                    this.code = new OAuth2AuthorizationCode(OAuth2AuthorizationCodeTestHelper.configDefaultCodeGenerator());
                    this.code.setAuthorizationRequest(storedRequest);

                    Clock clock = Clock.fixed(OAuth2AuthorizationCodeTestHelper.EXPIRATION_DATETIME.minusNanos(1).toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
                    OAuth2AuthorizationCode.setClock(clock);
                }

                @Test
                @DisplayName("RedirectMismatchException 이 발생해야 한다.")
                void shouldThrowsRedirectMismatchException() {
                    assertThrows(RedirectMismatchException.class, () -> code.validateWithAuthorizationRequest(request));
                }
            }

            @Nested
            @DisplayName("리다이렉트 주소가 null 이 아닐시")
            class WhenRedirectUriIsNotNull {
                private AuthorizationRequest request;
                private OAuth2AuthorizationCode code;

                @BeforeEach
                void setup() {
                    AuthorizationRequest storedRequest = OAuth2AuthorizationCodeTestHelper.mockAuthorizationRequest().configDefaultSetup().build();

                    this.request = OAuth2AuthorizationCodeTestHelper.mockAuthorizationRequest().configDefaultSetup().configMismatchesRedirectUri().build();
                    this.code = new OAuth2AuthorizationCode(OAuth2AuthorizationCodeTestHelper.configDefaultCodeGenerator());
                    this.code.setAuthorizationRequest(storedRequest);

                    Clock clock = Clock.fixed(OAuth2AuthorizationCodeTestHelper.EXPIRATION_DATETIME.minusNanos(1).toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
                    OAuth2AuthorizationCode.setClock(clock);
                }

                @Test
                @DisplayName("RedirectMismatchException 이 발생해야 한다.")
                void shouldThrowsRedirectMismatchException() {
                    assertThrows(RedirectMismatchException.class, () -> code.validateWithAuthorizationRequest(request));
                }
            }
        }

        @Nested
        @DisplayName("클라이언트 아이디가 다를시")
        class WhenClientIdMismatch {
            private AuthorizationRequest request;
            private OAuth2AuthorizationCode code;

            @BeforeEach
            void setup() {
                AuthorizationRequest storedRequest = OAuth2AuthorizationCodeTestHelper.mockAuthorizationRequest().configDefaultSetup().build();

                this.request = OAuth2AuthorizationCodeTestHelper.mockAuthorizationRequest().configDefaultSetup().configMismatchesClientId().build();
                this.code = new OAuth2AuthorizationCode(OAuth2AuthorizationCodeTestHelper.configDefaultCodeGenerator());
                this.code.setAuthorizationRequest(storedRequest);

                Clock clock = Clock.fixed(OAuth2AuthorizationCodeTestHelper.EXPIRATION_DATETIME.minusNanos(1).toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
                OAuth2AuthorizationCode.setClock(clock);
            }

            @Test
            @DisplayName("InvalidClientException 이 발생해야 하며 에러 코드는 INVALID_CLIENT 이어야 한다.")
            void shouldThrowsInvalidClientExceptionAndErrorCodeInvalidClient() {
                OAuth2Error error = assertThrows(InvalidClientException.class, () -> this.code.validateWithAuthorizationRequest(request))
                        .getError();
                assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, error.getErrorCode());
            }
        }

        @Nested
        @DisplayName("일치하지 않는 정보가 없을시")
        class WhenNotMismatchRequest {

            @Nested
            @DisplayName("리다이렉트 주소가 null 일시")
            class WhenRedirectUriIsNull {
                private AuthorizationRequest request;
                private OAuth2AuthorizationCode code;

                @BeforeEach
                void setup() {
                    Clock createdClock = Clock.fixed(OAuth2AuthorizationCodeTestHelper.NOW.toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
                    OAuth2AuthorizationCode.setClock(createdClock);
                    AuthorizationRequest storedRequest = OAuth2AuthorizationCodeTestHelper.mockAuthorizationRequest().configDefaultSetup().configRedirectUriNull().build();

                    this.request = OAuth2AuthorizationCodeTestHelper.mockAuthorizationRequest().configDefaultSetup().configRedirectUriNull().build();
                    this.code = new OAuth2AuthorizationCode(OAuth2AuthorizationCodeTestHelper.configDefaultCodeGenerator());
                    this.code.setAuthorizationRequest(storedRequest);

                    Clock clock = Clock.fixed(OAuth2AuthorizationCodeTestHelper.EXPIRATION_DATETIME.minusNanos(1).toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
                    OAuth2AuthorizationCode.setClock(clock);
                }

                @Test
                @DisplayName("어떠한 에러도 발생시키지 않아야 한다.")
                void shouldNotThrows() {
                    assertDoesNotThrow(() -> this.code.validateWithAuthorizationRequest(request));
                }
            }

            @Nested
            @DisplayName("리다이렉트 주소가 null 이 아닐시")
            class WhenRedirectUriIsNotNull {
                private AuthorizationRequest request;
                private OAuth2AuthorizationCode code;

                @BeforeEach
                void setup() {
                    Clock createdClock = Clock.fixed(OAuth2AuthorizationCodeTestHelper.NOW.toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
                    OAuth2AuthorizationCode.setClock(createdClock);
                    AuthorizationRequest storedRequest = OAuth2AuthorizationCodeTestHelper.mockAuthorizationRequest().configDefaultSetup().build();

                    this.request = OAuth2AuthorizationCodeTestHelper.mockAuthorizationRequest().configDefaultSetup().build();
                    this.code = new OAuth2AuthorizationCode(OAuth2AuthorizationCodeTestHelper.configDefaultCodeGenerator());
                    this.code.setAuthorizationRequest(storedRequest);

                    Clock clock = Clock.fixed(OAuth2AuthorizationCodeTestHelper.EXPIRATION_DATETIME.minusNanos(1).toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
                    OAuth2AuthorizationCode.setClock(clock);
                }

                @Test
                @DisplayName("어떠한 에러도 발생시키지 않아야 한다.")
                void shouldNotThrows() {
                    assertDoesNotThrow(() -> this.code.validateWithAuthorizationRequest(request));
                }
            }
        }
    }
}