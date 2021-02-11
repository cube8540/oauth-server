package cube8540.oauth.authentication.oauth.token.domain;

import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import cube8540.oauth.authentication.oauth.error.InvalidClientException;
import cube8540.oauth.authentication.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.oauth.error.RedirectMismatchException;
import cube8540.oauth.authentication.oauth.security.AuthorizationRequest;
import cube8540.oauth.authentication.oauth.security.OAuth2TokenRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import java.time.Clock;

import static cube8540.oauth.authentication.AuthenticationApplication.DEFAULT_TIME_ZONE;
import static cube8540.oauth.authentication.AuthenticationApplication.DEFAULT_ZONE_OFFSET;
import static cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizationCodeTestHelper.CLIENT_ID;
import static cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizationCodeTestHelper.CODE_CHALLENGE;
import static cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizationCodeTestHelper.CODE_CHALLENGE_METHOD;
import static cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizationCodeTestHelper.DIFFERENT_CODE_VERIFIER;
import static cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizationCodeTestHelper.DIFFERENT_REDIRECT_URI;
import static cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizationCodeTestHelper.EXPIRATION_DATETIME;
import static cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizationCodeTestHelper.NOW;
import static cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizationCodeTestHelper.RAW_CLIENT_ID;
import static cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizationCodeTestHelper.RAW_CODE;
import static cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizationCodeTestHelper.RAW_DIFFERENT_CLIENT_ID;
import static cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizationCodeTestHelper.REDIRECT_URI;
import static cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizationCodeTestHelper.SCOPES;
import static cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizationCodeTestHelper.USERNAME;
import static cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizationCodeTestHelper.makeAuthorizationRequest;
import static cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizationCodeTestHelper.makeDefaultCodeGenerator;
import static cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizationCodeTestHelper.makeTokenRequest;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@DisplayName("OAuth2 인증 코드 도메인 테스트")
class OAuth2AuthorizationCodeTest {

    @Test
    @DisplayName("새 인카 코드 생성")
    void createNewAuthorizationCode() {
        Clock createdClock = Clock.fixed(NOW.toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
        OAuth2AuthorizationCode.setClock(createdClock);
        AuthorizationCodeGenerator codeGenerator = makeDefaultCodeGenerator();
        OAuth2AuthorizationCode code = new OAuth2AuthorizationCode(codeGenerator);


        assertEquals(RAW_CODE, code.getCode());
        assertEquals(EXPIRATION_DATETIME, code.getExpirationDateTime());
    }

    @Test
    @DisplayName("요청 정보 저장")
    void saveAuthorizationRequest() {
        AuthorizationRequest request = makeAuthorizationRequest();
        AuthorizationCodeGenerator generator = makeDefaultCodeGenerator();
        OAuth2AuthorizationCode code = new OAuth2AuthorizationCode(generator);

        code.setAuthorizationRequest(request);
        assertEquals(CLIENT_ID, code.getClientId());
        assertEquals(USERNAME, code.getUsername());
        assertEquals(REDIRECT_URI, code.getRedirectURI());
        assertEquals(SCOPES, code.getApprovedScopes());
        assertEquals(CODE_CHALLENGE, code.getCodeChallenge());
        assertEquals(CODE_CHALLENGE_METHOD, code.getCodeChallengeMethod());
    }

    @Test
    @DisplayName("code challenge가 null이 아니며 code challenge method가 null일시")
    void saveAuthorizationRequestWhenCodeChallengeNotNullAndCodeChallengeMethodIsNull() {
        AuthorizationRequest request = makeAuthorizationRequest();
        AuthorizationCodeGenerator generator = makeDefaultCodeGenerator();
        OAuth2AuthorizationCode code = new OAuth2AuthorizationCode(generator);

        when(request.getCodeChallengeMethod()).thenReturn(null);
        code.setAuthorizationRequest(request);

        assertEquals(CLIENT_ID, code.getClientId());
        assertEquals(USERNAME, code.getUsername());
        assertEquals(REDIRECT_URI, code.getRedirectURI());
        assertEquals(SCOPES, code.getApprovedScopes());
        assertEquals(CODE_CHALLENGE, code.getCodeChallenge());
        assertEquals(CodeChallengeMethod.PLAIN, code.getCodeChallengeMethod());
    }

    @Test
    @DisplayName("code challenge가 null 이며 code challenge method가 null이 아닐시")
    void saveAuthorizationRequestWhenCodeChallengeNullAndCodeChallengeMethodIsNotNull() {
        AuthorizationRequest request = makeAuthorizationRequest();
        AuthorizationCodeGenerator generator = makeDefaultCodeGenerator();
        OAuth2AuthorizationCode code = new OAuth2AuthorizationCode(generator);

        when(request.getCodeChallenge()).thenReturn(null);

        OAuth2Error error = assertThrows(InvalidGrantException.class, () -> code.setAuthorizationRequest(request)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_GRANT, error.getErrorCode());
    }

    @Test
    @DisplayName("code challenge와 code challenge method가 모두 null 일시")
    void saveAuthorizationRequestWhenCodeChallengeAndCodeChallengeMethodIsNull() {
        AuthorizationRequest request = makeAuthorizationRequest();
        AuthorizationCodeGenerator generator = makeDefaultCodeGenerator();
        OAuth2AuthorizationCode code = new OAuth2AuthorizationCode(generator);

        when(request.getCodeChallenge()).thenReturn(null);
        when(request.getCodeChallengeMethod()).thenReturn(null);
        code.setAuthorizationRequest(request);

        assertEquals(CLIENT_ID, code.getClientId());
        assertEquals(USERNAME, code.getUsername());
        assertEquals(REDIRECT_URI, code.getRedirectURI());
        assertEquals(SCOPES, code.getApprovedScopes());
        assertNull(code.getCodeChallenge());
        assertNull(code.getCodeChallengeMethod());
    }

    @Test
    @DisplayName("현재 시간이 코드의 만료일을 넘었을때 인증 코드 유효성 검사")
    void validationWhenThisTimeGraterThenExpirationDateTime() {
        Clock createdClock = Clock.fixed(NOW.toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
        OAuth2AuthorizationCode.setClock(createdClock);
        OAuth2TokenRequest storedRequest = makeTokenRequest();
        AuthorizationCodeGenerator generator = makeDefaultCodeGenerator();
        OAuth2AuthorizationCode code = new OAuth2AuthorizationCode(generator);

        Clock now = Clock.fixed(EXPIRATION_DATETIME.plusNanos(1).toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
        OAuth2AuthorizationCode.setClock(now);

        OAuth2Error error = assertThrows(InvalidGrantException.class, () -> code.validateWithAuthorizationRequest(storedRequest)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_GRANT, error.getErrorCode());
    }

    @Test
    @DisplayName("인증 코드의 리다이렉트 주소가 null 이며 인증 요청에 리다이렉트 주소가 null 이 아닐시")
    void whenRedirectUriOfCodeIsNullAndRedirectUriIsNotNullInRequest() {
        Clock createdClock = Clock.fixed(EXPIRATION_DATETIME.minusNanos(1).toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
        AuthorizationRequest storedRequest = makeAuthorizationRequest();
        OAuth2TokenRequest request = makeTokenRequest();
        AuthorizationCodeGenerator generator = makeDefaultCodeGenerator();
        OAuth2AuthorizationCode.setClock(createdClock);
        OAuth2AuthorizationCode code = new OAuth2AuthorizationCode(generator);

        when(storedRequest.getRedirectUri()).thenReturn(null);
        when(request.getRedirectUri()).thenReturn(DIFFERENT_REDIRECT_URI);
        code.setAuthorizationRequest(storedRequest);

        assertThrows(RedirectMismatchException.class, () -> code.validateWithAuthorizationRequest(request));
    }

    @Test
    @DisplayName("인증 코드의 리다이렉트 주소가 nul이 아니며 인증 요청에 리다이렉트 주소가 일치 하지 않을시")
    void whenRedirectUriOfCodeIsNotNullAndRedirectUriIsDifferentInRequest() {
        Clock createdClock = Clock.fixed(EXPIRATION_DATETIME.minusNanos(1).toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
        AuthorizationRequest storedRequest = makeAuthorizationRequest();
        OAuth2TokenRequest request = makeTokenRequest();
        AuthorizationCodeGenerator generator = makeDefaultCodeGenerator();
        OAuth2AuthorizationCode.setClock(createdClock);
        OAuth2AuthorizationCode code = new OAuth2AuthorizationCode(generator);

        when(storedRequest.getRedirectUri()).thenReturn(REDIRECT_URI);
        when(request.getRedirectUri()).thenReturn(DIFFERENT_REDIRECT_URI);
        code.setAuthorizationRequest(storedRequest);

        assertThrows(RedirectMismatchException.class, () -> code.validateWithAuthorizationRequest(request));
    }

    @Test
    @DisplayName("인증 코드의 클라이언트 아이디와 인증 요청의 클라이언트 아이디가 다를시")
    void whenClientIdOfCodeIsDifferentToClientIdOfRequest() {
        Clock createdClock = Clock.fixed(EXPIRATION_DATETIME.minusNanos(1).toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
        AuthorizationRequest storedRequest = makeAuthorizationRequest();
        OAuth2TokenRequest request = makeTokenRequest();
        AuthorizationCodeGenerator generator = makeDefaultCodeGenerator();
        OAuth2AuthorizationCode.setClock(createdClock);
        OAuth2AuthorizationCode code = new OAuth2AuthorizationCode(generator);

        when(storedRequest.getClientId()).thenReturn(RAW_CLIENT_ID);
        when(request.getClientId()).thenReturn(RAW_DIFFERENT_CLIENT_ID);
        code.setAuthorizationRequest(storedRequest);

        OAuth2Error error = assertThrows(InvalidClientException.class, () -> code.validateWithAuthorizationRequest(request)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, error.getErrorCode());
    }

    @Test
    @DisplayName("인증 코드의 code challenge가 null이 아니며 인증 요청의 code verifier가 null 일시")
    void whenCodeChallengeIsNotNullAndCodeVerifierIsNull() {
        Clock createdClock = Clock.fixed(EXPIRATION_DATETIME.minusNanos(1).toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
        AuthorizationRequest storedRequest = makeAuthorizationRequest();
        OAuth2TokenRequest request = makeTokenRequest();
        AuthorizationCodeGenerator generator = makeDefaultCodeGenerator();
        OAuth2AuthorizationCode.setClock(createdClock);
        OAuth2AuthorizationCode code = new OAuth2AuthorizationCode(generator);

        code.setAuthorizationRequest(storedRequest);
        when(request.getCodeVerifier()).thenReturn(null);

        OAuth2Error error = assertThrows(InvalidGrantException.class, () -> code.validateWithAuthorizationRequest(request)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_GRANT, error.getErrorCode());
    }

    @Test
    @DisplayName("인증 코드의 code challenge가 null이며 인증 요청의 code verifier가 null이 아닐시")
    void whenCodeChallengeIsNullAndCodeVerifierIsNotNull() {
        Clock createdClock = Clock.fixed(EXPIRATION_DATETIME.minusNanos(1).toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
        AuthorizationRequest storedRequest = makeAuthorizationRequest();
        OAuth2TokenRequest request = makeTokenRequest();
        AuthorizationCodeGenerator generator = makeDefaultCodeGenerator();
        OAuth2AuthorizationCode.setClock(createdClock);
        OAuth2AuthorizationCode code = new OAuth2AuthorizationCode(generator);

        when(storedRequest.getCodeChallenge()).thenReturn(null);
        when(storedRequest.getCodeChallengeMethod()).thenReturn(null);
        code.setAuthorizationRequest(storedRequest);

        OAuth2Error error = assertThrows(InvalidGrantException.class, () -> code.validateWithAuthorizationRequest(request)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_GRANT, error.getErrorCode());
    }

    @Test
    @DisplayName("인증코드의 code challenge와 인증 요청의 code verifier가 일치 하지 않을시")
    void whenCodeChallengeAndCodeVerifierIsMismatch() {
        Clock createdClock = Clock.fixed(EXPIRATION_DATETIME.minusNanos(1).toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
        AuthorizationRequest storedRequest = makeAuthorizationRequest();
        OAuth2TokenRequest request = makeTokenRequest();
        AuthorizationCodeGenerator generator = makeDefaultCodeGenerator();
        OAuth2AuthorizationCode.setClock(createdClock);
        OAuth2AuthorizationCode code = new OAuth2AuthorizationCode(generator);

        when(request.getCodeVerifier()).thenReturn(DIFFERENT_CODE_VERIFIER);
        code.setAuthorizationRequest(storedRequest);

        OAuth2Error error = assertThrows(InvalidGrantException.class, () -> code.validateWithAuthorizationRequest(request)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_GRANT, error.getErrorCode());
    }

    @Test
    @DisplayName("인증코드의 code challenge와 인증 요청의 code verifier가 모두 null 일시")
    void whenCodeChallengeAndCodeVerifierIsNull() {
        Clock createdClock = Clock.fixed(EXPIRATION_DATETIME.minusNanos(1).toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
        AuthorizationRequest storedRequest = makeAuthorizationRequest();
        OAuth2TokenRequest request = makeTokenRequest();
        AuthorizationCodeGenerator generator = makeDefaultCodeGenerator();
        OAuth2AuthorizationCode.setClock(createdClock);
        OAuth2AuthorizationCode code = new OAuth2AuthorizationCode(generator);

        when(request.getCodeVerifier()).thenReturn(null);
        when(storedRequest.getCodeChallenge()).thenReturn(null);
        when(storedRequest.getCodeChallengeMethod()).thenReturn(null);
        code.setAuthorizationRequest(storedRequest);

        assertDoesNotThrow(() -> code.validateWithAuthorizationRequest(request));
    }

    @Test
    @DisplayName("인증 코드와 요청 정보가 모두 일치할 때")
    void whenBothCodeAndRequestInformationMatches() {
        Clock createdClock = Clock.fixed(EXPIRATION_DATETIME.minusNanos(1).toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
        AuthorizationRequest storedRequest = makeAuthorizationRequest();
        OAuth2TokenRequest request = makeTokenRequest();
        AuthorizationCodeGenerator generator = makeDefaultCodeGenerator();
        OAuth2AuthorizationCode.setClock(createdClock);
        OAuth2AuthorizationCode code = new OAuth2AuthorizationCode(generator);

        code.setAuthorizationRequest(storedRequest);

        assertDoesNotThrow(() -> code.validateWithAuthorizationRequest(request));
    }
}