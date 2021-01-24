package cube8540.oauth.authentication.oauth.token.domain;

import cube8540.oauth.authentication.oauth.error.InvalidClientException;
import cube8540.oauth.authentication.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.oauth.error.RedirectMismatchException;
import cube8540.oauth.authentication.oauth.security.AuthorizationRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import java.time.Clock;

import static cube8540.oauth.authentication.AuthenticationApplication.DEFAULT_TIME_ZONE;
import static cube8540.oauth.authentication.AuthenticationApplication.DEFAULT_ZONE_OFFSET;
import static cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizationCodeTestHelper.CLIENT_ID;
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
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
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
    }

    @Test
    @DisplayName("현재 시간이 코드의 만료일을 넘었을때 인증 코드 유효성 검사")
    void validationWhenThisTimeGraterThenExpirationDateTime() {
        Clock createdClock = Clock.fixed(NOW.toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
        OAuth2AuthorizationCode.setClock(createdClock);
        AuthorizationRequest storedRequest = makeAuthorizationRequest();
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
        AuthorizationRequest request = makeAuthorizationRequest();
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
        AuthorizationRequest request = makeAuthorizationRequest();
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
        AuthorizationRequest request = makeAuthorizationRequest();
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
    @DisplayName("인증 코드와 요청 정보가 모두 일치할 때")
    void whenBothCodeAndRequestInformationMatches() {
        Clock createdClock = Clock.fixed(EXPIRATION_DATETIME.minusNanos(1).toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
        AuthorizationRequest storedRequest = makeAuthorizationRequest();
        AuthorizationRequest request = makeAuthorizationRequest();
        AuthorizationCodeGenerator generator = makeDefaultCodeGenerator();
        OAuth2AuthorizationCode.setClock(createdClock);
        OAuth2AuthorizationCode code = new OAuth2AuthorizationCode(generator);

        code.setAuthorizationRequest(storedRequest);

        assertDoesNotThrow(() -> code.validateWithAuthorizationRequest(request));
    }
}