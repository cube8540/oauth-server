package cube8540.oauth.authentication.rememberme.application;

import cube8540.oauth.authentication.rememberme.domain.RememberMePrincipal;
import cube8540.oauth.authentication.rememberme.domain.RememberMeToken;
import cube8540.oauth.authentication.rememberme.domain.RememberMeTokenGenerator;
import cube8540.oauth.authentication.rememberme.domain.RememberMeTokenRepository;
import cube8540.oauth.authentication.rememberme.domain.RememberMeTokenSeries;
import cube8540.oauth.authentication.rememberme.domain.RememberMeTokenValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.rememberme.CookieTheftException;
import org.springframework.security.web.authentication.rememberme.InvalidCookieException;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Base64;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("저장소를 통한 Remember Me 서비스 테스트")
public class TokenRepositoryBasedRememberMeServiceTest {

    private static final String REMEMBER_ME_KEY = "KEY";
    private static final String COOKIE_NAME = "remember-me";

    private static final String RAW_TOKEN_SERIES = "TOKEN-SERIES";
    private static final RememberMeTokenSeries TOKEN_SERIES = new RememberMeTokenSeries(RAW_TOKEN_SERIES);

    private static final String RAW_TOKEN_VALUE = "TOKEN_VALUE";
    private static final RememberMeTokenValue TOKEN_VALUE = new RememberMeTokenValue(RAW_TOKEN_VALUE);

    private static final String RAW_DIFFERENT_TOKEN_VALUE = "DIFFERENT-TOKEN_VALUE";
    private static final RememberMeTokenValue DIFFERENT_TOKEN_VALUE = new RememberMeTokenValue(RAW_DIFFERENT_TOKEN_VALUE);

    private static final String USERNAME = "username";
    private static final RememberMePrincipal TOKEN_PRINCIPAL = new RememberMePrincipal(USERNAME);

    private static final String SERVER_PATH = "http://localhost:8080";

    private UserDetailsService userDetailsService;
    private RememberMeTokenRepository repository;
    private RememberMeTokenGenerator generator;
    private TokenRepositoryBasedRememberMeService service;

    @BeforeEach
    void setup() {
        this.userDetailsService = mock(UserDetailsService.class);
        this.repository = mock(RememberMeTokenRepository.class);
        this.generator = mock(RememberMeTokenGenerator.class);

        when(generator.generateTokenSeries()).thenReturn(TOKEN_SERIES);
        when(generator.generateTokenValue()).thenReturn(TOKEN_VALUE);

        this.service = new TokenRepositoryBasedRememberMeService(REMEMBER_ME_KEY, generator, repository, userDetailsService);
    }

    @Test
    @DisplayName("로그인 성공")
    void onLoginSuccess() {
        ArgumentCaptor<Cookie> cookieArgumentCaptor = ArgumentCaptor.forClass(Cookie.class);
        ArgumentCaptor<RememberMeToken> tokenArgumentCaptor = ArgumentCaptor.forClass(RememberMeToken.class);
        Authentication authentication = mock(Authentication.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        when(authentication.getName()).thenReturn(USERNAME);
        when(request.getContextPath()).thenReturn(SERVER_PATH);

        this.service.onLoginSuccess(request, response, authentication);
        verify(repository, times(1)).save(tokenArgumentCaptor.capture());
        verify(response, times(1)).addCookie(cookieArgumentCaptor.capture());
        assertEquals(TOKEN_SERIES, tokenArgumentCaptor.getValue().getSeries());
        assertEquals(TOKEN_VALUE, tokenArgumentCaptor.getValue().getTokenValue());
        assertEquals(TOKEN_PRINCIPAL, tokenArgumentCaptor.getValue().getUsername());
        assertEquals(COOKIE_NAME, cookieArgumentCaptor.getValue().getName());
        assertEquals(makeTokenCookie(), cookieArgumentCaptor.getValue().getValue());
        assertEquals(RememberMeToken.tokenValiditySeconds, cookieArgumentCaptor.getValue().getMaxAge());
        assertEquals(SERVER_PATH, cookieArgumentCaptor.getValue().getPath());
    }

    @Test
    @DisplayName("요청 받은 쿠키 토큰의 갯수가 두개 미만 일 때")
    void processAutoLoginCookieWhenTokenIsLessThenTwo() {
        RememberMeToken token = mock(RememberMeToken.class);
        String[] cookieTokens = new String[] { RAW_TOKEN_SERIES };
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        when(repository.findById(TOKEN_SERIES)).thenReturn(Optional.of(token));

        assertThrows(InvalidCookieException.class, () -> this.service.processAutoLoginCookie(cookieTokens, request, response));
    }

    @Test
    @DisplayName("요청 받은 쿠키 토큰의 갯수가 두개를 초과 했을 떄")
    void processAutoLoginCookieWhenTokenIsGreaterThenTwo() {
        RememberMeToken token = mock(RememberMeToken.class);
        String[] cookieTokens = new String[] { RAW_TOKEN_SERIES, RAW_TOKEN_VALUE, USERNAME };
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        when(repository.findById(TOKEN_SERIES)).thenReturn(Optional.of(token));

        assertThrows(InvalidCookieException.class, () -> this.service.processAutoLoginCookie(cookieTokens, request, response));
    }

    @Test
    @DisplayName("요청 받은 토큰을 저장소에서 찾을 수 없을시")
    void processAutoLoginCookieWhenTokenIsNotFound() {
        String[] cookieTokens = new String[] { RAW_TOKEN_SERIES, RAW_TOKEN_VALUE };
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        when(repository.findById(TOKEN_SERIES)).thenReturn(Optional.empty());

        assertThrows(RememberMeAuthenticationException.class, () -> this.service.processAutoLoginCookie(cookieTokens, request, response));
    }

    @Test
    @DisplayName("검색된 토큰의 값과 쿠키의 토큰 값이 다를때")
    void processAutoLoginCookieWhenCookieTokenValueIsDifferentStoredTokenValue() {
        String[] cookieTokens = new String[] { RAW_TOKEN_SERIES, RAW_TOKEN_VALUE };
        RememberMeToken token = mock(RememberMeToken.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        when(repository.findById(TOKEN_SERIES)).thenReturn(Optional.of(token));
        when(token.getTokenValue()).thenReturn(DIFFERENT_TOKEN_VALUE);

        assertThrows(CookieTheftException.class, () ->  this.service.processAutoLoginCookie(cookieTokens, request, response));
        verify(repository, times(1)).delete(token);
    }

    @Test
    @DisplayName("토큰이 만료 되었을때")
    void processAutoLoginCookieWhenTokenExpired() {
        String[] cookieTokens = new String[] { RAW_TOKEN_SERIES, RAW_TOKEN_VALUE };
        RememberMeToken token = mock(RememberMeToken.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        when(repository.findById(TOKEN_SERIES)).thenReturn(Optional.of(token));
        when(token.getTokenValue()).thenReturn(TOKEN_VALUE);
        when(token.isExpired()).thenReturn(true);

        assertThrows(RememberMeAuthenticationException.class, () ->  this.service.processAutoLoginCookie(cookieTokens, request, response));
        verify(repository, times(1)).delete(token);
    }

    @Test
    @DisplayName("토큰으로 자동 로그인 성공")
    void processAutoLoginCookie() {
        String[] cookieTokens = new String[] { RAW_TOKEN_SERIES, RAW_TOKEN_VALUE };
        RememberMeToken token = mock(RememberMeToken.class);
        UserDetails userDetails = mock(UserDetails.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        when(repository.findById(TOKEN_SERIES)).thenReturn(Optional.of(token));
        when(token.getUsername()).thenReturn(TOKEN_PRINCIPAL);
        when(token.getTokenValue()).thenReturn(TOKEN_VALUE);
        when(token.isExpired()).thenReturn(false);
        when(userDetailsService.loadUserByUsername(USERNAME)).thenReturn(userDetails);

        UserDetails result = this.service.processAutoLoginCookie(cookieTokens, request, response);
        InOrder inOrder = inOrder(token, repository);
        assertEquals(result, userDetails);
        inOrder.verify(token, times(1)).updateLastUsedAt();
        inOrder.verify(repository, times(1)).save(token);
    }

    private String makeTokenCookie() {
        String cookie = RAW_TOKEN_SERIES + ":" + RAW_TOKEN_VALUE;

        StringBuilder value = new StringBuilder(new String(Base64.getEncoder().encode(cookie.getBytes())));
        while (value.charAt(value.length() - 1) == '=') {
            value.deleteCharAt(value.length() - 1);
        }
        return value.toString();
    }
}
