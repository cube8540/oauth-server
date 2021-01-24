package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.error.InvalidClientException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.ACCESS_TOKEN_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_ACCESS_TOKEN_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_CLIENT_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_DIFFERENT_CLIENT;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_USERNAME;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeAccessToken;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeAccessTokenRepository;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeAuthentication;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeEmptyAccessTokenRepository;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeEmptyUserDetailsService;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeUserDetails;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeUserDetailsService;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("기본 토큰 검색 테스트")
class DefaultOAuth2AccessTokenDetailsServiceTest {

    @Test
    @DisplayName("저장소에 등록 되지 않은 액세스 토큰 검색")
    void getNotRegisteredAccessTokenInRepository() {
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        UserDetailsService userDetailsService = makeEmptyUserDetailsService();
        DefaultOAuth2AccessTokenDetailsService service = new DefaultOAuth2AccessTokenDetailsService(repository, userDetailsService);

        assertThrows(OAuth2AccessTokenNotFoundException.class, () -> service.readAccessToken(RAW_ACCESS_TOKEN_ID));
    }

    @Test
    @DisplayName("요청한 클라이언트와 액세스 토큰의 클라이언트가 일치 하지 않을때 액세스 토큰 검색")
    void getAccessTokenWhenRequestedClientAndClientOfAccessTokenDoNotMatch() {
        OAuth2AuthorizedAccessToken accessToken = makeAccessToken();
        OAuth2AccessTokenRepository repository = makeAccessTokenRepository(ACCESS_TOKEN_ID, accessToken);
        UserDetailsService userDetailsService = makeEmptyUserDetailsService();
        Authentication authentication = makeAuthentication(RAW_DIFFERENT_CLIENT);
        DefaultOAuth2AccessTokenDetailsService service = new DefaultOAuth2AccessTokenDetailsService(repository, userDetailsService);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String errorCode = assertThrows(InvalidClientException.class, () -> service.readAccessToken(RAW_ACCESS_TOKEN_ID)).getError().getErrorCode();
        assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, errorCode);
    }

    @Test
    @DisplayName("저장소에 등록 되지 않은 액세스 토큰 소유자 검색")
    void getNotRegisteredOwnerOfAccessTokenInRepository() {
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        UserDetailsService userDetailsService = makeEmptyUserDetailsService();
        DefaultOAuth2AccessTokenDetailsService service = new DefaultOAuth2AccessTokenDetailsService(repository, userDetailsService);

        assertThrows(OAuth2AccessTokenNotFoundException.class, () -> service.readAccessTokenUser(RAW_ACCESS_TOKEN_ID));
    }

    @Test
    @DisplayName("요청한 클라이언트와 액세스 토큰의 클라이언트가 일치 하지 않을때 액세스 토큰 소유자 검색")
    void getAccessTokenOwnerWhenRequestedClientAndClientOfAccessTokenDoNotMatch() {
        OAuth2AuthorizedAccessToken accessToken = makeAccessToken();
        OAuth2AccessTokenRepository repository = makeAccessTokenRepository(ACCESS_TOKEN_ID, accessToken);
        UserDetailsService userDetailsService = makeEmptyUserDetailsService();
        Authentication authentication = makeAuthentication(RAW_DIFFERENT_CLIENT);
        DefaultOAuth2AccessTokenDetailsService service = new DefaultOAuth2AccessTokenDetailsService(repository, userDetailsService);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String errorCode = assertThrows(InvalidClientException.class, () -> service.readAccessTokenUser(RAW_ACCESS_TOKEN_ID)).getError().getErrorCode();
        assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, errorCode);
    }

    @Test
    @DisplayName("검색된 토큰의 유저 아이디가 null 일시")
    void getAccessTokenWhenFindTokenUsernameIsNull() {
        User userDetails = makeUserDetails();
        UserDetailsService userDetailsService = makeUserDetailsService(RAW_USERNAME, userDetails);
        OAuth2AuthorizedAccessToken accessToken = makeAccessToken();
        OAuth2AccessTokenRepository repository = makeAccessTokenRepository(ACCESS_TOKEN_ID, accessToken);
        Authentication authentication = makeAuthentication(RAW_CLIENT_ID);
        DefaultOAuth2AccessTokenDetailsService service = new DefaultOAuth2AccessTokenDetailsService(repository, userDetailsService);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        when(accessToken.getUsername()).thenReturn(null);

        String errorCode = assertThrows(InvalidRequestException.class, () -> service.readAccessTokenUser(RAW_ACCESS_TOKEN_ID)).getError().getErrorCode();
        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, errorCode);
    }

    @Test
    @DisplayName("검색된 유저의 민감한 데이터 삭제")
    void eraseSearchedUserSensitiveData() {
        User userDetails = makeUserDetails();
        UserDetailsService userDetailsService = makeUserDetailsService(RAW_USERNAME, userDetails);
        OAuth2AuthorizedAccessToken accessToken = makeAccessToken();
        OAuth2AccessTokenRepository repository = makeAccessTokenRepository(ACCESS_TOKEN_ID, accessToken);
        Authentication authentication = makeAuthentication(RAW_CLIENT_ID);
        DefaultOAuth2AccessTokenDetailsService service = new DefaultOAuth2AccessTokenDetailsService(repository, userDetailsService);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        service.readAccessTokenUser(RAW_ACCESS_TOKEN_ID);
        verify(userDetails, times(1)).eraseCredentials();
    }
}
