package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.AuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.OAuth2RequestValidator;
import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.token.domain.AuthorizationCode;
import cube8540.oauth.authentication.credentials.oauth.token.domain.AuthorizationCodeGenerator;
import cube8540.oauth.authentication.credentials.oauth.token.domain.AuthorizationCodeRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizationCode;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedRefreshToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2RefreshTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenEnhancer;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenId;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenIdGenerator;
import cube8540.oauth.authentication.users.domain.UserEmail;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OAuth2TokenApplicationTestHelper {

    static final String TOKEN_TYPE = "Bearer";

    static final String RAW_ACCESS_TOKEN_ID = "ACCESS-TOKEN-ID";
    static final OAuth2TokenId ACCESS_TOKEN_ID = new OAuth2TokenId(RAW_ACCESS_TOKEN_ID);

    static final String RAW_NEW_ACCESS_TOKEN_ID = "NEW-ACCESS-TOKEN-ID";
    static final OAuth2TokenId NEW_ACCESS_TOKEN_ID = new OAuth2TokenId(RAW_NEW_ACCESS_TOKEN_ID);

    static final String RAW_REFRESH_TOKEN_ID = "REFRESH-TOKEN-ID";
    static final OAuth2TokenId REFRESH_TOKEN_ID = new OAuth2TokenId(RAW_REFRESH_TOKEN_ID);

    static final String RAW_NEW_REFRESH_TOKEN_ID = "NEW-REFRESH-TOKEN-ID";
    static final OAuth2TokenId NEW_REFRESH_TOKEN_ID = new OAuth2TokenId(RAW_NEW_REFRESH_TOKEN_ID);

    static final String RAW_USERNAME = "email@email.com";
    static final UserEmail USERNAME = new UserEmail(RAW_USERNAME);
    static final String RAW_AUTHENTICATION_USERNAME = "auth@email.com";
    static final UserEmail AUTHENTICATION_USERNAME = new UserEmail(RAW_AUTHENTICATION_USERNAME);
    static final String PASSWORD = "Password1234!@#$";

    static final String RAW_CLIENT_ID = "CLIENT-ID";
    static final OAuth2ClientId CLIENT_ID = new OAuth2ClientId(RAW_CLIENT_ID);

    static final Set<String> RAW_SCOPES = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3"));
    static final Set<OAuth2ScopeId> SCOPES = RAW_SCOPES.stream().map(OAuth2ScopeId::new).collect(Collectors.toSet());
    static final Set<String> RAW_CLIENT_SCOPES = new HashSet<>(Arrays.asList("CLIENT-SCOPE-1", "CLIENT-SCOPE-2", "CLIENT-SCOPE-3"));
    static final Set<OAuth2ScopeId> CLIENT_SCOPES = RAW_CLIENT_SCOPES.stream().map(OAuth2ScopeId::new).collect(Collectors.toSet());
    static final Set<String> RAW_APPROVED_SCOPES = new HashSet<>(Arrays.asList("APPROVED-SCOPE-1", "APPROVED-SCOPE-1", "APPROVED-SCOPE-1"));
    static final Set<OAuth2ScopeId> APPROVED_SCOPES = RAW_APPROVED_SCOPES.stream().map(OAuth2ScopeId::new).collect(Collectors.toSet());

    static final LocalDateTime EXPIRATION_DATETIME = LocalDateTime.of(2020, 1, 24, 21, 24, 0);
    static final LocalDateTime TOKEN_CREATED_DATETIME = LocalDateTime.of(2020, 1, 29, 22, 57);
    static final long EXPIRATION_IN = 600000;

    static final AuthorizationGrantType GRANT_TYPE = AuthorizationGrantType.AUTHORIZATION_CODE;

    static final Map<String, String> ADDITIONAL_INFO = new HashMap<>();

    static final URI REDIRECT_URI = URI.create("http://localhost:8080");

    static final String RAW_AUTHORIZATION_CODE = "AUTHORIZATION-CODE";
    static final AuthorizationCode AUTHORIZATION_CODE = new AuthorizationCode(RAW_AUTHORIZATION_CODE);

    static final Integer ACCESS_TOKEN_VALIDITY_SECONDS = 600;
    static final Integer REFRESH_TOKEN_VALIDITY_SECONDS = 6000;

    static final String STATE = "REQUESTED_STATE";

    static MockAccessToken mockAccessToken() {
        return new MockAccessToken();
    }

    static MockRefreshToken mockRefreshToken() {
        return new MockRefreshToken();
    }

    static MockAccessTokenRepository mockAccessTokenRepository() {
        return new MockAccessTokenRepository();
    }

    static MockRefreshTokenRepository mockRefreshTokenRepository() {
        return new MockRefreshTokenRepository();
    }

    static OAuth2TokenEnhancer mockTokenEnhancer() {
        return mock(OAuth2TokenEnhancer.class);
    }

    static MockClientDetails mockClientDetails() {
        return new MockClientDetails();
    }

    static MockTokenRequest mockTokenRequest() {
        return new MockTokenRequest();
    }

    static MockAuthorizationCode mockAuthorizationCode() {
        return new MockAuthorizationCode();
    }

    static MockAuthorizationConsumer mockAuthorizationConsumer() {
        return new MockAuthorizationConsumer();
    }

    static OAuth2TokenIdGenerator mockTokenIdGenerator(OAuth2TokenId tokenId) {
        OAuth2TokenIdGenerator generator = mock(OAuth2TokenIdGenerator.class);
        when(generator.generateTokenValue()).thenReturn(tokenId);
        return generator;
    }

    static AuthorizationCodeGenerator mockCodeGenerator(AuthorizationCode code) {
        AuthorizationCodeGenerator generator = mock(AuthorizationCodeGenerator.class);
        when(generator.generate()).thenReturn(code);
        return generator;
    }

    static MockTokenRequestValidator mockTokenRequestValidator() {
        return new MockTokenRequestValidator();
    }

    static MockAuthenticationManager mockAuthenticationManager() {
        return new MockAuthenticationManager();
    }

    static Authentication mockAuthentication() {
        Authentication authentication = mock(Authentication.class);
        when(authentication.getName()).thenReturn(RAW_AUTHENTICATION_USERNAME);
        return authentication;
    }

    static MockAuthorizationRequest mockAuthorizationRequest() {
        return new MockAuthorizationRequest();
    }

    static MockAuthorizationCodeRepository mockAuthorizationCodeRepository() {
        return new MockAuthorizationCodeRepository();
    }

    static User mockUser() {
        return mock(User.class);
    }

    static MockUserDetailsService mockUserDetailsService() {
        return new MockUserDetailsService();
    }

    static class MockAccessToken {
        private OAuth2AuthorizedAccessToken accessToken;

        private MockAccessToken() {
            this.accessToken = mock(OAuth2AuthorizedAccessToken.class);
        }

        MockAccessToken configDefault() {
            when(accessToken.getTokenId()).thenReturn(ACCESS_TOKEN_ID);
            when(accessToken.getClient()).thenReturn(CLIENT_ID);
            when(accessToken.getUsername()).thenReturn(USERNAME);
            when(accessToken.getScopes()).thenReturn(SCOPES);
            when(accessToken.getExpiration()).thenReturn(EXPIRATION_DATETIME);
            when(accessToken.getTokenGrantType()).thenReturn(GRANT_TYPE);
            when(accessToken.expiresIn()).thenReturn(EXPIRATION_IN);
            when(accessToken.getAdditionalInformation()).thenReturn(ADDITIONAL_INFO);
            configNotExpired();
            return this;
        }

        MockAccessToken configScopes(Set<OAuth2ScopeId> scopeIds) {
            when(accessToken.getScopes()).thenReturn(scopeIds);
            return this;
        }

        MockAccessToken configNotExpired() {
            when(accessToken.isExpired()).thenReturn(false);
            return this;
        }

        MockAccessToken configExpired() {
            when(accessToken.isExpired()).thenReturn(true);
            return this;
        }

        MockAccessToken configRefreshToken(OAuth2AuthorizedRefreshToken refreshToken) {
            when(accessToken.getRefreshToken()).thenReturn(refreshToken);
            return this;
        }

        MockAccessToken configEmptyRefreshToken() {
            when(accessToken.getRefreshToken()).thenReturn(null);
            return this;
        }

        MockAccessToken configMismatchesClientId() {
            when(accessToken.getClient()).thenReturn(new OAuth2ClientId("DIFFERENT CLIENT"));
            return this;
        }

        MockAccessToken configNullAdditionalInfo() {
            when(accessToken.getAdditionalInformation()).thenReturn(null);
            return this;
        }

        OAuth2AuthorizedAccessToken build() {
            return accessToken;
        }
    }

    static class MockRefreshToken {
        private OAuth2AuthorizedRefreshToken refreshToken;

        private MockRefreshToken() {
            this.refreshToken = mock(OAuth2AuthorizedRefreshToken.class);
        }

        MockRefreshToken configDefault() {
            when(refreshToken.getTokenId()).thenReturn(REFRESH_TOKEN_ID);
            when(refreshToken.getExpiration()).thenReturn(EXPIRATION_DATETIME);
            when(refreshToken.expiresIn()).thenReturn(EXPIRATION_IN);
            configNotExpired();
            return this;
        }

        MockRefreshToken configNotExpired() {
            when(refreshToken.isExpired()).thenReturn(false);
            return this;
        }

        MockRefreshToken configExpired() {
            when(refreshToken.isExpired()).thenReturn(true);
            return this;
        }

        MockRefreshToken configAccessToken(OAuth2AuthorizedAccessToken accessToken) {
            when(refreshToken.getAccessToken()).thenReturn(accessToken);
            return this;
        }

        OAuth2AuthorizedRefreshToken build() {
            return refreshToken;
        }
    }

    static class MockAccessTokenRepository {
        private OAuth2AccessTokenRepository repository;

        private MockAccessTokenRepository() {
            this.repository = mock(OAuth2AccessTokenRepository.class);
        }

        MockAccessTokenRepository registerAccessToken(OAuth2AuthorizedAccessToken accessToken) {
            when(repository.findById(ACCESS_TOKEN_ID)).thenReturn(Optional.of(accessToken));
            return this;
        }

        MockAccessTokenRepository emptyAccessToken() {
            when(repository.findById(ACCESS_TOKEN_ID)).thenReturn(Optional.empty());
            return this;
        }

        MockAccessTokenRepository registerAuthentication(OAuth2AuthorizedAccessToken accessToken) {
            when(repository.findByClientAndUsername(CLIENT_ID, USERNAME)).thenReturn(Optional.of(accessToken));
            return this;
        }

        MockAccessTokenRepository emptyAuthentication() {
            when(repository.findByClientAndUsername(CLIENT_ID, USERNAME)).thenReturn(Optional.empty());
            return this;
        }

        OAuth2AccessTokenRepository build() {
            return repository;
        }
    }

    static class MockRefreshTokenRepository {
        private OAuth2RefreshTokenRepository repository;

        private MockRefreshTokenRepository() {
            this.repository = mock(OAuth2RefreshTokenRepository.class);
        }

        MockRefreshTokenRepository emptyRefreshToken() {
            when(repository.findById(REFRESH_TOKEN_ID)).thenReturn(Optional.empty());
            return this;
        }

        MockRefreshTokenRepository registerRefreshToken(OAuth2AuthorizedRefreshToken refreshToken) {
            when(repository.findById(REFRESH_TOKEN_ID)).thenReturn(Optional.of(refreshToken));
            return this;
        }

        OAuth2RefreshTokenRepository build() {
            return repository;
        }
    }

    static class MockClientDetails {
        private OAuth2ClientDetails clientDetails;

        private MockClientDetails() {
            this.clientDetails = mock(OAuth2ClientDetails.class);
        }

        MockClientDetails configDefault() {
            when(clientDetails.getClientId()).thenReturn(RAW_CLIENT_ID);
            when(clientDetails.getScopes()).thenReturn(RAW_CLIENT_SCOPES);
            when(clientDetails.getAccessTokenValiditySeconds()).thenReturn(ACCESS_TOKEN_VALIDITY_SECONDS);
            when(clientDetails.getRefreshTokenValiditySeconds()).thenReturn(REFRESH_TOKEN_VALIDITY_SECONDS);
            return this;
        }

        OAuth2ClientDetails build() {
            return clientDetails;
        }
    }

    static class MockTokenRequest {
        private OAuth2TokenRequest tokenRequest;

        private MockTokenRequest() {
            this.tokenRequest = mock(OAuth2TokenRequest.class);
        }

        MockTokenRequest configDefaultClientId() {
            when(tokenRequest.getClientId()).thenReturn(RAW_CLIENT_ID);
            return this;
        }

        MockTokenRequest configDefaultCode() {
            when(tokenRequest.getCode()).thenReturn(RAW_AUTHORIZATION_CODE);
            return this;
        }

        MockTokenRequest configDefaultUsername() {
            when(tokenRequest.getUsername()).thenReturn(RAW_USERNAME);
            return this;
        }

        MockTokenRequest configNullUsername() {
            when(tokenRequest.getUsername()).thenReturn(null);
            return this;
        }

        MockTokenRequest configDefaultPassword() {
            when(tokenRequest.getPassword()).thenReturn(PASSWORD);
            return this;
        }

        MockTokenRequest configNullPassword() {
            when(tokenRequest.getPassword()).thenReturn(null);
            return this;
        }

        MockTokenRequest configDefaultScopes() {
            when(tokenRequest.getScopes()).thenReturn(RAW_SCOPES);
            return this;
        }

        MockTokenRequest configNullScopes() {
            when(tokenRequest.getScopes()).thenReturn(null);
            return this;
        }

        MockTokenRequest configEmptyScopes() {
            when(tokenRequest.getScopes()).thenReturn(Collections.emptySet());
            return this;
        }

        MockTokenRequest configDefaultState() {
            when(tokenRequest.getState()).thenReturn(STATE);
            return this;
        }

        MockTokenRequest configNullState() {
            when(tokenRequest.getState()).thenReturn(null);
            return this;
        }

        MockTokenRequest configDefaultRedirectUri() {
            when(tokenRequest.getRedirectUri()).thenReturn(REDIRECT_URI);
            return this;
        }

        MockTokenRequest configNullRedirectUri() {
            when(tokenRequest.getRedirectUri()).thenReturn(null);
            return this;
        }

        MockTokenRequest configDefaultRefreshToken() {
            when(tokenRequest.getRefreshToken()).thenReturn(RAW_REFRESH_TOKEN_ID);
            return this;
        }

        OAuth2TokenRequest build() {
            return tokenRequest;
        }
    }

    static class MockAuthorizationCode {
        private OAuth2AuthorizationCode code;

        private MockAuthorizationCode() {
            this.code = mock(OAuth2AuthorizationCode.class);
        }

        MockAuthorizationCode configDefault() {
            when(code.getCode()).thenReturn(AUTHORIZATION_CODE);
            when(code.getClientId()).thenReturn(CLIENT_ID);
            when(code.getUsername()).thenReturn(USERNAME);
            when(code.getApprovedScopes()).thenReturn(APPROVED_SCOPES);
            return this;
        }

        MockAuthorizationCode configDefaultApprovalScopesNull() {
            when(code.getApprovedScopes()).thenReturn(null);
            return this;
        }

        MockAuthorizationCode configDefaultApprovalScopesEmpty() {
            when(code.getApprovedScopes()).thenReturn(Collections.emptySet());
            return this;
        }

        OAuth2AuthorizationCode build() {
            return code;
        }
    }

    static final class MockAuthorizationConsumer {
        private OAuth2AuthorizationCodeConsumer consumer;

        private MockAuthorizationConsumer() {
            this.consumer = mock(OAuth2AuthorizationCodeConsumer.class);
        }

        MockAuthorizationConsumer consume(OAuth2AuthorizationCode code) {
            when(consumer.consume(AUTHORIZATION_CODE)).thenReturn(Optional.of(code));
            return this;
        }

        MockAuthorizationConsumer empty() {
            when(consumer.consume(AUTHORIZATION_CODE)).thenReturn(Optional.empty());
            return this;
        }

        OAuth2AuthorizationCodeConsumer build() {
            return consumer;
        }
    }

    static final class MockTokenRequestValidator {
        private OAuth2RequestValidator validator;

        private MockTokenRequestValidator() {
            this.validator = mock(OAuth2RequestValidator.class);
        }

        MockTokenRequestValidator configValidationTrue(OAuth2ClientDetails clientDetails, Set<String> scopes) {
            when(validator.validateScopes(clientDetails, scopes)).thenReturn(true);
            return this;
        }

        MockTokenRequestValidator configValidationFalse(OAuth2ClientDetails clientDetails, Set<String> scopes) {
            when(validator.validateScopes(clientDetails, scopes)).thenReturn(false);
            return this;
        }

        MockTokenRequestValidator configValidationTrue(Set<String> clientScopes, Set<String> scopes) {
            when(validator.validateScopes(clientScopes, scopes)).thenReturn(true);
            return this;
        }

        MockTokenRequestValidator configValidationFalse(Set<String> clientScopes, Set<String> scopes) {
            when(validator.validateScopes(clientScopes, scopes)).thenReturn(false);
            return this;
        }

        OAuth2RequestValidator build() {
            return validator;
        }
    }

    static final class MockAuthenticationManager {
        private AuthenticationManager manager;

        private MockAuthenticationManager() {
            this.manager = mock(AuthenticationManager.class);
        }

        MockAuthenticationManager authentication(Authentication token, Authentication authentication) {
            when(manager.authenticate(token)).thenReturn(authentication);
            return this;
        }

        MockAuthenticationManager badCredentials(Authentication token) {
            when(manager.authenticate(token)).thenThrow(new BadCredentialsException("bad credentials"));
            return this;
        }

        MockAuthenticationManager badAccountStatus(Authentication token) {
            when(manager.authenticate(token)).thenThrow(new TestAccountStatusException("account not allowed"));
            return this;
        }

        AuthenticationManager build() {
            return manager;
        }
    }

    static class MockAuthorizationRequest {
        private AuthorizationRequest request;

        private MockAuthorizationRequest() {
            this.request = mock(AuthorizationRequest.class);
        }

        MockAuthorizationRequest configDefault() {
            when(request.getRequestScopes()).thenReturn(RAW_SCOPES);
            when(request.getClientId()).thenReturn(RAW_CLIENT_ID);
            when(request.getRedirectUri()).thenReturn(REDIRECT_URI);
            when(request.getUsername()).thenReturn(RAW_USERNAME);
            when(request.getState()).thenReturn(STATE);
            return this;
        }

        AuthorizationRequest build() {
            return request;
        }
    }

    static class MockAuthorizationCodeRepository {
        private AuthorizationCodeRepository repository;

        private MockAuthorizationCodeRepository() {
            this.repository = mock(AuthorizationCodeRepository.class);
        }

        MockAuthorizationCodeRepository registerCode(OAuth2AuthorizationCode code) {
            when(repository.findById(AUTHORIZATION_CODE)).thenReturn(Optional.of(code));
            return this;
        }

        MockAuthorizationCodeRepository emptyCode() {
            when(repository.findById(AUTHORIZATION_CODE)).thenReturn(Optional.empty());
            return this;
        }

        AuthorizationCodeRepository build() {
            return repository;
        }
    }

    static class MockUserDetailsService {
        private UserDetailsService service;

        private MockUserDetailsService() {
            this.service = mock(UserDetailsService.class);
        }

        MockUserDetailsService registerUser(UserDetails userDetails) {
            when(service.loadUserByUsername(RAW_USERNAME)).thenReturn(userDetails);
            return this;
        }

        UserDetailsService build() {
            return service;
        }
    }

    private static final class TestAccountStatusException extends AccountStatusException {

        public TestAccountStatusException(String msg) {
            super(msg);
        }
    }
}
