package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.AuthorityCode;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.security.AuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2RequestValidator;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.token.domain.AccessTokenDetailsWithClient;
import cube8540.oauth.authentication.credentials.oauth.token.domain.AuthorizationCodeGenerator;
import cube8540.oauth.authentication.credentials.oauth.token.domain.AuthorizationCodeRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenReadRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizationCode;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedRefreshToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2ComposeUniqueKey;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2ComposeUniqueKeyGenerator;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2RefreshTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenEnhancer;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenId;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenIdGenerator;
import cube8540.oauth.authentication.credentials.oauth.token.domain.PrincipalUsername;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OAuth2TokenApplicationTestHelper {

    static final String TOKEN_TYPE = "Bearer";

    static final String RAW_ACCESS_TOKEN_ID = "ACCESS-TOKEN-ID";
    static final OAuth2TokenId ACCESS_TOKEN_ID = new OAuth2TokenId(RAW_ACCESS_TOKEN_ID);

    static final String RAW_EXISTS_ACCESS_TOKEN_ID = "EXISTS-ACCESS-TOKEN-ID";
    static final OAuth2TokenId EXISTS_ACCESS_TOKEN_ID = new OAuth2TokenId(RAW_EXISTS_ACCESS_TOKEN_ID);

    static final String RAW_NEW_ACCESS_TOKEN_ID = "NEW-ACCESS-TOKEN-ID";
    static final OAuth2TokenId NEW_ACCESS_TOKEN_ID = new OAuth2TokenId(RAW_NEW_ACCESS_TOKEN_ID);

    static final String RAW_REFRESH_TOKEN_ID = "REFRESH-TOKEN-ID";
    static final OAuth2TokenId REFRESH_TOKEN_ID = new OAuth2TokenId(RAW_REFRESH_TOKEN_ID);

    static final String RAW_NEW_REFRESH_TOKEN_ID = "NEW-REFRESH-TOKEN-ID";
    static final OAuth2TokenId NEW_REFRESH_TOKEN_ID = new OAuth2TokenId(RAW_NEW_REFRESH_TOKEN_ID);

    static final String RAW_USERNAME = "username";
    static final PrincipalUsername USERNAME = new PrincipalUsername(RAW_USERNAME);
    static final String RAW_DIFFERENT_USERNAME = "different";
    static final String RAW_AUTHENTICATION_USERNAME = "auth";
    static final PrincipalUsername AUTHENTICATION_USERNAME = new PrincipalUsername(RAW_AUTHENTICATION_USERNAME);
    static final String PASSWORD = "Password1234!@#$";

    static final String RAW_CLIENT_ID = "CLIENT-ID";
    static final OAuth2ClientId CLIENT_ID = new OAuth2ClientId(RAW_CLIENT_ID);
    static final String RAW_DIFFERENT_CLIENT = "DIFFERENT-CLIENT";
    static final OAuth2ClientId DIFFERENT_CLIENT = new OAuth2ClientId(RAW_DIFFERENT_CLIENT);

    static final Set<String> RAW_SCOPES = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3"));
    static final Set<AuthorityCode> SCOPES = RAW_SCOPES.stream().map(AuthorityCode::new).collect(Collectors.toSet());
    static final Set<String> RAW_CLIENT_SCOPES = new HashSet<>(Arrays.asList("CLIENT-SCOPE-1", "CLIENT-SCOPE-2", "CLIENT-SCOPE-3"));
    static final Set<AuthorityCode> CLIENT_SCOPES = RAW_CLIENT_SCOPES.stream().map(AuthorityCode::new).collect(Collectors.toSet());
    static final Set<String> RAW_APPROVED_SCOPES = new HashSet<>(Arrays.asList("APPROVED-SCOPE-1", "APPROVED-SCOPE-1", "APPROVED-SCOPE-1"));
    static final Set<AuthorityCode> APPROVED_SCOPES = RAW_APPROVED_SCOPES.stream().map(AuthorityCode::new).collect(Collectors.toSet());

    static final LocalDateTime EXPIRATION_DATETIME = LocalDateTime.of(2020, 1, 24, 21, 24, 0);
    static final LocalDateTime TOKEN_CREATED_DATETIME = LocalDateTime.of(2020, 1, 29, 22, 57);
    static final long EXPIRATION_IN = 600000;

    static final AuthorizationGrantType GRANT_TYPE = AuthorizationGrantType.AUTHORIZATION_CODE;

    static final Map<String, String> ADDITIONAL_INFO = new HashMap<>();

    static final URI REDIRECT_URI = URI.create("http://localhost:8080");

    static final String RAW_AUTHORIZATION_CODE = "AUTHORIZATION-CODE";

    static final Integer ACCESS_TOKEN_VALIDITY_SECONDS = 600;
    static final Integer REFRESH_TOKEN_VALIDITY_SECONDS = 6000;

    static final String STATE = "REQUESTED_STATE";

    static final String RAW_COMPOSE_UNIQUE_KEY = "COMPOSE_UNIQUE_KEY";
    static final OAuth2ComposeUniqueKey COMPOSE_UNIQUE_KEY = new OAuth2ComposeUniqueKey(RAW_COMPOSE_UNIQUE_KEY);

    static OAuth2ComposeUniqueKeyGenerator makeComposeUniqueKeyGenerator() {
        OAuth2ComposeUniqueKeyGenerator generator = mock(OAuth2ComposeUniqueKeyGenerator.class);

        when(generator.generateKey(any())).thenReturn(COMPOSE_UNIQUE_KEY);

        return generator;
    }

    static OAuth2AccessTokenRepository makeEmptyAccessTokenRepository() {
        return mock(OAuth2AccessTokenRepository.class);
    }

    static OAuth2AccessTokenRepository makeAccessTokenRepository(OAuth2TokenId tokenId, OAuth2AuthorizedAccessToken accessToken) {
        OAuth2AccessTokenRepository repository = mock(OAuth2AccessTokenRepository.class);

        when(repository.findById(tokenId)).thenReturn(Optional.of(accessToken));

        return repository;
    }

    static OAuth2AccessTokenRepository makeAccessTokenRepository(OAuth2ComposeUniqueKey composeUniqueKey, OAuth2AuthorizedAccessToken accessToken) {
        OAuth2AccessTokenRepository repository = mock(OAuth2AccessTokenRepository.class);

        when(repository.findByComposeUniqueKey(composeUniqueKey)).thenReturn(Optional.of(accessToken));

        return repository;
    }

    static OAuth2RefreshTokenRepository makeEmptyRefreshTokenRepository() {
        return mock(OAuth2RefreshTokenRepository.class);
    }

    static OAuth2RefreshTokenRepository makeRefreshTokenRepository(OAuth2TokenId tokenId, OAuth2AuthorizedRefreshToken refreshToken) {
        OAuth2RefreshTokenRepository repository = mock(OAuth2RefreshTokenRepository.class);

        when(repository.findById(tokenId)).thenReturn(Optional.of(refreshToken));

        return repository;
    }

    static OAuth2AccessTokenReadRepository makeAccessTokenReadRepository(String username, List<AccessTokenDetailsWithClient> tokenWithClients) {
        OAuth2AccessTokenReadRepository repository = mock(OAuth2AccessTokenReadRepository.class);

        when(repository.readAccessTokenWithClientByUsername(username)).thenReturn(tokenWithClients);

        return repository;
    }

    static AuthorizationCodeRepository makeEmptyAuthorizationCodeRepository() {
        AuthorizationCodeRepository repository = mock(AuthorizationCodeRepository.class);

        doAnswer(returnsFirstArg()).when(repository).save(isA(OAuth2AuthorizationCode.class));

        return repository;
    }

    static AuthorizationCodeRepository makeAuthorizationCodeRepository(String code, OAuth2AuthorizationCode authorizationCode) {
        AuthorizationCodeRepository repository = makeEmptyAuthorizationCodeRepository();

        when(repository.findById(code)).thenReturn(Optional.of(authorizationCode));

        return repository;
    }

    static OAuth2AuthorizationCodeConsumer makeEmptyCodeConsumer() {
        return mock(OAuth2AuthorizationCodeConsumer.class);
    }

    static OAuth2AuthorizationCode makeAuthorizationCode() {
        OAuth2AuthorizationCode code = mock(OAuth2AuthorizationCode.class);

        when(code.getCode()).thenReturn(RAW_AUTHORIZATION_CODE);
        when(code.getClientId()).thenReturn(CLIENT_ID);
        when(code.getUsername()).thenReturn(USERNAME);
        when(code.getApprovedScopes()).thenReturn(APPROVED_SCOPES);

        return code;
    }

    static OAuth2AuthorizationCodeConsumer makeCodeConsumer(String codeId, OAuth2AuthorizationCode code) {
        OAuth2AuthorizationCodeConsumer consumer = mock(OAuth2AuthorizationCodeConsumer.class);

        when(consumer.consume(codeId)).thenReturn(Optional.of(code));

        return consumer;
    }

    static OAuth2ClientDetails makeClientDetails() {
        OAuth2ClientDetails clientDetails = mock(OAuth2ClientDetails.class);

        when(clientDetails.getClientId()).thenReturn(RAW_CLIENT_ID);
        when(clientDetails.getScopes()).thenReturn(RAW_CLIENT_SCOPES);
        when(clientDetails.getAccessTokenValiditySeconds()).thenReturn(ACCESS_TOKEN_VALIDITY_SECONDS);
        when(clientDetails.getRefreshTokenValiditySeconds()).thenReturn(REFRESH_TOKEN_VALIDITY_SECONDS);

        return clientDetails;
    }

    static OAuth2TokenRequest makeTokenRequest() {
        OAuth2TokenRequest request = mock(OAuth2TokenRequest.class);

        when(request.getCode()).thenReturn(RAW_AUTHORIZATION_CODE);
        when(request.getUsername()).thenReturn(RAW_USERNAME);
        when(request.getPassword()).thenReturn(PASSWORD);
        when(request.getScopes()).thenReturn(RAW_SCOPES);
        when(request.getRedirectUri()).thenReturn(REDIRECT_URI);
        when(request.getRefreshToken()).thenReturn(RAW_REFRESH_TOKEN_ID);
        when(request.getState()).thenReturn(STATE);
        when(request.getGrantType()).thenReturn(GRANT_TYPE);

        return request;
    }

    static OAuth2RequestValidator makeErrorValidator(OAuth2ClientDetails clientDetails, Set<String> approvalScopes) {
        OAuth2RequestValidator validator = mock(OAuth2RequestValidator.class);

        when(validator.validateScopes(clientDetails, approvalScopes)).thenReturn(false);

        return validator;
    }

    static OAuth2RequestValidator makeErrorValidator(Set<String> scopes, Set<String> approvalScopes) {
        OAuth2RequestValidator validator = mock(OAuth2RequestValidator.class);

        when(validator.validateScopes(scopes, approvalScopes)).thenReturn(false);

        return validator;
    }

    static OAuth2RequestValidator makePassValidator(OAuth2ClientDetails clientDetails, Set<String> approvalScopes) {
        OAuth2RequestValidator validator = mock(OAuth2RequestValidator.class);

        when(validator.validateScopes(clientDetails, approvalScopes)).thenReturn(true);

        return validator;
    }

    static OAuth2RequestValidator makePassValidator(Set<String> scopes, Set<String> approvalScopes) {
        OAuth2RequestValidator validator = mock(OAuth2RequestValidator.class);

        when(validator.validateScopes(scopes, approvalScopes)).thenReturn(true);

        return validator;
    }

    static OAuth2AuthorizedAccessToken makeAccessToken() {
        OAuth2AuthorizedAccessToken token = mock(OAuth2AuthorizedAccessToken.class);

        when(token.getTokenId()).thenReturn(ACCESS_TOKEN_ID);
        when(token.getClient()).thenReturn(CLIENT_ID);
        when(token.getUsername()).thenReturn(USERNAME);
        when(token.getScopes()).thenReturn(SCOPES);
        when(token.getExpiration()).thenReturn(EXPIRATION_DATETIME);
        when(token.getTokenGrantType()).thenReturn(GRANT_TYPE);
        when(token.expiresIn()).thenReturn(EXPIRATION_IN);
        when(token.getAdditionalInformation()).thenReturn(ADDITIONAL_INFO);
        when(token.isExpired()).thenReturn(false);
        when(token.getComposeUniqueKey()).thenReturn(COMPOSE_UNIQUE_KEY);

        return token;
    }

    static OAuth2AuthorizedAccessToken makeExistsAccessToken() {
        OAuth2AuthorizedAccessToken token = mock(OAuth2AuthorizedAccessToken.class);

        when(token.getTokenId()).thenReturn(EXISTS_ACCESS_TOKEN_ID);
        when(token.getClient()).thenReturn(CLIENT_ID);
        when(token.getUsername()).thenReturn(USERNAME);
        when(token.getScopes()).thenReturn(SCOPES);
        when(token.getExpiration()).thenReturn(EXPIRATION_DATETIME);
        when(token.getTokenGrantType()).thenReturn(GRANT_TYPE);
        when(token.expiresIn()).thenReturn(EXPIRATION_IN);
        when(token.getAdditionalInformation()).thenReturn(ADDITIONAL_INFO);
        when(token.isExpired()).thenReturn(false);
        when(token.getComposeUniqueKey()).thenReturn(COMPOSE_UNIQUE_KEY);

        return token;
    }

    static OAuth2AuthorizedAccessToken makeExistsAccessToken(AuthorizationGrantType grantType) {
        OAuth2AuthorizedAccessToken token = makeExistsAccessToken();

        when(token.getTokenGrantType()).thenReturn(grantType);

        return token;
    }

    static OAuth2AuthorizedAccessToken makeExpiredExistsAccessToken() {
        OAuth2AuthorizedAccessToken token = makeExistsAccessToken();

        when(token.isExpired()).thenReturn(true);

        return token;
    }

    static OAuth2AuthorizedAccessToken makeAccessToken(Set<AuthorityCode> scopes) {
        OAuth2AuthorizedAccessToken accessToken = makeAccessToken();

        when(accessToken.getScopes()).thenReturn(scopes);

        return accessToken;
    }

    static OAuth2AuthorizedRefreshToken makeRefreshToken(OAuth2AuthorizedAccessToken accessToken) {
        OAuth2AuthorizedRefreshToken refreshToken = mock(OAuth2AuthorizedRefreshToken.class);

        when(refreshToken.getTokenId()).thenReturn(REFRESH_TOKEN_ID);
        when(refreshToken.getExpiration()).thenReturn(EXPIRATION_DATETIME);
        when(refreshToken.expiresIn()).thenReturn(EXPIRATION_IN);
        when(refreshToken.isExpired()).thenReturn(false);
        when(refreshToken.getAccessToken()).thenReturn(accessToken);

        return refreshToken;
    }

    static OAuth2TokenEnhancer makeTokenEnhancer() {
        return mock(OAuth2TokenEnhancer.class);
    }

    static OAuth2TokenIdGenerator makeTokenIdGenerator(OAuth2TokenId tokenId) {
        OAuth2TokenIdGenerator generator = mock(OAuth2TokenIdGenerator.class);
        when(generator.generateTokenValue()).thenReturn(tokenId);
        return generator;
    }

    static AuthorizationCodeGenerator makeCodeGenerator(String code) {
        AuthorizationCodeGenerator generator = mock(AuthorizationCodeGenerator.class);
        when(generator.generate()).thenReturn(code);
        return generator;
    }

    static AuthenticationManager makeAuthenticationManager(UsernamePasswordAuthenticationToken usernameAndPassword, Authentication authentication) {
        AuthenticationManager manager = mock(AuthenticationManager.class);

        when(manager.authenticate(usernameAndPassword)).thenReturn(authentication);

        return manager;
    }

    static AuthenticationManager makeBadCredentials(UsernamePasswordAuthenticationToken usernameAndPassword) {
        AuthenticationManager manager = mock(AuthenticationManager.class);

        when(manager.authenticate(usernameAndPassword)).thenThrow(new BadCredentialsException("bad credentials"));

        return manager;
    }

    static AuthenticationManager makeBadStatus(UsernamePasswordAuthenticationToken usernameAndPassword) {
        AuthenticationManager manager = mock(AuthenticationManager.class);

        when(manager.authenticate(usernameAndPassword)).thenThrow(new TestAccountStatusException("account not allowed"));

        return manager;
    }

    static AuthenticationManager makeAuthenticationManager() {
        return mock(AuthenticationManager.class);
    }

    static Authentication makeAuthentication() {
        Authentication authentication = mock(Authentication.class);
        when(authentication.getName()).thenReturn(RAW_AUTHENTICATION_USERNAME);
        return authentication;
    }

    static Authentication makeAuthentication(String principalName) {
        Authentication authentication = mock(Authentication.class);
        when(authentication.getName()).thenReturn(principalName);
        return authentication;
    }

    static AuthorizationRequest makeAuthorizationRequest() {
        AuthorizationRequest request = mock(AuthorizationRequest.class);

        when(request.getRequestScopes()).thenReturn(RAW_SCOPES);
        when(request.getClientId()).thenReturn(RAW_CLIENT_ID);
        when(request.getRedirectUri()).thenReturn(REDIRECT_URI);
        when(request.getUsername()).thenReturn(RAW_USERNAME);
        when(request.getState()).thenReturn(STATE);

        return request;
    }

    static UserDetailsService makeEmptyUserDetailsService() {
        return mock(UserDetailsService.class);
    }

    static UserDetailsService makeUserDetailsService(String username, UserDetails userDetails) {
        UserDetailsService service = makeEmptyUserDetailsService();

        when(service.loadUserByUsername(username)).thenReturn(userDetails);

        return service;
    }

    static User makeUserDetails() {
        return mock(User.class);
    }

    private static final class TestAccountStatusException extends AccountStatusException {

        public TestAccountStatusException(String msg) {
            super(msg);
        }
    }
}
