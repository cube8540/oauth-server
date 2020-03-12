package cube8540.oauth.authentication.credentials.oauth.authorize.endpoint;

import cube8540.oauth.authentication.credentials.oauth.AuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.DefaultAuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.DefaultOAuth2RequestValidator;
import cube8540.oauth.authentication.credentials.oauth.OAuth2RequestValidator;
import cube8540.oauth.authentication.credentials.oauth.OAuth2Utils;
import cube8540.oauth.authentication.credentials.oauth.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.OAuth2ClientDetailsService;
import cube8540.oauth.authentication.credentials.oauth.error.ClientNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.error.AbstractOAuth2AuthenticationException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.credentials.oauth.error.OAuth2ExceptionTranslator;
import cube8540.oauth.authentication.credentials.oauth.error.RedirectMismatchException;
import cube8540.oauth.authentication.credentials.oauth.OAuth2ScopeDetails;
import cube8540.oauth.authentication.credentials.oauth.OAuth2ScopeDetailsService;
import cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2AuthorizationCodeGenerator;
import cube8540.oauth.authentication.credentials.oauth.token.domain.AuthorizationCode;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.DefaultSessionAttributeStore;
import org.springframework.web.bind.support.SessionAttributeStore;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

import java.net.URI;
import java.security.Principal;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

@Slf4j
@Controller
@SessionAttributes({AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE, AuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST_ATTRIBUTE})
public class AuthorizationEndpoint {

    protected static final String ORIGINAL_AUTHORIZATION_REQUEST_ATTRIBUTE = "originalAuthorizationRequest";
    protected static final String AUTHORIZATION_REQUEST_ATTRIBUTE = "authorizationRequest";
    protected static final String AUTHORIZATION_REQUEST_CLIENT_NAME = "authorizationRequestClientName";
    protected static final String AUTHORIZATION_REQUEST_SCOPES_NAME = "authorizationRequestScopes";

    private static final String DEFAULT_FORWARD_PREFIX = "forward:";

    public static final String DEFAULT_ERROR_PAGE = "/oauth/error";
    public static final String DEFAULT_APPROVAL_PAGE = DEFAULT_FORWARD_PREFIX + "/oauth/approval";

    private final OAuth2ClientDetailsService clientDetailsService;

    private final OAuth2ScopeDetailsService scopeDetailsService;

    private final OAuth2AuthorizationCodeGenerator codeGenerator;

    @Setter
    private SessionAttributeStore sessionAttributeStore = new DefaultSessionAttributeStore();

    @Setter
    private OAuth2ExceptionTranslator exceptionTranslator = new OAuth2ExceptionTranslator();

    private String errorPage = DEFAULT_ERROR_PAGE;

    private String approvalPage = DEFAULT_APPROVAL_PAGE;

    @Setter
    private RedirectResolver redirectResolver = new DefaultRedirectResolver();

    @Setter
    private ScopeApprovalResolver approvalResolver = new DefaultScopeApprovalResolver();

    @Setter
    private OAuth2RequestValidator requestValidator = new DefaultOAuth2RequestValidator();

    @Autowired
    public AuthorizationEndpoint(@Qualifier("defaultOAuth2ClientDetailsService") OAuth2ClientDetailsService clientDetailsService,
                                 OAuth2ScopeDetailsService scopeDetailsService,
                                 OAuth2AuthorizationCodeGenerator codeGenerator) {
        this.clientDetailsService = clientDetailsService;
        this.scopeDetailsService = scopeDetailsService;
        this.codeGenerator = codeGenerator;
    }

    @GetMapping(value = "/oauth/authorize")
    public ModelAndView authorize(@RequestParam Map<String, String> parameters, Map<String, Object> model, Principal principal) {
        if (!(principal instanceof Authentication) || !((Authentication) principal).isAuthenticated()) {
            throw new InsufficientAuthenticationException("User must be authenticated");
        }

        AuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest(parameters, principal);
        if (authorizationRequest.getResponseType() == null) {
            throw InvalidRequestException.invalidRequest("response_type is required");
        }
        if (!authorizationRequest.getResponseType().equals(OAuth2AuthorizationResponseType.CODE)) {
            throw InvalidRequestException.unsupportedResponseType("unsupported response type");
        }

        OAuth2ClientDetails clientDetails = clientDetailsService.loadClientDetailsByClientId(parameters.get(OAuth2Utils.AuthorizationRequestKey.CLIENT_ID));
        URI redirectURI = redirectResolver.resolveRedirectURI(parameters.get(OAuth2Utils.AuthorizationRequestKey.REDIRECT_URI), clientDetails);
        authorizationRequest.setRedirectUri(redirectURI);
        if (!requestValidator.validateScopes(clientDetails, authorizationRequest.getRequestScopes())) {
            throw InvalidGrantException.invalidScope("cannot grant scope");
        }
        authorizationRequest.setRequestScopes(extractRequestScope(clientDetails, authorizationRequest));

        Collection<OAuth2ScopeDetails> scopeDetails = scopeDetailsService.loadScopeDetailsByScopeIds(authorizationRequest.getRequestScopes());
        model.put(AUTHORIZATION_REQUEST_ATTRIBUTE, authorizationRequest);
        model.put(ORIGINAL_AUTHORIZATION_REQUEST_ATTRIBUTE, parameters);
        return new ModelAndView(approvalPage)
                .addObject(AUTHORIZATION_REQUEST_CLIENT_NAME, clientDetails.getClientName())
                .addObject(AUTHORIZATION_REQUEST_SCOPES_NAME, scopeDetails);
    }

    @PostMapping(value = "/oauth/authorize")
    public ModelAndView approval(@RequestParam Map<String, String> approvalParameters, Map<String, Object> model, SessionStatus sessionStatus, Principal principal) {
        try {
            if (!(principal instanceof Authentication) || !((Authentication) principal).isAuthenticated()) {
                throw new InsufficientAuthenticationException("User must be authenticated");
            }

            Map<?, ?> originalAuthorizationRequestMap = (Map<?, ?>) model.get(ORIGINAL_AUTHORIZATION_REQUEST_ATTRIBUTE);
            AuthorizationRequest originalAuthorizationRequest = (AuthorizationRequest) model.get(AUTHORIZATION_REQUEST_ATTRIBUTE);
            if (originalAuthorizationRequest == null || originalAuthorizationRequestMap == null) {
                throw InvalidRequestException.invalidRequest("Cannot approval uninitialized authorization request");
            }

            AuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest(originalAuthorizationRequest);
            Set<String> approvalScopes = approvalResolver.resolveApprovalScopes(originalAuthorizationRequest, approvalParameters);
            authorizationRequest.setRequestScopes(approvalScopes);

            URI redirectURI = authorizationRequest.getRedirectUri();
            if (originalAuthorizationRequestMap.get(OAuth2Utils.AuthorizationRequestKey.REDIRECT_URI) == null) {
                authorizationRequest.setRedirectUri(null);
            }
            AuthorizationCode code = codeGenerator.generateNewAuthorizationCode(authorizationRequest);
            ModelAndView modelAndView = new ModelAndView(new RedirectView(redirectURI.toString()))
                    .addObject(OAuth2Utils.AuthorizationResponseKey.CODE, code.getValue());
            if (authorizationRequest.getState() != null) {
                modelAndView.addObject(OAuth2Utils.AuthorizationResponseKey.STATE, authorizationRequest.getState());
            }
            return modelAndView;
        } finally {
            sessionStatus.setComplete();
        }
    }

    @ExceptionHandler(ClientNotFoundException.class)
    public ModelAndView handleClientRegistrationException(ClientNotFoundException e, ServletWebRequest webRequest) {
        log.warn("Handling error client registration exception : {}, {}", e.getClass().getName(), e.getMessage());
        return handleException(e, webRequest);
    }

    @ExceptionHandler(AbstractOAuth2AuthenticationException.class)
    public ModelAndView handleOAuth2AuthenticationException(AbstractOAuth2AuthenticationException e, ServletWebRequest webRequest) {
        log.warn("Handling error : {}, {}", e.getClass().getName(), e.getMessage());
        return handleException(e, webRequest);
    }

    @ExceptionHandler(Exception.class)
    public ModelAndView handleOtherException(Exception e, ServletWebRequest webRequest) {
        log.warn("Handling error : {}, {}", e.getClass().getName(), e.getMessage());
        return handleException(e, webRequest);
    }

    public void setErrorPage(String errorPage) {
        Objects.requireNonNull(errorPage);
        this.errorPage = DEFAULT_FORWARD_PREFIX + errorPage;
    }

    public void setApprovalPage(String approvalPage) {
        Objects.requireNonNull(approvalPage);
        this.approvalPage = DEFAULT_FORWARD_PREFIX + approvalPage;
    }

    private ModelAndView handleException(Exception e, ServletWebRequest webRequest) {
        ResponseEntity<OAuth2Error> responseEntity = exceptionTranslator.translate(e);
        webRequest.getResponse().setStatus(responseEntity.getStatusCode().value());

        if (e instanceof ClientNotFoundException || e instanceof RedirectMismatchException) {
            return new ModelAndView(errorPage, Collections.singletonMap("error", responseEntity.getBody()));
        }

        AuthorizationRequest authorizationRequest = getErrorAuthorizationRequest(webRequest);
        try {
            OAuth2ClientDetails clientDetails = clientDetailsService.loadClientDetailsByClientId(authorizationRequest.getClientId());
            String storedRedirectURI = Optional.ofNullable(authorizationRequest.getRedirectUri()).map(URI::toString).orElse(null);
            URI redirectURI = redirectResolver.resolveRedirectURI(storedRedirectURI, clientDetails);
            return getUnsuccessfulRedirectView(redirectURI, responseEntity.getBody(), authorizationRequest);
        } catch (Exception exception) {
            log.error("An exception occurred during error handling {} {}", exception.getClass().getName(), exception.getMessage());
            return new ModelAndView(errorPage, Collections.singletonMap("error", responseEntity.getBody()));
        }
    }

    private ModelAndView getUnsuccessfulRedirectView(URI redirectURI, OAuth2Error error, AuthorizationRequest authorizationRequest) {
        ModelAndView modelAndView = new ModelAndView(new RedirectView(redirectURI.toString()))
                .addObject("error_code", error.getErrorCode())
                .addObject("error_description", error.getDescription());

        if (authorizationRequest.getState() != null) {
            modelAndView.addObject("state", authorizationRequest.getState());
        }
        return modelAndView;
    }

    private AuthorizationRequest getErrorAuthorizationRequest(ServletWebRequest webRequest) {
        AuthorizationRequest authorizationRequest = (AuthorizationRequest) sessionAttributeStore
                .retrieveAttribute(webRequest, AUTHORIZATION_REQUEST_ATTRIBUTE);
        if (authorizationRequest != null) {
            return authorizationRequest;
        }
        Map<String, String> parameters = new HashMap<>();
        parameters.put(OAuth2Utils.AuthorizationRequestKey.REDIRECT_URI,
                webRequest.getParameter(OAuth2Utils.AuthorizationRequestKey.REDIRECT_URI));
        parameters.put(OAuth2Utils.AuthorizationRequestKey.CLIENT_ID,
                webRequest.getParameter(OAuth2Utils.AuthorizationRequestKey.CLIENT_ID));
        parameters.put(OAuth2Utils.AuthorizationRequestKey.STATE,
                webRequest.getParameter(OAuth2Utils.AuthorizationRequestKey.STATE));
        return new DefaultAuthorizationRequest(parameters, SecurityContextHolder.getContext().getAuthentication());
    }

    protected Set<String> extractRequestScope(OAuth2ClientDetails clientDetails, AuthorizationRequest authorizationRequest) {
        return authorizationRequest.getRequestScopes().isEmpty() ? clientDetails.getScopes() : authorizationRequest.getRequestScopes();
    }
}
