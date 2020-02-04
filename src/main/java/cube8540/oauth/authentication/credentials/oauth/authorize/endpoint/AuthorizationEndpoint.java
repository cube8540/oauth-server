package cube8540.oauth.authentication.credentials.oauth.authorize.endpoint;

import cube8540.oauth.authentication.credentials.oauth.AuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.DefaultAuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.DefaultOAuth2RequestValidator;
import cube8540.oauth.authentication.credentials.oauth.OAuth2RequestValidator;
import cube8540.oauth.authentication.credentials.oauth.OAuth2Utils;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetailsService;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientRegistrationException;
import cube8540.oauth.authentication.credentials.oauth.error.DefaultOAuth2ExceptionTranslator;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.credentials.oauth.error.OAuth2ExceptionTranslator;
import cube8540.oauth.authentication.credentials.oauth.error.RedirectMismatchException;
import cube8540.oauth.authentication.credentials.oauth.error.UnsupportedResponseTypeException;
import cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2AuthorizationCodeGenerator;
import cube8540.oauth.authentication.credentials.oauth.token.domain.AuthorizationCode;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
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
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

@Slf4j
@Controller
@SessionAttributes({AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE})
public class AuthorizationEndpoint {

    protected static final String AUTHORIZATION_REQUEST_ATTRIBUTE = "authorizationRequest";
    protected static final String AUTHORIZATION_REQUEST_CLIENT_NAME = "authorizationRequestClientName";
    protected static final String AUTHORIZATION_REQUEST_SCOPES_NAME = "authorizationRequestScopes";

    private static final String DEFAULT_FORWARD_PREFIX = "forward:";

    public static final String DEFAULT_ERROR_PAGE = "/oauth/error";
    public static final String DEFAULT_APPROVAL_PAGE = "/oauth/approval";

    private final OAuth2ClientDetailsService clientDetailsService;

    private final OAuth2AuthorizationCodeGenerator codeGenerator;

    @Setter
    private SessionAttributeStore sessionAttributeStore = new DefaultSessionAttributeStore();

    @Setter
    private OAuth2ExceptionTranslator exceptionTranslator = new DefaultOAuth2ExceptionTranslator();

    private String errorPage = DEFAULT_FORWARD_PREFIX + DEFAULT_ERROR_PAGE;

    private String approvalPage = DEFAULT_FORWARD_PREFIX + DEFAULT_APPROVAL_PAGE;

    @Setter
    private RedirectResolver redirectResolver = new DefaultRedirectResolver();

    @Setter
    private ScopeApprovalResolver approvalResolver = new DefaultScopeApprovalResolver();

    @Setter
    private OAuth2RequestValidator requestValidator = new DefaultOAuth2RequestValidator();

    @Autowired
    public AuthorizationEndpoint(OAuth2ClientDetailsService clientDetailsService, OAuth2AuthorizationCodeGenerator codeGenerator) {
        this.clientDetailsService = clientDetailsService;
        this.codeGenerator = codeGenerator;
    }

    @GetMapping(value = "/oauth/authorize")
    public ModelAndView authorize(@RequestParam Map<String, String> parameters, Map<String, Object> model, Principal principal) {
        if (!(principal instanceof Authentication) || !((Authentication) principal).isAuthenticated()) {
            throw new InsufficientAuthenticationException("User must be authenticated");
        }

        AuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest(parameters, principal);
        if (!OAuth2AuthorizationResponseType.CODE.equals(authorizationRequest.responseType())) {
            throw new UnsupportedResponseTypeException("unsupported response type");
        }

        OAuth2ClientDetails clientDetails = clientDetailsService.loadClientDetailsByClientId(parameters.get(OAuth2Utils.AuthorizationRequestKey.CLIENT_ID));
        URI redirectURI = redirectResolver.resolveRedirectURI(parameters.get(OAuth2Utils.AuthorizationRequestKey.REDIRECT_URI), clientDetails);
        authorizationRequest.setRedirectURI(redirectURI);
        if (!requestValidator.validateScopes(clientDetails, authorizationRequest.requestScopes())) {
            throw new InvalidGrantException("cannot grant scope");
        }
        authorizationRequest.setRequestScopes(extractRequestScope(clientDetails, authorizationRequest));

        model.put(AUTHORIZATION_REQUEST_ATTRIBUTE, authorizationRequest);
        return new ModelAndView(approvalPage)
                .addObject(AUTHORIZATION_REQUEST_CLIENT_NAME, clientDetails.clientName())
                .addObject(AUTHORIZATION_REQUEST_SCOPES_NAME, authorizationRequest.requestScopes());
    }

    @PostMapping(value = "/oauth/authorize")
    public ModelAndView approval(@RequestParam Map<String, String> approvalParameters, Map<String, Object> model, SessionStatus sessionStatus, Principal principal) {
        try {
            if (!(principal instanceof Authentication) || !((Authentication) principal).isAuthenticated()) {
                throw new InsufficientAuthenticationException("User must be authenticated");
            }

            AuthorizationRequest originalAuthorizationRequest = (AuthorizationRequest) model.get(AUTHORIZATION_REQUEST_ATTRIBUTE);
            if (originalAuthorizationRequest == null) {
                throw new InvalidRequestException("Cannot approval uninitialized authorization request");
            }

            AuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest(originalAuthorizationRequest);
            Set<String> approvalScopes = approvalResolver.resolveApprovalScopes(originalAuthorizationRequest, approvalParameters);
            authorizationRequest.setRequestScopes(approvalScopes);

            AuthorizationCode code = codeGenerator.generateNewAuthorizationCode(authorizationRequest);
            ModelAndView modelAndView = new ModelAndView(new RedirectView(authorizationRequest.redirectURI().toString()))
                    .addObject(OAuth2Utils.AuthorizationResponseKey.CODE, code.getValue());
            if (authorizationRequest.state() != null) {
                modelAndView.addObject(OAuth2Utils.AuthorizationResponseKey.STATE, authorizationRequest.state());
            }
            return modelAndView;
        } finally {
            sessionStatus.setComplete();
        }
    }

    @ExceptionHandler(OAuth2ClientRegistrationException.class)
    public ModelAndView handleClientRegistrationException(OAuth2ClientRegistrationException e, ServletWebRequest webRequest) {
        if (log.isWarnEnabled()) {
            log.warn("Handling error client registration exception : {}, {}", e.getClass().getName(), e.getMessage());
        }
        return handleException(e, webRequest);
    }

    @ExceptionHandler(OAuth2AuthenticationException.class)
    public ModelAndView handleOAuth2AuthenticationException(OAuth2AuthenticationException e, ServletWebRequest webRequest) {
        if (log.isWarnEnabled()) {
            log.warn("Handling error : {}, {}", e.getClass().getName(), e.getMessage());
        }
        return handleException(e, webRequest);
    }

    @ExceptionHandler(Exception.class)
    public ModelAndView handleOtherException(Exception e, ServletWebRequest webRequest) {
        if (log.isWarnEnabled()) {
            log.warn("Handling error : {}, {}", e.getClass().getName(), e.getMessage());
        }
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

        if (e instanceof OAuth2ClientRegistrationException || e instanceof RedirectMismatchException) {
            return new ModelAndView(errorPage, Collections.singletonMap("error", responseEntity.getBody()));
        }

        AuthorizationRequest authorizationRequest = getErrorAuthorizationRequest(webRequest);
        try {
            OAuth2ClientDetails clientDetails = clientDetailsService.loadClientDetailsByClientId(authorizationRequest.clientId());
            String storedRedirectURI = Optional.ofNullable(authorizationRequest.redirectURI()).map(URI::toString).orElse(null);
            URI redirectURI = redirectResolver.resolveRedirectURI(storedRedirectURI, clientDetails);
            return getUnsuccessfulRedirectView(redirectURI, responseEntity.getBody(), authorizationRequest);
        } catch (Exception exception) {
            if (log.isErrorEnabled()) {
                log.error("An exception occurred during error handling {} {}", exception.getClass().getName(), exception.getMessage());
            }
            return new ModelAndView(errorPage, Collections.singletonMap("error", responseEntity.getBody()));
        }
    }

    private ModelAndView getUnsuccessfulRedirectView(URI redirectURI, OAuth2Error error, AuthorizationRequest authorizationRequest) {
        ModelAndView modelAndView = new ModelAndView(new RedirectView(redirectURI.toString()))
                .addObject("error_code", error.getErrorCode())
                .addObject("error_description", error.getDescription());

        if (authorizationRequest.state() != null) {
            modelAndView.addObject("state", authorizationRequest.state());
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
        return authorizationRequest.requestScopes().isEmpty() ? clientDetails.scope() : authorizationRequest.requestScopes();
    }
}
