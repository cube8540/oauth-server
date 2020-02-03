package cube8540.oauth.authentication.credentials.oauth.authorize.endpoint;

import cube8540.oauth.authentication.credentials.oauth.AuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.DefaultAuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.DefaultOAuth2RequestValidator;
import cube8540.oauth.authentication.credentials.oauth.OAuth2RequestValidator;
import cube8540.oauth.authentication.credentials.oauth.OAuth2Utils;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetailsService;
import cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2AuthorizationCodeGenerator;
import cube8540.oauth.authentication.credentials.oauth.token.domain.AuthorizationCode;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.credentials.oauth.error.UnsupportedResponseTypeException;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

import java.net.URI;
import java.security.Principal;
import java.util.Map;
import java.util.Set;

@Controller
@SessionAttributes({AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE})
public class AuthorizationEndpoint {

    protected static final String AUTHORIZATION_REQUEST_ATTRIBUTE = "authorizationRequest";
    protected static final String AUTHORIZATION_REQUEST_CLIENT_NAME = "authorizationRequestClientName";
    protected static final String AUTHORIZATION_REQUEST_SCOPES_NAME = "authorizationRequestScopes";

    private static final String DEFAULT_ERROR_PAGE = "forward:/oauth/error";
    private static final String DEFAULT_APPROVAL_PAGE = "forward:/oauth/approval";

    private final OAuth2ClientDetailsService clientDetailsService;

    private final OAuth2AuthorizationCodeGenerator codeGenerator;

    @Setter
    private String errorPage = DEFAULT_ERROR_PAGE;

    @Setter
    private String approvalPage = DEFAULT_APPROVAL_PAGE;

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
    public ModelAndView authorize(@RequestParam Map<String, String> parameters, Map<String, Object> model, SessionStatus sessionStatus, Principal principal) {
        try {
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
        } catch (RuntimeException e) {
            sessionStatus.setComplete();
            throw e;
        }
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
        } catch (RuntimeException e) {
            sessionStatus.setComplete();
            throw e;
        }
    }

    protected Set<String> extractRequestScope(OAuth2ClientDetails clientDetails, AuthorizationRequest authorizationRequest) {
        return authorizationRequest.requestScopes().isEmpty() ? clientDetails.scope() : authorizationRequest.requestScopes();
    }
}
