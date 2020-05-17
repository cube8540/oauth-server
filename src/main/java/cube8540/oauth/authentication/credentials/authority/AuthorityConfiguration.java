package cube8540.oauth.authentication.credentials.authority;

import cube8540.oauth.authentication.credentials.authority.application.DefaultSecuredResourceManagementService;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResourceValidationPolicy;
import cube8540.oauth.authentication.credentials.authority.infra.DefaultSecuredResourceValidationPolicy;
import cube8540.oauth.authentication.credentials.authority.infra.SecuredResourceExceptionTranslator;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ScopeDetailsService;
import cube8540.oauth.authentication.error.ExceptionTranslator;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.annotation.PostConstruct;

@Configuration
public class AuthorityConfiguration {

    @Setter(onMethod_ = @Autowired)
    private DefaultSecuredResourceManagementService securedResourceManagementService;

    @Setter(onMethod_ = @Autowired)
    private OAuth2ScopeDetailsService scopeDetailsService;

    @PostConstruct
    public void setManagementServicePolicy() {
        securedResourceManagementService.setValidationPolicy(createSecuredResourceValidationPolicy(scopeDetailsService));
    }

    private SecuredResourceValidationPolicy createSecuredResourceValidationPolicy(OAuth2ScopeDetailsService scopeDetailsService) {
        DefaultSecuredResourceValidationPolicy policy = new DefaultSecuredResourceValidationPolicy();
        policy.setAuthorityDetailsService(scopeDetailsService);
        return policy;
    }

    @Bean
    public ExceptionTranslator<ErrorMessage<Object>> securedResourceExceptionTranslator() {
        return new SecuredResourceExceptionTranslator();
    }

}
