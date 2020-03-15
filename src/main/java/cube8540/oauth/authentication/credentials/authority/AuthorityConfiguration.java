package cube8540.oauth.authentication.credentials.authority;

import cube8540.oauth.authentication.credentials.authority.application.DefaultAuthorityManagementService;
import cube8540.oauth.authentication.credentials.authority.application.DefaultSecuredResourceManagementService;
import cube8540.oauth.authentication.credentials.authority.application.SecuredResourceReadService;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityValidationPolicy;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResourceValidationPolicy;
import cube8540.oauth.authentication.credentials.authority.infra.AuthorityExceptionTranslator;
import cube8540.oauth.authentication.credentials.authority.infra.DefaultAuthorityValidationPolicy;
import cube8540.oauth.authentication.credentials.authority.infra.DefaultSecuredResourceValidationPolicy;
import cube8540.oauth.authentication.credentials.authority.infra.SecuredResourceExceptionTranslator;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import cube8540.oauth.authentication.error.ExceptionTranslator;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.annotation.PostConstruct;

@Configuration
public class AuthorityConfiguration {

    @Setter(onMethod_ = @Autowired)
    private DefaultAuthorityManagementService authorityManagementService;

    @Setter(onMethod_ = @Autowired)
    private DefaultSecuredResourceManagementService securedResourceManagementService;

    @PostConstruct
    public void setManagementServicePolicy() {
        authorityManagementService.setValidationPolicy(createAuthorityValidationPolicy(securedResourceManagementService));
        securedResourceManagementService.setValidationPolicy(createSecuredResourceValidationPolicy(authorityManagementService));
    }

    private AuthorityValidationPolicy createAuthorityValidationPolicy(SecuredResourceReadService securedResourceReadService) {
        DefaultAuthorityValidationPolicy policy = new DefaultAuthorityValidationPolicy();
        policy.setSecuredResourceReadService(securedResourceReadService);
        return policy;
    }

    private SecuredResourceValidationPolicy createSecuredResourceValidationPolicy(AuthorityDetailsService authorityDetailsService) {
        DefaultSecuredResourceValidationPolicy policy = new DefaultSecuredResourceValidationPolicy();
        policy.setAuthorityDetailsService(authorityDetailsService);
        return policy;
    }

    @Bean
    public ExceptionTranslator<ErrorMessage<Object>> authorityExceptionTranslator() {
        return new AuthorityExceptionTranslator();
    }

    @Bean
    public ExceptionTranslator<ErrorMessage<Object>> securedResourceExceptionTranslator() {
        return new SecuredResourceExceptionTranslator();
    }

}
