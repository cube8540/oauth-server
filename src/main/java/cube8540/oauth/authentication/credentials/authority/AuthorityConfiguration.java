package cube8540.oauth.authentication.credentials.authority;

import cube8540.oauth.authentication.credentials.authority.application.AuthorityManagementService;
import cube8540.oauth.authentication.credentials.authority.application.DefaultAuthorityManagementService;
import cube8540.oauth.authentication.credentials.authority.application.DefaultSecuredResourceManagementService;
import cube8540.oauth.authentication.credentials.authority.application.SecuredResourceManagementService;
import cube8540.oauth.authentication.credentials.authority.application.SecuredResourceReadService;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityRepository;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResourceRepository;
import cube8540.oauth.authentication.credentials.authority.infra.AuthorityExceptionTranslator;
import cube8540.oauth.authentication.credentials.authority.infra.DefaultAuthorityValidationPolicy;
import cube8540.oauth.authentication.credentials.authority.infra.DefaultSecuredResourceValidationPolicy;
import cube8540.oauth.authentication.credentials.authority.infra.SecuredResourceExceptionTranslator;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import cube8540.oauth.authentication.error.message.ExceptionTranslator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AuthorityConfiguration {

    @Bean
    @Autowired
    public AuthorityManagementService authorityManagementService(AuthorityRepository repository, SecuredResourceReadService securedResourceReadService) {
        DefaultAuthorityManagementService service = new DefaultAuthorityManagementService(repository);

        DefaultAuthorityValidationPolicy policy = new DefaultAuthorityValidationPolicy();
        policy.setSecuredResourceReadService(securedResourceReadService);

        service.setValidationPolicy(policy);

        return service;
    }

    @Bean
    @Autowired
    public SecuredResourceManagementService securedResourceManagementService(SecuredResourceRepository securedResourceRepository) {
        DefaultSecuredResourceManagementService service = new DefaultSecuredResourceManagementService(securedResourceRepository);

        service.setPolicy(new DefaultSecuredResourceValidationPolicy());
        return service;
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
