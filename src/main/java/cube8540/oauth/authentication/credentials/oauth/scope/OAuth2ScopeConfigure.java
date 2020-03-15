package cube8540.oauth.authentication.credentials.oauth.scope;

import cube8540.oauth.authentication.credentials.authority.AuthorityDetailsService;
import cube8540.oauth.authentication.credentials.oauth.scope.application.DefaultScopeDetailsService;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeRepository;
import cube8540.oauth.authentication.credentials.oauth.scope.infra.DefaultOAuth2ScopeValidationPolicy;
import cube8540.oauth.authentication.credentials.oauth.scope.infra.ScopeAPIExceptionTranslator;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import cube8540.oauth.authentication.error.ExceptionTranslator;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OAuth2ScopeConfigure {

    @Setter(onMethod_ = @Autowired)
    private OAuth2ScopeRepository scopeRepository;

    @Setter(onMethod_ = @Autowired)
    private AuthorityDetailsService authorityService;

    @Bean
    public DefaultScopeDetailsService defaultScopeDetailsService() {
        DefaultScopeDetailsService service = new DefaultScopeDetailsService(scopeRepository);

        DefaultOAuth2ScopeValidationPolicy policy = new DefaultOAuth2ScopeValidationPolicy();
        policy.setAuthorityService(authorityService);

        service.setValidationPolicy(policy);
        return service;
    }

    @Bean
    public ExceptionTranslator<ErrorMessage<Object>> scopeExceptionTranslator() {
        return new ScopeAPIExceptionTranslator();
    }

}
