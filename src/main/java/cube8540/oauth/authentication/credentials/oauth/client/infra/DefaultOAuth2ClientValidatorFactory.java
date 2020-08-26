package cube8540.oauth.authentication.credentials.oauth.client.infra;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientValidatorFactory;
import cube8540.oauth.authentication.credentials.oauth.client.infra.rule.ClientCanGrantedScopeValidationRule;
import cube8540.oauth.authentication.credentials.oauth.client.infra.rule.DefaultClientGrantTypeValidationRule;
import cube8540.oauth.authentication.credentials.oauth.client.infra.rule.DefaultClientIdValidationRule;
import cube8540.oauth.authentication.credentials.oauth.client.infra.rule.DefaultClientNameValidationRule;
import cube8540.oauth.authentication.credentials.oauth.client.infra.rule.DefaultClientSecretValidationRule;
import cube8540.oauth.authentication.credentials.oauth.client.infra.rule.DefaultOAuth2ClientOwnerValidationRule;
import cube8540.oauth.authentication.credentials.oauth.scope.application.OAuth2AccessibleScopeDetailsService;
import cube8540.validator.core.Validator;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class DefaultOAuth2ClientValidatorFactory implements OAuth2ClientValidatorFactory {

    @Setter(onMethod_ = {@Autowired, @Qualifier("defaultScopeDetailsService")})
    private OAuth2AccessibleScopeDetailsService scopeDetailsService;

    @Override
    public Validator<OAuth2Client> createValidator(OAuth2Client client) {
        ClientCanGrantedScopeValidationRule scopeRule = new ClientCanGrantedScopeValidationRule();
        scopeRule.setSecurityContext(SecurityContextHolder.getContext());
        scopeRule.setScopeDetailsService(scopeDetailsService);

        return Validator.of(client).registerRule(new DefaultClientIdValidationRule())
                .registerRule(new DefaultClientSecretValidationRule())
                .registerRule(new DefaultOAuth2ClientOwnerValidationRule())
                .registerRule(new DefaultClientNameValidationRule())
                .registerRule(new DefaultClientGrantTypeValidationRule())
                .registerRule(scopeRule);
    }
}
