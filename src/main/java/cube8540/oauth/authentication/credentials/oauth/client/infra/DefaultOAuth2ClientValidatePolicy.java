package cube8540.oauth.authentication.credentials.oauth.client.infra;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientValidatePolicy;
import cube8540.oauth.authentication.credentials.oauth.client.infra.rule.ClientCanGrantedScopeValidationRule;
import cube8540.oauth.authentication.credentials.oauth.client.infra.rule.DefaultClientGrantTypeValidationRule;
import cube8540.oauth.authentication.credentials.oauth.client.infra.rule.DefaultClientIdValidationRule;
import cube8540.oauth.authentication.credentials.oauth.client.infra.rule.DefaultClientNameValidationRule;
import cube8540.oauth.authentication.credentials.oauth.client.infra.rule.DefaultClientSecretValidationRule;
import cube8540.oauth.authentication.credentials.oauth.client.infra.rule.DefaultOAuth2ClientOwnerValidationRule;
import cube8540.oauth.authentication.credentials.oauth.scope.OAuth2AccessibleScopeDetailsService;
import cube8540.validator.core.ValidationRule;
import lombok.Setter;
import org.springframework.security.core.context.SecurityContextHolder;

public class DefaultOAuth2ClientValidatePolicy implements OAuth2ClientValidatePolicy {

    @Setter
    private OAuth2AccessibleScopeDetailsService scopeDetailsService;

    @Override
    public ValidationRule<OAuth2Client> clientIdRule() {
        return new DefaultClientIdValidationRule();
    }

    @Override
    public ValidationRule<OAuth2Client> secretRule() {
        return new DefaultClientSecretValidationRule();
    }

    @Override
    public ValidationRule<OAuth2Client> ownerRule() {
        return new DefaultOAuth2ClientOwnerValidationRule();
    }

    @Override
    public ValidationRule<OAuth2Client> clientNameRule() {
        return new DefaultClientNameValidationRule();
    }

    @Override
    public ValidationRule<OAuth2Client> grantTypeRule() {
        return new DefaultClientGrantTypeValidationRule();
    }

    @Override
    public ValidationRule<OAuth2Client> scopeRule() {
        ClientCanGrantedScopeValidationRule scopeRule = new ClientCanGrantedScopeValidationRule();
        scopeRule.setSecurityContext(SecurityContextHolder.getContext());
        scopeRule.setScopeDetailsService(scopeDetailsService);
        return scopeRule;
    }
}
