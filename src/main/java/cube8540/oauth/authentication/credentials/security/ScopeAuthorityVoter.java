package cube8540.oauth.authentication.credentials.security;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.vote.RoleVoter;

public class ScopeAuthorityVoter extends RoleVoter {

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return super.supports(attribute) && (ScopeSecurityConfig.class.isAssignableFrom(attribute.getClass()));
    }
}
