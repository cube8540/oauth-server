package cube8540.oauth.authentication.credentials.security;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.vote.RoleVoter;

public class RoleAuthorityVoter extends RoleVoter {

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return super.supports(attribute) && (RoleSecurityConfig.class.isAssignableFrom(attribute.getClass()));
    }
}
