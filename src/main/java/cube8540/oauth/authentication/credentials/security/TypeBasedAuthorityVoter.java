package cube8540.oauth.authentication.credentials.security;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.vote.RoleVoter;

public class TypeBasedAuthorityVoter extends RoleVoter {

    private Class<? extends ConfigAttribute> attributeType;

    public TypeBasedAuthorityVoter(Class<? extends ConfigAttribute> attributeType) {
        this.attributeType = attributeType;
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return attributeType.isAssignableFrom(attribute.getClass());
    }
}
