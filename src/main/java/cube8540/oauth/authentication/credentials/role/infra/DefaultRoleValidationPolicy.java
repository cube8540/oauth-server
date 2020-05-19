package cube8540.oauth.authentication.credentials.role.infra;

import cube8540.oauth.authentication.credentials.role.domain.Role;
import cube8540.oauth.authentication.credentials.role.infra.rule.DefaultRoleCodeValidationRule;
import cube8540.validator.core.ValidationRule;

public class DefaultRoleValidationPolicy implements RoleValidationPolicy {
    @Override
    public ValidationRule<Role> roleCodeRule() {
        return new DefaultRoleCodeValidationRule();
    }
}
