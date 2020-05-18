package cube8540.oauth.authentication.credentials.role.infra;

import cube8540.oauth.authentication.credentials.role.domain.Role;
import cube8540.validator.core.ValidationRule;

public interface RoleValidationPolicy {

    ValidationRule<Role> roleCodeRule();

}
