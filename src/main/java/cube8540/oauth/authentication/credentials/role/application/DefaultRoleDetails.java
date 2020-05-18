package cube8540.oauth.authentication.credentials.role.application;

import cube8540.oauth.authentication.credentials.AuthorityDetails;
import cube8540.oauth.authentication.credentials.role.domain.Role;
import lombok.Value;

@Value
public class DefaultRoleDetails implements AuthorityDetails {

    String code;

    String description;

    boolean basic;

    public static DefaultRoleDetails of(Role role) {
        return new DefaultRoleDetails(role.getCode().getValue(), role.getDescription(), role.isBasic());
    }

}
