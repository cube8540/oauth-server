package cube8540.oauth.authentication.credentials.role.application;

import cube8540.oauth.authentication.credentials.AuthorityDetails;
import cube8540.oauth.authentication.credentials.AuthorityType;
import cube8540.oauth.authentication.credentials.role.domain.Role;
import lombok.Value;

@Value
public class DefaultAuthorityDetails implements AuthorityDetails {

    String code;

    String description;

    AuthorityType authorityType;

    public static DefaultAuthorityDetails of(Role role) {
        return new DefaultAuthorityDetails(role.getCode().getValue(), role.getDescription(), AuthorityType.AUTHORITY);
    }

}
