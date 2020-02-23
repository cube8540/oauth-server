package cube8540.oauth.authentication.credentials.authority.application;

import cube8540.oauth.authentication.credentials.authority.AuthorityDetails;
import cube8540.oauth.authentication.credentials.authority.domain.Authority;
import lombok.Value;

@Value
public class DefaultAuthorityDetails implements AuthorityDetails {

    private String code;

    private String description;

    private boolean basic;

    public static DefaultAuthorityDetails of(Authority authority) {
        return new DefaultAuthorityDetails(authority.getCode().getValue(), authority.getDescription(), authority.isBasic());
    }
}
