package cube8540.oauth.authentication.credentials.authority.application;

import cube8540.oauth.authentication.credentials.authority.AuthorityDetails;
import cube8540.oauth.authentication.credentials.authority.domain.Authority;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

@Getter
@ToString
@EqualsAndHashCode
public class DefaultAuthorityDetails implements AuthorityDetails {

    private String code;

    private String description;

    public DefaultAuthorityDetails(Authority authority) {
        this.code = authority.getCode().getValue();
        this.description = authority.getDescription();
    }

    @Override
    public String code() {
        return code;
    }

    @Override
    public String description() {
        return description;
    }
}
