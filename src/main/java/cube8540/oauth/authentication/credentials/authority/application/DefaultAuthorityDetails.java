package cube8540.oauth.authentication.credentials.authority.application;

import cube8540.oauth.authentication.credentials.authority.AuthorityDetails;
import cube8540.oauth.authentication.credentials.authority.domain.Authority;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResourceId;
import lombok.Value;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Value
public class DefaultAuthorityDetails implements AuthorityDetails {

    private String code;

    private String description;

    private boolean basic;

    private List<String> accessibleResources;

    public static DefaultAuthorityDetails of(Authority authority) {
        List<String> accessibleResources = Optional.ofNullable(authority.getAccessibleResources()).orElse(Collections.emptySet())
                .stream().map(SecuredResourceId::getValue).collect(Collectors.toList());
        return new DefaultAuthorityDetails(authority.getCode().getValue(), authority.getDescription(), authority.isBasic(), accessibleResources);
    }
}
