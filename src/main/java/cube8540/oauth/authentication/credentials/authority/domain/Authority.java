package cube8540.oauth.authentication.credentials.authority.domain;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.springframework.data.domain.AbstractAggregateRoot;

@Getter
@ToString
@EqualsAndHashCode(callSuper = false)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Authority extends AbstractAggregateRoot<Authority> {

    private AuthorityCode code;

    private String description;

    private boolean basic;

    public static Authority createBasicAuthority(String authorityCode, String description) {
        return new Authority(new AuthorityCode(authorityCode), description, Boolean.TRUE);
    }

    public static Authority createDefaultAuthority(String authorityCode, String description) {
        return new Authority(new AuthorityCode(authorityCode), description, Boolean.FALSE);
    }
}
