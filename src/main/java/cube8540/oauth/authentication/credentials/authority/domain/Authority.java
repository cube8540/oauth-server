package cube8540.oauth.authentication.credentials.authority.domain;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.springframework.data.domain.AbstractAggregateRoot;

import javax.persistence.AttributeOverride;
import javax.persistence.Column;
import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.Table;

@Getter
@ToString
@EqualsAndHashCode(callSuper = false)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "authority")
public class Authority extends AbstractAggregateRoot<Authority> {

    @EmbeddedId
    @AttributeOverride(name = "value", column = @Column(name = "code", length = 32))
    private AuthorityCode code;

    @Column(name = "description", length = 64)
    private String description;

    @Column(name = "is_basic", nullable = false)
    private boolean basic;

    public static Authority createBasicAuthority(String authorityCode, String description) {
        return new Authority(new AuthorityCode(authorityCode), description, Boolean.TRUE);
    }

    public static Authority createDefaultAuthority(String authorityCode, String description) {
        return new Authority(new AuthorityCode(authorityCode), description, Boolean.FALSE);
    }
}
