package cube8540.oauth.authentication.credentials.authority.domain;

import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
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
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "authority")
public class Authority extends AbstractAggregateRoot<Authority> {

    @EmbeddedId
    @AttributeOverride(name = "value", column = @Column(name = "code", length = 32))
    private AuthorityCode code;

    @Setter
    @Column(name = "description", length = 64)
    private String description;

    @Column(name = "is_basic", nullable = false)
    private boolean basic;

    public Authority(String code, String description) {
        this.code = new AuthorityCode(code);
        this.description = description;
        this.basic = false;
    }

    public void settingBasicAuthority() {
        this.basic = true;
    }

    public void settingNotBasicAuthority() {
        this.basic = false;
    }
}
