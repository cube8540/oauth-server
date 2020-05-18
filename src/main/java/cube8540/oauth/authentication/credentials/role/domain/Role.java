package cube8540.oauth.authentication.credentials.role.domain;

import cube8540.oauth.authentication.credentials.domain.AbstractAuthority;
import cube8540.oauth.authentication.credentials.domain.AuthorityCode;
import cube8540.oauth.authentication.credentials.role.domain.exception.RoleInvalidException;
import cube8540.oauth.authentication.credentials.role.infra.RoleValidationPolicy;
import cube8540.validator.core.Validator;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.AttributeOverride;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;

@Getter
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "role")
@AttributeOverride(name = "code.value", column = @Column(name = "code", length = 32))
public class Role extends AbstractAuthority {

    @Setter
    @Column(name = "basic", nullable = false)
    private boolean basic;

    public Role(String code, String description) {
        super(new AuthorityCode(code), description);
        this.basic = false;
    }

    public void validate(RoleValidationPolicy policy) {
        Validator.of(this).registerRule(policy.roleCodeRule())
                .getResult().hasErrorThrows(RoleInvalidException::instance);
    }
}
