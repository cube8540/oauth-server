package cube8540.oauth.authentication.credentials.oauth.scope.domain;

import cube8540.oauth.authentication.credentials.AbstractAuthority;
import cube8540.oauth.authentication.credentials.AuthorityCode;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.exception.ScopeInvalidException;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import javax.persistence.AttributeOverride;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;

@Getter
@ToString
@EqualsAndHashCode(callSuper = false)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "oauth2_scope")
@AttributeOverride(name = "code.value", column = @Column(name = "scope_id", length = 32))
public class OAuth2Scope extends AbstractAuthority {

    @Setter
    @Column(name = "is_secured", nullable = false)
    private Boolean secured;

    public OAuth2Scope(String scopeId, String description) {
        super(new AuthorityCode(scopeId), description);
        this.secured = true;
    }

    public boolean isSecured() {
        return secured != null && secured;
    }

    public void validate(OAuth2ScopeValidatorFactory factory) {
        factory.createValidator(this).getResult().hasErrorThrows(ScopeInvalidException::instance);
    }
}
