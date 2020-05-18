package cube8540.oauth.authentication.credentials.resource.domain;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import javax.persistence.Column;
import javax.persistence.Embeddable;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import java.io.Serializable;

@Getter
@ToString
@EqualsAndHashCode
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Embeddable
public class AccessibleAuthority implements Serializable {

    @Column(name = "authority", length = 32, nullable = false)
    private String authority;

    @Enumerated(EnumType.STRING)
    @Column(name = "authority_type", length = 16, nullable = false)
    private AuthorityType authorityType;

    public enum AuthorityType {
        AUTHORITY, OAUTH2_SCOPE
    }
}
