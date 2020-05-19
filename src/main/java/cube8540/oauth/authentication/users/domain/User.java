package cube8540.oauth.authentication.users.domain;

import cube8540.oauth.authentication.users.domain.exception.UserAuthorizationException;
import cube8540.oauth.authentication.users.domain.exception.UserInvalidException;
import cube8540.validator.core.Validator;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.data.domain.AbstractAggregateRoot;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.persistence.AttributeOverride;
import javax.persistence.AttributeOverrides;
import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.Embedded;
import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.Table;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Getter
@ToString
@EqualsAndHashCode(callSuper = false)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "user")
@DynamicInsert
@DynamicUpdate
public class User extends AbstractAggregateRoot<User> {

    @EmbeddedId
    @AttributeOverride(name = "value", column = @Column(name = "username", length = 32))
    private Username username;

    @Embedded
    @AttributeOverride(name = "value", column = @Column(name = "email", length = 128, unique = true))
    private UserEmail email;

    @Column(name = "password", length = 64, nullable = false)
    private String password;

    @Embedded
    @AttributeOverrides(value = {
            @AttributeOverride(name = "keyValue", column = @Column(name = "credentials_key", length = 32)),
            @AttributeOverride(name = "expiryDateTime", column = @Column(name = "credentials_key_expiry_datetime"))
    })
    private UserCredentialsKey credentialsKey;

    @Embedded
    @AttributeOverrides(value = {
            @AttributeOverride(name = "keyValue", column = @Column(name = "password_credentials_key", length = 32)),
            @AttributeOverride(name = "expiryDateTime", column = @Column(name = "password_credentials_key_expiry_datetime"))
    })
    private UserCredentialsKey passwordCredentialsKey;

    @Column(name = "is_credentials", nullable = false)
    private boolean isCredentials;

    @CreationTimestamp
    @Column(name = "registered_at", nullable = false)
    private LocalDateTime registeredAt;

    @UpdateTimestamp
    @Column(name = "last_updated_at", nullable = false)
    private LocalDateTime lastUpdatedAt;

    @ElementCollection
    @CollectionTable(name = "user_authority", joinColumns = @JoinColumn(name = "username", nullable = false))
    @AttributeOverride(name = "value", column = @Column(name = "authority_code", length = 32, nullable = false))
    private Set<UserAuthority> authorities;

    public User(String username, String email, String password) {
        this.username = new Username(username);
        this.email = new UserEmail(email);
        this.password = password;
        this.isCredentials = false;
        registerEvent(new UserRegisterEvent(this.username));
    }

    public void validation(UserValidationPolicy policy) {
        Validator.of(this).registerRule(policy.usernameRule())
                .registerRule(policy.emailRule())
                .registerRule(policy.passwordRule())
                .getResult().hasErrorThrows(UserInvalidException::instance);
    }

    public void generateCredentialsKey(UserCredentialsKeyGenerator keyGenerator) {
        if (isCredentials) {
            throw UserAuthorizationException.alreadyCredentials("This account is already certification");
        }
        this.credentialsKey = keyGenerator.generateKey();
        registerEvent(new UserGeneratedCredentialsKeyEvent(username, email, credentialsKey));
    }

    public void credentials(String credentialsKey) {
        UserKeyMatchedResult matchedResult = Optional.ofNullable(this.credentialsKey)
                .map(key -> key.matches(credentialsKey))
                .orElseThrow(() -> UserAuthorizationException.invalidKey("Key is not matched"));
        assertMatchedResult(matchedResult);
        this.credentialsKey = null;
        this.isCredentials = true;
    }

    public void changePassword(String existsPassword, String changePassword, PasswordEncoder encoder) {
        if (!encoder.matches(existsPassword, password)) {
            throw UserAuthorizationException.invalidPassword("Existing password is not matched");
        }
        this.password = changePassword;
    }

    public void forgotPassword(UserCredentialsKeyGenerator keyGenerator) {
        this.passwordCredentialsKey = keyGenerator.generateKey();
        registerEvent(new UserGeneratedPasswordCredentialsKeyEvent(email, passwordCredentialsKey));
    }

    public void resetPassword(String passwordCredentialsKey, String changePassword) {
        UserKeyMatchedResult matchedResult = Optional.ofNullable(this.passwordCredentialsKey)
                .map(key -> key.matches(passwordCredentialsKey))
                .orElseThrow(() -> UserAuthorizationException.invalidKey("Key is not matched"));
        assertMatchedResult(matchedResult);
        this.password = changePassword;
        this.passwordCredentialsKey = null;
    }

    public void encrypted(PasswordEncoder encoder) {
        this.password = encoder.encode(this.password);
    }

    public void grantAuthority(UserAuthority authority) {
        if (this.authorities == null) {
            this.authorities = new HashSet<>();
        }
        this.authorities.add(authority);
    }

    private void assertMatchedResult(UserKeyMatchedResult matchedResult) {
        if (matchedResult.equals(UserKeyMatchedResult.NOT_MATCHED)) {
            throw UserAuthorizationException.invalidKey("Key is not matched");
        } else if (matchedResult.equals(UserKeyMatchedResult.EXPIRED)) {
            throw UserAuthorizationException.keyExpired("Key is expired");
        }
    }
}
