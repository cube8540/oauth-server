package cube8540.oauth.authentication.users.domain;

import cube8540.oauth.authentication.credentials.authority.domain.AuthorityCode;
import cube8540.validator.core.Validator;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;
import org.hibernate.annotations.Target;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.data.domain.AbstractAggregateRoot;

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
import java.util.Collection;
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
    @AttributeOverride(name = "value", column = @Column(name = "email", length = 128))
    private UserEmail email;

    @Embedded
    @Target(value = UserEncryptedPassword.class)
    @AttributeOverride(name = "password", column = @Column(name = "password", length = 64, nullable = false))
    private UserPassword password;

    @Embedded
    @AttributeOverrides(value = {
            @AttributeOverride(name = "keyValue", column = @Column(name = "credentials_key", length = 32)),
            @AttributeOverride(name = "expiryDateTime", column = @Column(name = "credentials_key_expiry_datetime"))
    })
    private UserCredentialsKey credentialsKey;

    @ElementCollection
    @CollectionTable(name = "user_authority", joinColumns = @JoinColumn(name = "email", nullable = false))
    @AttributeOverride(name = "value", column = @Column(name = "authority_code", length = 32, nullable = false))
    private Set<AuthorityCode> authorities;


    @Embedded
    @AttributeOverrides(value = {
            @AttributeOverride(name = "keyValue", column = @Column(name = "password_credentials_key", length = 32)),
            @AttributeOverride(name = "expiryDateTime", column = @Column(name = "password_credentials_key_expiry_datetime"))
    })
    private UserCredentialsKey passwordCredentialsKey;

    @CreationTimestamp
    @Column(name = "registered_at", nullable = false)
    private LocalDateTime registeredAt;

    @UpdateTimestamp
    @Column(name = "last_updated_at", nullable = false)
    private LocalDateTime lastUpdatedAt;

    public User(String email, String password, UserPasswordEncoder encoder) {
        this.email = new UserEmail(email);
        this.password = new UserRawPassword(password);

        Validator.of(this).registerRule(new UserEmailValidationRule())
                .registerRule(new UserPasswordValidationRule())
                .getResult().hasErrorThrows(UserInvalidException::new);
        encrypted(encoder);
        registerEvent(new UserRegisterEvent(this.email));
    }

    public void generateCredentialsKey(UserCredentialsKeyGenerator keyGenerator) {
        if (this.authorities != null && !this.authorities.isEmpty()) {
            throw new UserAlreadyCertificationException("this account is already certification");
        }
        this.credentialsKey = keyGenerator.generateKey();
        registerEvent(new UserGeneratedCredentialsKeyEvent(email, credentialsKey));
    }

    public void credentials(String credentialsKey, Collection<AuthorityCode> authorities) {
        UserKeyMatchedResult matchedResult = Optional.ofNullable(this.credentialsKey)
                .map(key -> key.matches(credentialsKey))
                .orElseThrow(() -> new UserNotMatchedException("key is not matched"));
        assertMatchedResult(matchedResult);
        this.authorities = new HashSet<>(authorities);
        this.credentialsKey = null;
    }

    public void changePassword(String existsPassword, String changePassword, UserPasswordEncoder encoder) {
        if (!encoder.matches(password, new UserRawPassword(existsPassword))) {
            throw new UserNotMatchedException("existing password is not matched");
        }
        changePassword(changePassword, encoder);
    }

    public void forgotPassword(UserCredentialsKeyGenerator keyGenerator) {
        this.passwordCredentialsKey = keyGenerator.generateKey();
        registerEvent(new UserGeneratedPasswordCredentialsKeyEvent(email, passwordCredentialsKey));
    }

    public void resetPassword(String passwordCredentialsKey, String changePassword, UserPasswordEncoder encoder) {
        UserKeyMatchedResult matchedResult = Optional.ofNullable(this.passwordCredentialsKey)
                .map(key -> key.matches(passwordCredentialsKey))
                .orElseThrow(() -> new UserNotMatchedException("key is not matched"));
        assertMatchedResult(matchedResult);
        changePassword(changePassword, encoder);
        this.passwordCredentialsKey = null;
    }

    private void changePassword(String changePassword, UserPasswordEncoder encoder) {
        this.password = new UserRawPassword(changePassword);
        Validator.of(this).registerRule(new UserPasswordValidationRule())
                .getResult().hasErrorThrows(UserInvalidException::new);
        encrypted(encoder);
    }

    private void encrypted(UserPasswordEncoder encoder) {
        this.password = this.password.encrypted(encoder);
    }

    private void assertMatchedResult(UserKeyMatchedResult matchedResult) {
        if (matchedResult.equals(UserKeyMatchedResult.NOT_MATCHED)) {
            throw new UserNotMatchedException("key is not matched");
        } else if (matchedResult.equals(UserKeyMatchedResult.EXPIRED)) {
            throw new UserExpiredException("key is expired");
        }
    }
}
