package cube8540.oauth.authentication.users.domain;

public interface UserPassword {

    String getPassword();

    boolean isEncrypted();

    boolean isValid();

    UserPassword encrypted(UserPasswordEncoder encoder);

}
