package cube8540.oauth.authentication.users.domain;

public interface UserPasswordEncoder {

    String encoding(String password);

    boolean matches(UserPassword encryptedPassword, UserPassword rawPassword);

}
