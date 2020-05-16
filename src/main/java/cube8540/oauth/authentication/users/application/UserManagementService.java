package cube8540.oauth.authentication.users.application;

public interface UserManagementService {

    Long countUser(String username);

    UserProfile loadUserProfile(String username);

    UserProfile registerUser(UserRegisterRequest registerRequest);

    UserProfile removeUser(String username);

}
