package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserRepository;
import cube8540.oauth.authentication.users.domain.Username;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class DefaultUserService implements UserDetailsService {

    private final UserRepository repository;

    @Autowired
    public DefaultUserService(UserRepository repository) {
        this.repository = repository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = repository.findByUsername(new Username(username))
                .orElseThrow(() -> new UsernameNotFoundException(username + " is not found"));

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getEmail().getValue()).password(user.getPassword())
                .accountLocked(!user.isCredentials()).authorities(Collections.emptySet())
                .build();
    }
}
