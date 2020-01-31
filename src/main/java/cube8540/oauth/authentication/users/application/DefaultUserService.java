package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserEmail;
import cube8540.oauth.authentication.users.domain.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class DefaultUserService implements UserDetailsService {

    private final UserRepository repository;

    @Autowired
    public DefaultUserService(UserRepository repository) {
        this.repository = repository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = repository.findByEmail(new UserEmail(username))
                .orElseThrow(() -> new UsernameNotFoundException(username + " is not found"));

        Set<GrantedAuthority> authorities = Optional.ofNullable(user.getAuthorities()).orElse(Collections.emptySet())
                .stream().map(auth -> new SimpleGrantedAuthority(auth.getValue()))
                .collect(Collectors.toSet());
        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getEmail().getValue()).password(user.getPassword().getPassword())
                .accountLocked(authorities.isEmpty()).authorities(authorities)
                .build();
    }
}
