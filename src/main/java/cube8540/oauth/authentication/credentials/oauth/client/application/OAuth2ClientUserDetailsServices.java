package cube8540.oauth.authentication.credentials.oauth.client.application;

import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetailsService;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientNotFoundException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collections;

public class OAuth2ClientUserDetailsServices implements UserDetailsService {
    private final OAuth2ClientDetailsService service;

    public OAuth2ClientUserDetailsServices(OAuth2ClientDetailsService service) {
        this.service = service;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        try {
            OAuth2ClientDetails details = service.loadClientDetailsByClientId(username);
            return new User(details.clientId(), details.clientSecret(), Collections.emptyList());
        } catch (OAuth2ClientNotFoundException e) {
            throw new UsernameNotFoundException(username + " client not found", e);
        }
    }
}
