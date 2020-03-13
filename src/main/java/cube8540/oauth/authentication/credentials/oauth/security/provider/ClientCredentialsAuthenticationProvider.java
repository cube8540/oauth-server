package cube8540.oauth.authentication.credentials.oauth.security.provider;

import cube8540.oauth.authentication.credentials.oauth.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.OAuth2ClientDetailsService;
import cube8540.oauth.authentication.credentials.oauth.client.domain.exception.ClientNotFoundException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;

public class ClientCredentialsAuthenticationProvider implements AuthenticationProvider {

    private final OAuth2ClientDetailsService service;
    private final PasswordEncoder encoder;

    public ClientCredentialsAuthenticationProvider(OAuth2ClientDetailsService service, PasswordEncoder encoder) {
        this.service = service;
        this.encoder = encoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        try {
            if (authentication.getPrincipal() == null || authentication.getCredentials() == null) {
                throw new BadCredentialsException("principal and credentials is required");
            }

            OAuth2ClientDetails client = service.loadClientDetailsByClientId(authentication.getPrincipal().toString());
            String givenSecret = authentication.getCredentials().toString();
            if (!encoder.matches(givenSecret, client.getClientSecret())) {
                throw new BadCredentialsException("secret does not match stored value");
            }
            return new ClientCredentialsToken(client, client.getClientSecret(), Collections.emptyList());
        } catch (ClientNotFoundException e) {
            throw new BadCredentialsException(e.getMessage());
        } catch (BadCredentialsException | InternalAuthenticationServiceException e) {
            throw e;
        }catch (Exception e) {
            throw new InternalAuthenticationServiceException(e.getMessage(), e);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return ClientCredentialsToken.class.isAssignableFrom(authentication);
    }
}
