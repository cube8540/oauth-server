package cube8540.oauth.authentication.credentials.oauth.client.provider;

import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetailsService;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientNotFoundException;
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
            OAuth2ClientDetails client = service.loadClientDetailsByClientId(authentication.getPrincipal().toString());

            String givenSecret = authentication.getCredentials().toString();
            if (!encoder.matches(givenSecret, client.clientSecret())) {
                throw new BadCredentialsException("secret does not match stored value");
            }

            return new ClientCredentialsToken(client, authentication.getCredentials(), Collections.emptyList());
        } catch (OAuth2ClientNotFoundException e) {
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
