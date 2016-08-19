package uk.ac.cam.lib.spring.security.raven;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.Assert;
import uk.ac.cam.ucs.webauth.WebauthException;
import uk.ac.cam.ucs.webauth.WebauthRequest;
import uk.ac.cam.ucs.webauth.WebauthResponse;
import uk.ac.cam.ucs.webauth.WebauthValidator;

import java.time.Instant;
import java.util.Optional;

/**
 * Validates {@link RavenAuthenticationToken}s for a {@link ProviderManager}.
 */
public class RavenAuthenticationProvider implements AuthenticationProvider {

    private WebauthValidator validator;
    private AuthenticatedRavenTokenCreator tokenCreator;

    public RavenAuthenticationProvider(
        WebauthValidator validator,
        AuthenticatedRavenTokenCreator tokenCreator) {

        Assert.notNull(validator);
        Assert.notNull(tokenCreator);

        this.validator = validator;
        this.tokenCreator = tokenCreator;
    }

    public WebauthValidator getWebauthValidator() {
        return this.validator;
    }

    public AuthenticatedRavenTokenCreator getTokenCreator() {
        return this.tokenCreator;
    }

    /**
     * {@inheritDoc}
     *
     * @throws IllegalStateException if the
     *         {@link AuthenticatedRavenTokenCreator} returns an unauthenticated
     *         token.
     */
    @Override
    public Authentication authenticate(Authentication authentication)
        throws AuthenticationException {

        assert this.supports(authentication.getClass());

        RavenAuthenticationToken token =
            (RavenAuthenticationToken)authentication;

        WebauthRequest request = token.getRavenRequest()
            .orElseThrow(this::reportClearedCredentials);
        WebauthResponse response = token.getRavenResponse()
            .orElseThrow(this::reportClearedCredentials);
        Instant authResponseTimestamp = token.getResponseReceivedTime()
            .orElseThrow(this::reportClearedCredentials);

        Optional<Integer> status = Optional.empty();
        try {
            status = Optional.of(response.getInt("status"));
            getWebauthValidator().validate(
                request, response, authResponseTimestamp.toEpochMilli());
        }
        catch(WebauthException e) {
            if(status.isPresent() && status.get() != WebauthResponse.SUCCESS) {
                throw new BadStatusRavenAuthenticationException(
                    status.get(), e);
            }

            throw new RavenAuthenticationException(
                "Raven auth response did not validate", e);
        }

        Authentication result = getTokenCreator()
            .createAuthenticatedToken(token);

        if(!result.isAuthenticated())
            throw new IllegalStateException(String.format(
                "AuthenticatedRavenTokenCreator returned an unauthenticated " +
                "token. creator: %s, token: %s", getTokenCreator(), result));

        return result;
    }

    private RavenAuthenticationException reportClearedCredentials() {
        return new RavenAuthenticationException(
            "Credentials have been erased before authentication");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return RavenAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
