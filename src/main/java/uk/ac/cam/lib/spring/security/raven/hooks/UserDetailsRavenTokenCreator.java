package uk.ac.cam.lib.spring.security.raven.hooks;


import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.util.Assert;
import uk.ac.cam.lib.spring.security.raven.AuthenticatedRavenTokenCreator;
import uk.ac.cam.lib.spring.security.raven.RavenAuthenticationToken;

/**
 * An {@link AuthenticatedRavenTokenCreator} which uses {@link UserDetails}
 * instances (obtained from a {@link UserDetailsService}) to create
 * authenticated {@link RavenAuthenticationToken}s.
 */
public class UserDetailsRavenTokenCreator
    implements AuthenticatedRavenTokenCreator {

    private final UserDetailsService userDetailsService;

    public UserDetailsRavenTokenCreator(UserDetailsService userDetailsService) {
        Assert.notNull(userDetailsService);

        this.userDetailsService = userDetailsService;
    }

    public UserDetailsService getUserDetailsService() {
        return this.userDetailsService;
    }

    @Override
    public Authentication createAuthenticatedToken(
        RavenAuthenticationToken validatedToken) {

        Assert.isTrue(!validatedToken.isAuthenticated());

        UserDetails details = getUserDetailsService().loadUserByUsername(
            this.getUsername(validatedToken));

        return this.createTokenFromUserDetails(validatedToken, details);
    }

    /**
     * Get the username from the token. Can be overridden by subclasses to
     * modify usernames.
     *
     * This implementation returns the string representation of the token's
     * principal. By default this will be the value of "principal" field of the
     * Raven auth response, which in turn is the user's CRSid.
     *
     * @param token The token to get the username for.
     * @return The username.
     */
    protected String getUsername(RavenAuthenticationToken token) {
        // The default for an unauthenticated token
        return token.getPrincipal().toString();
    }

    /**
     * Create an authenticated version of the unauthenticated token, using the
     * specified UserDetails instance. Can be overridden to customise the
     * Authentication object.
     */
    protected Authentication createTokenFromUserDetails(
        RavenAuthenticationToken previous, UserDetails details) {

        return previous.authenticate(details, details.getAuthorities());
    }
}
