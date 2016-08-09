package uk.ac.cam.lib.spring.security.raven;


import org.springframework.security.core.Authentication;

/**
 * A hook to allow applications to customise the Authentication objects returned
 * by {@link RavenAuthenticationProvider} upon successful login attempts.
 */
public interface AuthenticatedRavenTokenCreator {
    /**
     * Create an Authentication object to represent the logged-in user.
     *
     * The returned authentication object must be authenticated
     * ({@link Authentication#isAuthenticated()}).
     *
     * @param validatedToken A valid Raven login request.
     * @return The Authentication object to use.
     */
    Authentication createAuthenticatedToken(RavenAuthenticationToken validatedToken);
}
