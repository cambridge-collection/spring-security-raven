# Spring Security Raven

This library implements support for authentication with Ucam Webauth (Raven)
using the auth patterns used by Spring Security.

## Spring Security auth patterns

As a quick guide, the following are the main parts of Spring Security's typical
pattern for authentication and how it maps onto this library.

### Entry points

`AuthenticationEntryPoint`s are responsible for starting the authentication
exchange with the user. These are typically invoked by Spring Security's
`ExceptionTranslationFilter` which catches auth exceptions thrown by higher
level code, and may decide to initiate a login exchange (using the entry point)

`RavenAuthenticationEntryPoint` implements such an entry point, which works
by redirecting users to the Raven login page with an appropriate return URL.

### Authentication filters

Auth filters, typically subclassing `AbstractAuthenticationProcessingFilter`
are responsible for handling the results of user auth exchanges. In our case,
this means handling URLs with a `WLS-Response` query parameter, which is how
Raven communicates back authentication results to the application.

The class implementing such a filter is `RavenAuthenticationFilter`.

### Authentication tokens

Auth filters typically work by constructing an auth token from the credentials
obtained by the filter, passing off the token to another component to be
authenticated. This library is no different, and the auth filter constructs a
`RavenAuthenticationToken` containing the auth response from Raven.

### Authentication providers

In Spring Security, auth tokens are authenticated by `AuthenticationManager`
implementations. The most common of these is the `ProviderManager` which
delegates to one or more `AuthenticationProvider` objects depending on the type
of token to be authenticated. A `RavenAuthenticationProvider` is provided to
authenticate the `RavenAuthenticationToken`s.

### Authenticated token creators

The `AuthenticatedRavenTokenCreator` interface is specific to this library. It's
implementations are responsible for creating an authenticated version of the
RavenAuthenticationTokens. A sample implementation is provided which uses a
Spring Security `UserDetailsService` object to lookup `UserDetails` instances
based on the CRSid provided in the auth response from Raven.

### Raven request creators

Another interface specific to this library is `RavenRequestCreator`. It's
responsible for constructing an auth request to Raven for a given HTTP request.

It's used for two things. Firstly, the entry point uses it to construct an auth
request for a given URL. Secondly, it's used by the auth filter to reconstruct
the request that would have been sent for a given URL. This is required as
validation of auth responses requires knowledge of the parameters that would have
been sent to Raven for a given URL. (e.g. to ensure that the auth request was
not tampered with, e.g. to turn off the flag which requires a password exchange
with the user.)
