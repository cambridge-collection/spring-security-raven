package uk.ac.cam.lib.spring.security.raven.hooks;


import com.google.common.collect.ImmutableSet;
import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import uk.ac.cam.lib.spring.security.raven.RavenAuthenticationToken;

import java.util.Set;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class UserDetailsRavenTokenCreatorTest {

    @Test
    public void testCreateAuthenticationToken() {
        Set<GrantedAuthority> authorities = ImmutableSet.of(
            new SimpleGrantedAuthority("foo"),
            new SimpleGrantedAuthority("bar"));

        User u = new User("hwtb2", "password", authorities);
        UserDetailsService uds = mock(UserDetailsService.class);

        when(uds.loadUserByUsername("hwtb2")).thenReturn(u);

        RavenAuthenticationToken mockResultToken =
            mock(RavenAuthenticationToken.class);

        RavenAuthenticationToken token = mock(RavenAuthenticationToken.class);
        when(token.isAuthenticated()).thenReturn(false);
        when(token.getPrincipal()).thenReturn("hwtb2");
        when(token.authenticate(u, authorities)).thenReturn(mockResultToken);

        RavenAuthenticationToken resultToken =
            (RavenAuthenticationToken)new UserDetailsRavenTokenCreator(uds)
                .createAuthenticatedToken(token);

        verify(uds).loadUserByUsername("hwtb2");
        verify(token, atLeastOnce()).getPrincipal();
        verify(token, times(1)).authenticate(u, authorities);
        assertThat(resultToken, is(sameInstance(mockResultToken)));
    }
}
