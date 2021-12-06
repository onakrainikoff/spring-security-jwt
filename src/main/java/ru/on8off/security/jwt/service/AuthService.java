package ru.on8off.security.jwt.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.stereotype.Service;
import ru.on8off.security.jwt.repository.DomainUserInMemoryRepository;

import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
public class AuthService implements UserDetailsService {
    @Autowired
    private DomainUserInMemoryRepository domainUserInMemoryRepository;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Value("${jwt.secret}")
    private String jwtSecret;
    @Value("${jwt.expirationms}")
    private Long jwtExpirationMs;


    public String login(String username, String  password){
        var user = (User)authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password)).getPrincipal();
        var authorities = user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));
       return JWT.create().withSubject(user.getUsername())
                .withClaim("authorities", authorities)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + jwtExpirationMs))
               .sign(Algorithm.HMAC512(jwtSecret));
    }

    public void authenticate(String jwtString, WebAuthenticationDetails details) {
        DecodedJWT jwt;
        try {
            jwt = JWT.require(Algorithm.HMAC512(jwtSecret)).build().verify(jwtString);
        } catch (Exception e) {
            throw new SessionAuthenticationException("Invalid JWT token: "+ e.getMessage());
        }
        var username = jwt.getSubject();
        var roles = Arrays.stream(jwt.getClaim("authorities").asString().split(","))
                          .map(SimpleGrantedAuthority::new).collect(Collectors.toList());

        var user = new User(username, "", roles);
        var auth =  new UsernamePasswordAuthenticationToken(user, "", user.getAuthorities());
        auth.setDetails(details);
        SecurityContextHolder.getContext().setAuthentication(auth);
    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        var domainUser = domainUserInMemoryRepository.getDomainUser(username);
        if (domainUser == null) {
            throw new UsernameNotFoundException("Username" + username + " fot found");
        }
        var authorities = Stream.concat(domainUser.getRoles().stream(), domainUser.getGroups().stream())
                .map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        return new User(domainUser.getUsername(), domainUser.getPassword(), authorities);
    }

    public List<String> getGroups(){
        return SecurityContextHolder.getContext().getAuthentication().getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(a -> a.startsWith("GROUP_"))
                .collect(Collectors.toList());
    }


}
