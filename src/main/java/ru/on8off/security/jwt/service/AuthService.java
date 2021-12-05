package ru.on8off.security.jwt.service;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
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
        Claims claims = Jwts.claims().setSubject(user.getUsername());
        var authorities = user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));
        claims.put("authorities", authorities);
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .signWith(SignatureAlgorithm.HS256, jwtSecret)
                .compact();
    }

    public void authenticate(String jwtString, WebAuthenticationDetails details) {
        Claims claims;
        try {
            claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(jwtString).getBody();
        } catch (Exception e) {
            throw new SessionAuthenticationException("Invalid JWT token");
        }
        if(claims.getExpiration().before(new Date())){
            throw new CredentialsExpiredException("Jwt has been expired");
        }
        var username = claims.getSubject();
        var roles = Arrays.stream(claims.get("authorities", String.class).split(","))
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
        var authorities = Stream.concat(domainUser.getRoles().stream(), domainUser.getPermissions().stream())
                .map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        return new User(domainUser.getUsername(), domainUser.getPassword(), authorities);
    }

    public List<String> getPermissions(){
        return SecurityContextHolder.getContext().getAuthentication().getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(a -> a.startsWith("PERMISSION_"))
                .collect(Collectors.toList());
    }


}
