package ru.on8off.security.jwt.repository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import javax.annotation.PostConstruct;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Repository
public class DomainUserInMemoryRepository {
    private Map<String, DomainUser> userStore = new HashMap<>();
    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostConstruct
    public void init(){
        userStore.put("admin", new DomainUser("admin", passwordEncoder.encode("admin123"), List.of("ROLE_ADMIN"), List.of("GROUP_ADMINS")));
        userStore.put("user", new DomainUser("user", passwordEncoder.encode("user123"), List.of("ROLE_USER"), List.of("GROUP_PROJECT_1")));
        userStore.put("user2", new DomainUser("user2", passwordEncoder.encode("user123"), List.of("ROLE_USER"), List.of("GROUP_PROJECT_2")));
    }

    public DomainUser getDomainUser(String username){
        return userStore.get(username);
    }

}
