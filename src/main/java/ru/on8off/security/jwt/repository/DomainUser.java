package ru.on8off.security.jwt.repository;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class DomainUser {
    private String username;
    private String password;
    private List<String> roles;
    private List<String> groups;
 }
