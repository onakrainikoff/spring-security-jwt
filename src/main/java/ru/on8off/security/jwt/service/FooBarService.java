package ru.on8off.security.jwt.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class FooBarService {
    @Autowired
    private AuthService authService;

    public String getForAdmin(){
        return "OK";
    }

    public String getForAdminWithPermissions(List<String> permissions){
        if(permissions.contains("PERMISSION_ALL") || permissions.contains("PERMISSION_PERMISSION_PROJECT_1")) {
            return "ALL DATA";
        } else {
            return null;
        }
    }

    public String getForUser(){
        return "OK";
    }

    public String getForUserWithPermissions(List<String> permissions){
        if(permissions.contains("PERMISSION_ALL") || permissions.contains("PERMISSION_PROJECT_1")) {
            return "ALL DATA";
        } else {
            return null;
        }
    }


}
