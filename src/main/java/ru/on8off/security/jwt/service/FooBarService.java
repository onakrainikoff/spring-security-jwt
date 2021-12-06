package ru.on8off.security.jwt.service;

import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class FooBarService {

    public String getForAdmin(){
        return "OK";
    }

    public String getForAdminWithPermissions(List<String> groups){
        if(groups.contains("GROUP_ADMINS") || groups.contains("GROUP_PROJECT_1")) {
            return "ALL DATA";
        } else {
            return null;
        }
    }

    public String getForUser(){
        return "OK";
    }

    public String getForUserWithPermissions(List<String> groups){
        if(groups.contains("GROUP_ADMINS") || groups.contains("GROUP_PROJECT_1")) {
            return "ALL DATA";
        } else {
            return null;
        }
    }


}
