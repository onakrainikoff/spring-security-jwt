package ru.on8off.security.jwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RestController;
import ru.on8off.security.jwt.service.FooBarService;

import java.util.List;

@RestController
public class FooBarController {
    @Autowired
    private FooBarService fooBarService;

    @GetMapping("/getForAdmin")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String getForAdmin(){
        return fooBarService.getForAdmin();
    }

    @GetMapping("/getForAdminWithPermissions")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String getForAdminSecured(@RequestAttribute List<String> permissions){
        return fooBarService.getForAdminWithPermissions(permissions);
    }

    @GetMapping("/getForUser")
    @PreAuthorize("hasRole('ROLE_USER')")
    public String getForUser(){
        return fooBarService.getForUser();
    }

    @GetMapping("/getForUserWithPermissions")
    @PreAuthorize("hasRole('ROLE_USER')")
    public String getForUserWithPermissions(@RequestAttribute List<String> permissions){
        return fooBarService.getForUserWithPermissions(permissions);
    }

}
