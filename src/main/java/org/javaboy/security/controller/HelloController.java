package org.javaboy.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/hello")
    public String hello(){
        return "hello";
    }

    @GetMapping("/admin/hello")
    public String adminHello(){
        return "admin";
    }

    @GetMapping("/user/hello")
    public String userHello(){
        return "user";
    }
}
