package org.javaboy.security.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
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

    @GetMapping("login")
    public String login(){
        return "login";
    }

    public static void main(String[] args) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        for (int i=0;i<10;i++){
            System.out.println(encoder.encode("123"));
        }
    }

}
