package com.vilin.springboot.security;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan("com.vilin.springboot.security.mapper")
public class SpringBootSecurityApp {
    public static void main(String[] args) {
        SpringApplication.run(SpringBootSecurityApp.class, args);
    }
}
