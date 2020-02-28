package com.vilin.springboot.security.security;

import com.vilin.springboot.security.authentication.SecurityAuthenticationFailureHandler;
import com.vilin.springboot.security.authentication.SecurityAuthenticationSuccessHandler;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

//@Configuration
@EnableWebSecurity
public class SpringBootSecurityConfig extends WebSecurityConfigurerAdapter {
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//                .antMatchers("/product/add").hasAuthority("ROLE_PRODUCT_ADD")
//                .antMatchers("/product/delete").hasAuthority("ROLE_PRODUCT_DELETE")
//                .antMatchers("/product/update").hasAuthority("ROLE_PRODUCT_UPDATE")
//                .antMatchers("/product/list").hasAuthority("ROLE_PRODUCT_LIST")
//                .antMatchers("/login").permitAll()
//                .antMatchers("/**").fullyAuthenticated()
//                .and()
//                .formLogin()
//                .loginProcessingUrl("/securityLogin")
//                .loginPage("/login")
//                .and()
//                .csrf().disable();
//    }
//
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication()
//                .passwordEncoder(new BCryptPasswordEncoder())
//                .withUser("lwei")
//                .password(new BCryptPasswordEncoder().encode("123456"))
//                .authorities("ROLE_PRODUCT_ADD", "ROLE_PRODUCT_DELETE");
//    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //任意请求需要认证
        http.authorizeRequests().anyRequest().authenticated()
                //开启form表单验证，自定义自己的认真表单页面，同时permitAll对该认证表单不设防
                .and().formLogin().loginPage("/myLogin.html").loginProcessingUrl("/login")
                .successHandler(new SecurityAuthenticationSuccessHandler())
                .failureHandler(new SecurityAuthenticationFailureHandler())
                .permitAll()
                //关闭csrf
                .and().csrf().disable();
    }
}
