package com.vilin.springboot.security.security;

import com.vilin.springboot.security.authentication.SecurityAuthenticationFailureHandler;
import com.vilin.springboot.security.authentication.SecurityAuthenticationSuccessHandler;
import com.vilin.springboot.security.filter.VerificationCodeFilter;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

//@Configuration
@EnableWebSecurity
@MapperScan("com.vilin.springboot.security.mapper")
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


//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        //任意请求需要认证
//        http.authorizeRequests().anyRequest().authenticated()
//                //开启form表单验证，自定义自己的认真表单页面，同时permitAll对该认证表单不设防
//                .and().formLogin().loginPage("/myLogin.html").loginProcessingUrl("/login")
//                .successHandler(new SecurityAuthenticationSuccessHandler())
//                .failureHandler(new SecurityAuthenticationFailureHandler())
//                .permitAll()
//                //关闭csrf
//                .and().csrf().disable();
//    }

//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//                .antMatchers("/admin/api/**").hasRole("ADMIN")
//                .antMatchers("/user/api/**").hasRole("USER")
//                .antMatchers("/app/api/**").permitAll()
//                .anyRequest().authenticated()
//                .and()
//                .formLogin().permitAll();
//    }

//    @Bean
//    public UserDetailsService userDetailsService() {
//        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
//        manager.createUser(User.withUsername("user").password("123").roles("USER").build());
//        manager.createUser(User.withUsername("admin").password("123").roles("USER", "ADMIN").build());
//        return manager;
//    }

//    @Autowired
//    private DataSource dataSource;

//    @Bean
//    public UserDetailsService userDetailsService() {
//        JdbcUserDetailsManager manager = new JdbcUserDetailsManager();
//        manager.setDataSource(dataSource);
//        if (!manager.userExists("user")) {
//            manager.createUser(User.withUsername("user").password("123").roles("USER").build());
//        }
//        if (!manager.userExists("admin")) {
//            manager.createUser(User.withUsername("admin").password("123").roles("USER", "ADMIN").build());
//        }
//        return manager;
//    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/admin/api/**").hasRole("ADMIN")
                .antMatchers("/user/api/**").hasRole("USER")
                .antMatchers("/app/api/**", "/captcha.jpg").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .failureHandler(new SecurityAuthenticationFailureHandler())
                .successHandler(new SecurityAuthenticationSuccessHandler())
                .loginPage("/myLogin.html")
                .loginProcessingUrl("/login")
                .permitAll()
                .and()
                .csrf().disable();
        // 将过滤器添加在UsernamePasswordAuthenticationFilter之前
        http.addFilterBefore(new VerificationCodeFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
