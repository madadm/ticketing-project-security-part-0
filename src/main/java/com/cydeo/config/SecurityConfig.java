package com.cydeo.config;

import com.cydeo.service.SecurityService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class SecurityConfig {


    private final SecurityService securityService;
    private final AuthSuccessHandler authSuccessHandler;

    public SecurityConfig(SecurityService securityService, AuthSuccessHandler authSuccessHandler) {
        this.securityService = securityService;
        this.authSuccessHandler = authSuccessHandler;
    }
//    @Bean
//    public UserDetailsService userDetailsService(PasswordEncoder encoder){
//
//        List<UserDetails> userList = new ArrayList<>();
//
//        userList.add(
//                new User("mike", encoder.encode("password"), Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN")))
//        );
//        userList.add(
//        new User("ozzy", encoder.encode("password"), Arrays.asList(new SimpleGrantedAuthority("ROLE_MANAGER")))
//        );
//
//        return new InMemoryUserDetailsManager(userList);
//    }



    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeRequests()
                .antMatchers("/user/**").hasAnyAuthority("Admin")
                .antMatchers("/project/**").hasAnyAuthority("Manager")
                .antMatchers("/task/employee/**").hasAnyAuthority("Employee")
                .antMatchers("/task/**").hasAnyAuthority("Manager")
                //.antMatchers("/user/**").hasRole("ADMIN")
//                .antMatchers("/project/**").hasRole("MANAGER")
//                .antMatchers("/task/employee/**").hasRole("EMPLOYEE")
//                .antMatchers("/task/**").hasRole("MANAGER")
                .antMatchers(
                        "/",
                        "/login",
                        "/fragments/**",
                        "/assets/**",
                        "/images/**",
                        "/welcome"
                ).permitAll()
                .anyRequest().authenticated()
                .and()
//                .httpBasic()
                    .formLogin()
                    .loginPage("/login")
                    //.defaultSuccessUrl("/welcome")
                .successHandler(authSuccessHandler)
                    .failureUrl("/login?error=true")
                    .permitAll()
                .and()
                    .logout()
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                    .logoutSuccessUrl("/login")
                .and()
                    .rememberMe()
                    .tokenValiditySeconds(120)
                    .key("cydeo")
                .userDetailsService(securityService)
                .and()
                    .build();
    }
}
