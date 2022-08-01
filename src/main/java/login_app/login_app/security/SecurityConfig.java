package login_app.login_app.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import login_app.login_app.domaine.Role;
import login_app.login_app.filter.CustomAuthorizationFilter;
import login_app.login_app.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.ldap.userdetails.LdapUserDetailsImpl;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Configuration
@Slf4j
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final UserService userService ;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.csrf().disable();
        http.authorizeRequests().antMatchers("/api/login/**", "/api/token/refresh/**").permitAll()
        .antMatchers(GET,"/api/users/**").hasAnyAuthority("ROLE_ADMIN");
        http.authorizeRequests().anyRequest().authenticated()
                .and().formLogin()
                .loginProcessingUrl("/api/login")
                .successHandler(new AuthenticationSuccessHandler() {

                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                                        Authentication authentication) throws IOException, ServletException {
                        LdapUserDetailsImpl user = (LdapUserDetailsImpl) authentication.getPrincipal();
                        log.info(user.getUsername());
                        login_app.login_app.domaine.User user1 = userService.getUser(user.getUsername());
                        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
                        String access_token = JWT.create()
                                .withSubject(user1.getUsername())
                                .withExpiresAt(new Date(System.currentTimeMillis()+10*60*1000))
                                .withIssuer(request.getRequestURL().toString())
                                .withClaim("roles",user1.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                                .sign(algorithm);

                        String refresh_token = JWT.create()
                                .withSubject(user.getUsername())
                                .withExpiresAt(new Date(System.currentTimeMillis()+30*60*1000))
                                .withIssuer(request.getRequestURL().toString())
                                .sign(algorithm);


                        Map<String,String> tokens = new HashMap<>();
                        tokens.put("access_token",access_token);
                        tokens.put("refresh_token",refresh_token);
                        response.setContentType(APPLICATION_JSON_VALUE);
                        new ObjectMapper().writeValue(response.getOutputStream(),tokens);
                    }
                });


        http.addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .ldapAuthentication()
                .userDnPatterns("uid={0},ou=people")
                .groupSearchBase("ou=groups")
                .contextSource()
                .url("ldap://localhost:8389/dc=springframework,dc=org")
                .and()
                .passwordCompare()
                .passwordEncoder(new BCryptPasswordEncoder())
                .passwordAttribute("userPassword");
    }

}
