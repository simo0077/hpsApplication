package login_app.login_app;

import login_app.login_app.domaine.LdapUser;
import login_app.login_app.domaine.Role;
import login_app.login_app.domaine.User;
import login_app.login_app.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.lang.model.element.Name;
import java.util.ArrayList;

@SpringBootApplication
public class LoginAppApplication {

	public static void main(String[] args) {
		SpringApplication.run(LoginAppApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run(UserService userService){
		return args -> {
			userService.saveRole(new Role(null,"ROLE_USER"));
			userService.saveRole(new Role(null,"ROLE_ADMIN"));

			userService.saveUser(new User(null,"ben","ben","benpassword",new ArrayList<>()));
			userService.saveUser(new User(null,"user2","user2","1234",new ArrayList<>()));

			userService.addRoleToUser("ben","ROLE_ADMIN");
			userService.addRoleToUser("user2","ROLE_USER");

		};
	}
}
