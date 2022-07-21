package login_app.login_app;

import login_app.login_app.domaine.Role;
import login_app.login_app.domaine.User;
import login_app.login_app.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

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

			userService.saveUser(new User(null,"user1","user1","1234",new ArrayList<>()));
			userService.saveUser(new User(null,"user2","user2","1234",new ArrayList<>()));

			userService.addRoleToUser("user1","ROLE_ADMIN");
			userService.addRoleToUser("user2","ROLE_USER");

		};
	}
}
