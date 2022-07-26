package login_app.login_app.service;

import login_app.login_app.domaine.Role;
import login_app.login_app.domaine.User;

import java.util.List;

public interface UserServiceInterface {
    User saveUser(User user);
    Role saveRole(Role role);
    void addRoleToUser(String username,String roleName);
    User getUser(String username);

    List<User> getUsers();
}
