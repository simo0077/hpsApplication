package login_app.login_app.service;

import login_app.login_app.domaine.Groupe;
import login_app.login_app.domaine.Role;
import login_app.login_app.domaine.User;

import javax.naming.NamingException;
import java.util.List;

public interface UserServiceInterface {
    User saveUser(User user);
    Role saveRole(Role role);
    Groupe saveGroup(Groupe group);
    void addRoleToUser(String username,String roleName);
    void addGroupToUser(String username,String groupName);
    User getUser(String username);

    List<User> getUsers() throws NamingException;
}
