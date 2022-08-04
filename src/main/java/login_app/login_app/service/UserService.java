package login_app.login_app.service;

import login_app.login_app.domaine.Groupe;
import login_app.login_app.domaine.Role;
import login_app.login_app.domaine.User;
import login_app.login_app.repository.GroupeRepo;
import login_app.login_app.repository.RoleRepo;
import login_app.login_app.repository.UserRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.naming.NamingException;
import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service @RequiredArgsConstructor @Transactional @Slf4j
public class UserService implements UserServiceInterface {

    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final GroupeRepo groupeRepo;
    private final LdapService ldapService;





    @Override
    public User saveUser(User user) {

        log.info("saving new user {} to database", user.getName());
        return userRepo.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("saving new role {} to database",role.getName());

        return roleRepo.save(role);
    }
    @Override
    public Groupe saveGroup(Groupe group) {
        log.info("saving new group {} to database",group.getName());

        return groupeRepo.save(group);
    }


    @Override
    public void addRoleToUser(String username, String roleName) {
        log.info("adding role {} to user {}",username,roleName);
        User user = userRepo.findByUsername(username);
        Role role = roleRepo.findByName(roleName);
        user.getRoles().add(role);
    }

    @Override
    public void addGroupToUser(String username, String groupName) {
        log.info("adding group {} to user {}",username,groupName);
        User user = userRepo.findByUsername(username);
        Groupe groupe = groupeRepo.findByName(groupName);
        user.getGroups().add(groupe);
    }
    @Override
    public User getUser(String username) {
        log.info("getting a user {}", username);
        return userRepo.findByUsername(username);
    }

    @Override
    public List<User> getUsers() throws NamingException {
        log.info("getting all users");
        List<User> users=  userRepo.findAll();
        users.forEach(user ->{
            try {
                List<String> ldapGroups = ldapService.getLdapGroups(user.getUsername());
                    user.setLdapGroups(ldapGroups);

            } catch (NamingException e) {
                throw new RuntimeException(e);
            }
        });
        return users;

    }



}
