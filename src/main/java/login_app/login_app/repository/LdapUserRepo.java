package login_app.login_app.repository;

import login_app.login_app.domaine.LdapUser;

import org.springframework.data.ldap.repository.LdapRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface LdapUserRepo extends LdapRepository<LdapUser> {
    LdapUser findByUsername(String username);
    LdapUser findByUsernameAndPassword(String username, String password);
    List<LdapUser> findByUsernameLikeIgnoreCase(String username);
}
