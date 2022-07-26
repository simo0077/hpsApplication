package login_app.login_app.domaine;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.ldap.odm.annotations.Attribute;
import org.springframework.ldap.odm.annotations.Entry;
import org.springframework.ldap.odm.annotations.Id;

import javax.lang.model.element.Name;
import javax.naming.ldap.LdapName;
import java.util.List;


@Entry(
        base = "ou=users",
        objectClasses = { "person", "inetOrgPerson", "top" })
@Data
@NoArgsConstructor
public class LdapUser {
    @Id
    private LdapName id;

    private @Attribute(name = "cn") String username;
    private @Attribute(name = "sn") String password;

    public LdapUser(String username, String encode) {
        this.username = username;
        this.password = encode;
    }


    // standard getters/setters
}