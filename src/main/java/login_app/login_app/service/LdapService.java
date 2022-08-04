package login_app.login_app.service;

import org.springframework.stereotype.Service;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
@Service
public class LdapService {
    DirContext context;
    public void newConnection() {
        Properties env = new Properties();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:10389");
        env.put(Context.SECURITY_PRINCIPAL, "uid=admin, ou=system");
        env.put(Context.SECURITY_CREDENTIALS, "secret");
        try {
            context = new InitialDirContext(env);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    public List<String> getLdapGroups(String username) throws NamingException {
        newConnection();
        String searchFilter = ("objectClass=groupOfUniqueNames");
        String[] requiredAtt = {"cn","uniqueMember"};
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setReturningAttributes(requiredAtt);
        NamingEnumeration groups = context.search("ou=groups,dc=example,dc=com",searchFilter,controls);
        SearchResult results = null;
        String groupName= null;

        List<String> usergroups = new ArrayList<>();
        while(groups.hasMore()){
            results = (SearchResult) groups.next();
            Attributes attr = results.getAttributes();
            groupName = attr.get("cn").get(0).toString();
            for(int i = 0;i<attr.get("uniqueMember").size();i++){
                if(attr.get("uniqueMember").get(i).toString().contains(username)){
                    usergroups.add(groupName);
                    System.out.println(groupName);

                    break;
                }
            }

        }
        return usergroups;
    }
}
