package login_app.login_app.repository;



import login_app.login_app.domaine.Groupe;
import org.springframework.data.jpa.repository.JpaRepository;

public interface GroupeRepo extends JpaRepository<Groupe,Long> {
    Groupe findByName(String name);
}
