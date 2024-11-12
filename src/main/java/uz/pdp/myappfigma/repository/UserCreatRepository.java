package uz.pdp.myappfigma.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import uz.pdp.myappfigma.entity.AuthUser;

import java.util.Optional;

@Repository
public interface UserCreatRepository extends JpaRepository<AuthUser,Long> {

    Optional<AuthUser> findByEmail(String email);

    Boolean existsByEmail(String email);
}