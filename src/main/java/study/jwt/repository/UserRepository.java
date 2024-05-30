package study.jwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import study.jwt.entity.UserEntity;

public interface UserRepository extends JpaRepository<UserEntity, Integer> {

    Boolean existsByUsername(String username);

    UserEntity findByUsername(String username);
}
