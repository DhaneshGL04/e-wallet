package com.github.Dhanesh.repository;

import com.github.Dhanesh.model.Role;
import com.github.Dhanesh.model.RoleType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Set;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

    List<Role> getReferenceByTypeIsIn(Set<RoleType> types);
}
