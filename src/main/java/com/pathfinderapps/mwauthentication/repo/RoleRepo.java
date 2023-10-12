package com.pathfinderapps.mwauthentication.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import com.pathfinderapps.mwauthentication.model.Role;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepo extends JpaRepository<Role,Integer>{
	Role findByName(String name);
}
