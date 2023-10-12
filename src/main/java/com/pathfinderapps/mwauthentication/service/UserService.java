package com.pathfinderapps.mwauthentication.service;

import java.util.List;
import java.util.Map;

import com.pathfinderapps.mwauthentication.model.Role;
import com.pathfinderapps.mwauthentication.model.User;

public interface UserService {
	User saveUser(User user);
	Role saveRole(Role role);
	void addRoleToUser(String username, String roleName);
	User getUser(String username);
	List<User> getUsers();
	Map<String,String> login(String username, String password) throws Exception;
}
