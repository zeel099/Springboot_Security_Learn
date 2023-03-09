package com.learn.services;

import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Service;

import com.learn.models.User;

@Service
public class UserService {

	List<User> list = new ArrayList<>();
	
	public UserService() {
		list.add(new User("zeel","123abc","abc9@gmail.com"));
		list.add(new User("raj","345abc","xyz9@gmail.com"));
		list.add(new User("sam","123xyz","pqr9@gmail.com"));
		
	}
	
	public List<User>getAllUsers(){
		return this.list;
	}
	
	public User getUser(String username) {
		return this.list.stream().filter((user)->user.getUsername().equals(username)).findAny().orElse(null);
	}
	
	

	public User addUser(User user) {
		this.list.add(user);
		return user;
	}
}
