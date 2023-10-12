package com.pathfinderapps.mwauthentication.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class JWTApp {

	@Id @GeneratedValue(strategy = GenerationType.AUTO)
	private Long id;
	private String refresh_token;
	private String access_token;
}
