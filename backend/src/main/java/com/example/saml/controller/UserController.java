/*
 * Copyright 2018 Isaac Garza
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.example.saml.controller;

import com.example.saml.model.User;
import com.example.saml.util.Constants;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/user")
public class UserController {

    @GetMapping("/role")
    public ResponseEntity<User> getUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        GrantedAuthority adminAuthority = new SimpleGrantedAuthority(Constants.ROLE_ADMIN);
        GrantedAuthority userAuthority = new SimpleGrantedAuthority(Constants.ROLE_USER);
        if (auth.getAuthorities().contains(adminAuthority)) {
            userAuthority = adminAuthority;
        }
        User user = new User.UserBuilder()
                .withRole(userAuthority.getAuthority())
                .build();
        return new ResponseEntity<>(user, HttpStatus.OK);
    }
}
