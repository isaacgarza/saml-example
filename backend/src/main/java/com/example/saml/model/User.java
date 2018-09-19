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
package com.example.saml.model;

public class User {

    private String role;

    private User(UserBuilder userBuilder) {
        this.role = userBuilder.role;
    }

    public String getRole() {
        return role;
    }

    public static class UserBuilder {

        private String role;

        public UserBuilder() {
            //empty constructor
        }

        public UserBuilder withRole(String role) {
            this.role = role;
            return this;
        }

        public User build() {
            return new User(this);
        }
    }
}