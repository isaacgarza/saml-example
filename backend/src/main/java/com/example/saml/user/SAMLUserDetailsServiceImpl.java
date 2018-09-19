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
package com.example.saml.user;

import com.example.saml.util.Constants;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class SAMLUserDetailsServiceImpl implements SAMLUserDetailsService {
	private static final Logger LOGGER = LoggerFactory.getLogger(SAMLUserDetailsServiceImpl.class);

	public Object loadUserBySAML(SAMLCredential credential) {
		if (credential == null) {
			throw new UsernameNotFoundException("No credential entered. Unable to get username.");
		}

		// User exists. Give them at least USER role
		GrantedAuthority userAuthority = new SimpleGrantedAuthority(Constants.ROLE_ADMIN);

		// For debugging what's available in the credential from the IDP
		LOGGER.debug("############## Attributes ###############");
		credential.getAttributes().forEach(attribute ->
				LOGGER.debug("Attribute: {} \t Values: {}",
						attribute.getName(),
						StringUtils.join(credential.getAttributeAsStringArray(attribute.getName()), ',')
				));
		LOGGER.debug("############## Attributes ###############");

		String username = credential.getAttributeAsString("UserID");
		LOGGER.info("{} is logged in with authority {}", username, userAuthority.getAuthority());
		return new User(username, "DUMMY", Collections.singletonList(userAuthority));
	}
}
