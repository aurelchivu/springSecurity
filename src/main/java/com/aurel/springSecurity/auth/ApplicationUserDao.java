package com.aurel.springSecurity.auth;

import java.util.Optional;

// This interface gives the ability to load users from any data source
public interface ApplicationUserDao {
    Optional<ApplicationUser> selectApplicationUserByUsername(String username);
}
