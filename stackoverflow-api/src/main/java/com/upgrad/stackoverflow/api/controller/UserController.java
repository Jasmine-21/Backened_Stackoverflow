package com.upgrad.stackoverflow.api.controller;

import com.upgrad.stackoverflow.api.model.SigninResponse;
import com.upgrad.stackoverflow.api.model.SignoutResponse;
import com.upgrad.stackoverflow.api.model.SignupUserRequest;
import com.upgrad.stackoverflow.api.model.SignupUserResponse;
import com.upgrad.stackoverflow.service.business.UserBusinessService;
import com.upgrad.stackoverflow.service.entity.UserAuthEntity;
import com.upgrad.stackoverflow.service.entity.UserEntity;
import com.upgrad.stackoverflow.service.exception.AuthenticationFailedException;
import com.upgrad.stackoverflow.service.exception.SignOutRestrictedException;
import com.upgrad.stackoverflow.service.exception.SignUpRestrictedException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;
import java.util.UUID;
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserBusinessService userBusinessService;

    /**
     * A controller method for user signup.
     *
     * @param signupUserRequest - This argument contains all the attributes required to store user details in the database.
     * @return - ResponseEntity<SignupUserResponse> type object along with Http status CREATED.
     * @throws SignUpRestrictedException
     */

    /**
     * A controller method for user authentication.
     *
     * @param authorization - A field in the request header which contains the user credentials as Basic authentication.
     * @return - ResponseEntity<SigninResponse> type object along with Http status OK.
     * @throws AuthenticationFailedException
     */

    /**
     * A controller method for user signout.
     *
     * @param authorization - A field in the request header which contains the JWT token.
     * @return - ResponseEntity<SignoutResponse> type object along with Http status OK.
     * @throws SignOutRestrictedException
     */

}
