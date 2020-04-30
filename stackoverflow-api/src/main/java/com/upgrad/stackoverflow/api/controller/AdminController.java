package com.upgrad.stackoverflow.api.controller;

import com.upgrad.stackoverflow.api.model.UserDeleteResponse;
import com.upgrad.stackoverflow.service.business.AdminBusinessService;
import com.upgrad.stackoverflow.service.entity.UserEntity;
import com.upgrad.stackoverflow.service.exception.AuthorizationFailedException;
import com.upgrad.stackoverflow.service.exception.UserNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/admin")
public class AdminController {

    @Autowired
    private AdminBusinessService adminBusinessService;

    /**
     * A controller method to delete a user in the database.
     *
     * @param userId        - The uuid of the user to be deleted from the database.
     * @param authorization - A field in the request header which contains the JWT token.
     * @return - ResponseEntity<UserDeleteResponse> type object along with Http status OK.
     * @throws AuthorizationFailedException
     * @throws UserNotFoundException
     */

    @DeleteMapping("/user/{userId}")
    public ResponseEntity<UserDeleteResponse> deleteUser(@PathVariable("userId") String userId, @RequestHeader(value = "Authorization") String authorization) throws AuthorizationFailedException, UserNotFoundException {
        UserEntity userEntity = adminBusinessService.deleteUser(authorization, userId);
        UserDeleteResponse userDeleteResponse = new UserDeleteResponse();
        userDeleteResponse.setId(userEntity.getUuid());
        userDeleteResponse.setStatus("USER SUCCESSFULLY DELETED");
        return new ResponseEntity<UserDeleteResponse>(userDeleteResponse, HttpStatus.OK);
    }
}