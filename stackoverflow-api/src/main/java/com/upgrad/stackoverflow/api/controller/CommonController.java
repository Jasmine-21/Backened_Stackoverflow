package com.upgrad.stackoverflow.api.controller;

import com.upgrad.stackoverflow.api.model.UserDetailsResponse;
import com.upgrad.stackoverflow.service.business.CommonBusinessService;
import com.upgrad.stackoverflow.service.entity.UserEntity;
import com.upgrad.stackoverflow.service.exception.AuthorizationFailedException;
import com.upgrad.stackoverflow.service.exception.UserNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/")
public class CommonController {

    @Autowired
    private CommonBusinessService commonBusinessService;

    /**
     * A controller method to fetch the details of other user.
     *
     * @param userId        - The uuid of the user whose details are to be fetched from the database.
     * @param authorization - A field in the request header which contains the JWT token.
     * @return - ResponseEntity<UserDetailsResponse> type object along with Http status OK.
     * @throws UserNotFoundException
     * @throws AuthorizationFailedException
     *
     */
    @GetMapping("/userprofile/{userId}")
    public ResponseEntity<UserDetailsResponse> getProfileOfUser(@PathVariable("userId") String userId,@RequestHeader(value="Authorization") String authorization) throws AuthorizationFailedException, UserNotFoundException {

        UserEntity user = commonBusinessService.getUser(userId, authorization);
        UserDetailsResponse userDetailsResponse = new UserDetailsResponse();
        userDetailsResponse.setUserName(user.getUserName());
        userDetailsResponse.setFirstName(user.getFirstName());
        userDetailsResponse.setLastName(user.getLastName());
        userDetailsResponse.setEmailAddress(user.getEmail());
        userDetailsResponse.setDob(user.getDob());
        userDetailsResponse.setCountry(user.getCountry());
        userDetailsResponse.setAboutMe(user.getAboutMe());
        userDetailsResponse.setContactNumber(user.getContactNumber());
        return new ResponseEntity<UserDetailsResponse>(userDetailsResponse, HttpStatus.OK);
    }

}
