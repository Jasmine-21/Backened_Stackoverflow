package com.upgrad.stackoverflow.api.controller;

import com.upgrad.stackoverflow.service.business.AdminBusinessService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;

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

}
