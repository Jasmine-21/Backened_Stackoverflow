package com.upgrad.stackoverflow.api.controller;

import com.upgrad.stackoverflow.api.model.*;
import com.upgrad.stackoverflow.service.business.QuestionBusinessService;
import com.upgrad.stackoverflow.service.entity.QuestionEntity;
import com.upgrad.stackoverflow.service.exception.AuthorizationFailedException;
import com.upgrad.stackoverflow.service.exception.InvalidQuestionException;
import com.upgrad.stackoverflow.service.exception.UserNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@RequestMapping("/question")
public class QuestionController {

    @Autowired
    private QuestionBusinessService questionBusinessService;

    /**
     * A controller method to create a question.
     *
     * @param questionRequest - This argument contains all the attributes required to store question details in the database.
     * @param authorization   - A field in the request header which contains the JWT token.
     * @return - ResponseEntity<QuestionResponse> type object along with Http status CREATED.
     * @throws AuthorizationFailedException
     */

    /**
     * A controller method to fetch all the questions from the database.
     *
     * @param authorization - A field in the request header which contains the JWT token.
     * @return - ResponseEntity<List<QuestionDetailsResponse>> type object along with Http status OK.
     * @throws AuthorizationFailedException
     */

    /**
     * A controller method to edit the question in the database.
     *
     * @param questionEditRequest - This argument contains all the attributes required to edit the question details in the database.
     * @param questionId          - The uuid of the question to be edited in the database.
     * @param authorization       - A field in the request header which contains the JWT token.
     * @return - ResponseEntity<QuestionEditResponse> type object along with Http status OK.
     * @throws AuthorizationFailedException
     * @throws InvalidQuestionException
     */

    /**
     * A controller method to delete the question in the database.
     *
     * @param questionId    - The uuid of the question to be deleted in the database.
     * @param authorization - A field in the request header which contains the JWT token.
     * @return - ResponseEntity<QuestionDeleteResponse> type object along with Http status OK.
     * @throws AuthorizationFailedException
     * @throws InvalidQuestionException
     */

    /**
     * A controller method to fetch all the questions posted by a specific user.
     *
     * @param userId        - The uuid of the user whose questions are to be fetched from the database.
     * @param authorization - A field in the request header which contains the JWT token.
     * @return - ResponseEntity<List<QuestionDetailsResponse>> type object along with Http status OK.
     * @throws AuthorizationFailedException
     * @throws UserNotFoundException
     */
}
