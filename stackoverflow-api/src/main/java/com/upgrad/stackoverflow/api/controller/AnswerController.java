package com.upgrad.stackoverflow.api.controller;

import com.upgrad.stackoverflow.api.model.*;
import com.upgrad.stackoverflow.service.business.AnswerBusinessService;
import com.upgrad.stackoverflow.service.entity.AnswerEntity;
import com.upgrad.stackoverflow.service.entity.QuestionEntity;
import com.upgrad.stackoverflow.service.exception.AnswerNotFoundException;
import com.upgrad.stackoverflow.service.exception.AuthorizationFailedException;
import com.upgrad.stackoverflow.service.exception.InvalidQuestionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;


@RequestMapping("/")
public class AnswerController {


    @Autowired
    private AnswerBusinessService answerBusinessService;

    /**
     * A controller method to post an answer to a specific question.
     *
     * @param answerRequest - This argument contains all the attributes required to store answer details in the database.
     * @param questionId    - The uuid of the question whose answer is to be posted in the database.
     * @param authorization - A field in the request header which contains the JWT token.
     * @return - ResponseEntity<AnswerResponse> type object along with Http status CREATED.
     * @throws AuthorizationFailedException
     * @throws InvalidQuestionException
     */

    /**
     * A controller method to edit an answer in the database.
     *
     * @param answerEditRequest - This argument contains all the attributes required to store edited answer details in the database.
     * @param answerId          - The uuid of the answer to be edited in the database.
     * @param authorization     - A field in the request header which contains the JWT token.
     * @return - ResponseEntity<AnswerEditResponse> type object along with Http status OK.
     * @throws AuthorizationFailedException
     * @throws AnswerNotFoundException
     */

    /**
     * A controller method to delete an answer in the database.
     *
     * @param answerId      - The uuid of the answer to be deleted in the database.
     * @param authorization - A field in the request header which contains the JWT token.
     * @return - ResponseEntity<AnswerDeleteResponse> type object along with Http status OK.
     * @throws AuthorizationFailedException
     * @throws AnswerNotFoundException
     */

    /**
     * A controller method to fetch all the answers for a specific question in the database.
     *
     * @param questionId    - The uuid of the question whose answers are to be fetched from the database.
     * @param authorization - A field in the request header which contains the JWT token.
     * @return - ResponseEntity<List<AnswerDetailsResponse>> type object along with Http status OK.
     * @throws AuthorizationFailedException
     * @throws InvalidQuestionException
     */

}
