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
import javax.persistence.TypedQuery;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
@RestController
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
    @PostMapping("/create")
    public ResponseEntity<QuestionResponse> createQuestion(@RequestBody QuestionRequest questionRequest, @RequestHeader(value="Authorization") String authorization) throws AuthorizationFailedException
    {
        QuestionEntity questionEntity=new QuestionEntity();
        questionEntity.setContent(questionRequest.getContent());
        QuestionEntity question = questionBusinessService.createQuestion(questionEntity, authorization);
        QuestionResponse questionResponse = new QuestionResponse();
        questionResponse.setId(question.getUuid());
        questionResponse.setStatus("QUESTION CREATED");
        return new ResponseEntity<QuestionResponse>(questionResponse, HttpStatus.CREATED);
    }
    /**
     * A controller method to fetch all the questions from the database.
     *
     * @param authorization - A field in the request header which contains the JWT token.
     * @return - ResponseEntity<List<QuestionDetailsResponse>> type object along with Http status OK.
     * @throws AuthorizationFailedException
     */
    @GetMapping("/all")
    public ResponseEntity<List<QuestionDetailsResponse>> getQuestions(@RequestHeader(value="Authorization") String authorization) throws AuthorizationFailedException
    {
        TypedQuery<QuestionEntity> questionList = questionBusinessService.getQuestions(authorization);
        List<QuestionEntity> resultedList = questionList.getResultList();
        List<QuestionDetailsResponse> responsedList = resultedList.stream()
                .map(question -> {
                    QuestionDetailsResponse response = new QuestionDetailsResponse();
                    response.setContent(question.getContent());
                    response.setId(question.getUuid());
                    return response;
                }).collect(Collectors.toList());

        return new ResponseEntity<>(responsedList, HttpStatus.OK);
    }

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
    @PutMapping(path = "/edit/{questionId}")
    public ResponseEntity<QuestionEditResponse> editQuestionContent(@PathVariable("questionId") String questionId, @RequestBody QuestionEditRequest questionEditRequest, @RequestHeader("authorization") String authorization) throws AuthorizationFailedException, InvalidQuestionException
    {
        QuestionEntity questionEntity = new QuestionEntity();
        questionEntity.setContent(questionEditRequest.getContent());
        QuestionEntity questionEditingContent = questionBusinessService.editQuestionContent(questionEntity, questionId, authorization);
        QuestionEditResponse question = new QuestionEditResponse();
        question.id(questionEditingContent.getUuid());
        question.status("QUESTION EDITED");
        return new ResponseEntity<QuestionEditResponse>(question, HttpStatus.OK);
    }


    /**
     * A controller method to delete the question in the database.
     *
     * @param questionId    - The uuid of the question to be deleted in the database.
     * @param authorization - A field in the request header which contains the JWT token.
     * @return - ResponseEntity<QuestionDeleteResponse> type object along with Http status OK.
     * @throws AuthorizationFailedException
     * @throws InvalidQuestionException
     */
    @DeleteMapping("/delete/{questionId}")
    public ResponseEntity<QuestionDeleteResponse> deleteQuestion(@PathVariable String questionId, @RequestHeader("authorization") String authorization) throws AuthorizationFailedException,InvalidQuestionException{

        QuestionEntity questionEntity = questionBusinessService.deleteQuestion(questionId,authorization);
        QuestionDeleteResponse questionDeletingResponse = new QuestionDeleteResponse().id(questionEntity.getUuid()).status("QUESTION DELETED");
        return new ResponseEntity<QuestionDeleteResponse>(questionDeletingResponse,HttpStatus.OK);
    }

    /**
     * A controller method to fetch all the questions posted by a specific user.
     *
     * @param userId        - The uuid of the user whose questions are to be fetched from the database.
     * @param authorization - A field in the request header which contains the JWT token.
     * @return - ResponseEntity<List<QuestionDetailsResponse>> type object along with Http status OK.
     * @throws AuthorizationFailedException
     * @throws UserNotFoundException
     */
    @GetMapping("/all/{userId}")
    public ResponseEntity<List<QuestionDetailsResponse>> getAllByUserId(@PathVariable String userId, @RequestHeader("authorization") String authorization) throws AuthorizationFailedException, UserNotFoundException{
        TypedQuery<QuestionEntity> questionLists = questionBusinessService.getQuestionsByUser(userId,authorization);
        List<QuestionEntity> resultedList = questionLists.getResultList();
        List<QuestionDetailsResponse> responsedList = resultedList.stream()
                .map(question -> {
                    QuestionDetailsResponse response = new QuestionDetailsResponse();
                    response.setContent(question.getContent());
                    response.setId(question.getUuid());
                    return response;
                }).collect(Collectors.toList());

        return new ResponseEntity<>(responsedList, HttpStatus.OK);
    }

}