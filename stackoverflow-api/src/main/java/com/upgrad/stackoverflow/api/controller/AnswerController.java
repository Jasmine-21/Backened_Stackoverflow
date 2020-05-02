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

import javax.persistence.TypedQuery;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;


@RequestMapping("")
@RestController
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
    @PostMapping("/question/{questionId}/answer/create")
    public ResponseEntity<AnswerResponse> postAnswer(@RequestBody AnswerRequest answerRequest, @RequestHeader String authorization, @PathVariable String questionId) throws AuthorizationFailedException, InvalidQuestionException
    {
        AnswerEntity answerEntity=new AnswerEntity();
        answerEntity.setUuid(UUID.randomUUID().toString());
        answerEntity.setAns(answerRequest.getAnswer());
        answerEntity.setDate(ZonedDateTime.now());
        QuestionEntity questionEntity = answerBusinessService.getQuestionByUuid(questionId);
        answerEntity.setQuestion(questionEntity);
        AnswerEntity answerEntity1 = answerBusinessService.createAnswer(answerEntity,authorization);
        AnswerResponse answerResponse = new AnswerResponse().id(answerEntity1.getUuid()).status("Answer Created");
        return new ResponseEntity<AnswerResponse>(answerResponse, HttpStatus.CREATED);
    }
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
    @PutMapping("/answer/edit/{answerId}")
    public ResponseEntity<AnswerEditResponse> editAnswer(@RequestBody AnswerEditRequest answerEditRequest, @RequestHeader String authorization, @PathVariable String answerId) throws AuthorizationFailedException, AnswerNotFoundException
    {
        AnswerEntity answerEntity=new AnswerEntity();
        answerEntity.setAns(answerEditRequest.getContent());
        AnswerEntity answerEntity1 = answerBusinessService.editAnswerContent(answerEntity,  answerId,  authorization);
        AnswerEditResponse answerEditResponse =new AnswerEditResponse().id(answerEntity1.getUuid()).status("Answer Edited");
        return new ResponseEntity<AnswerEditResponse>(answerEditResponse, HttpStatus.OK);
    }
    /**
     * A controller method to delete an answer in the database.
     *
     * @param answerId      - The uuid of the answer to be deleted in the database.
     * @param authorization - A field in the request header which contains the JWT token.
     * @return - ResponseEntity<AnswerDeleteResponse> type object along with Http status OK.
     * @throws AuthorizationFailedException
     * @throws AnswerNotFoundException
     */
    @DeleteMapping("/answer/delete/{answerId}")
    public ResponseEntity<AnswerDeleteResponse> deleteAnswer(@PathVariable String answerId, @RequestHeader("authorization") String authorization) throws AuthorizationFailedException, AnswerNotFoundException
    {
        AnswerEntity answerEntity = answerBusinessService.deleteAnswer(answerId, authorization);
        AnswerDeleteResponse answerDeleteResponse = new AnswerDeleteResponse().id(answerEntity.getUuid()).status("Answer Deleted");
        return new ResponseEntity<AnswerDeleteResponse>(answerDeleteResponse,HttpStatus.OK);
    }

    /**
     * A controller method to fetch all the answers for a specific question in the database.
     *
     * @param questionId    - The uuid of the question whose answers are to be fetched from the database.
     * @param authorization - A field in the request header which contains the JWT token.
     * @return - ResponseEntity<List<AnswerDetailsResponse>> type object along with Http status OK.
     * @throws AuthorizationFailedException
     * @throws InvalidQuestionException
     */
    @GetMapping("/answer/all/{questionId}")
    public ResponseEntity<List<AnswerDetailsResponse>> getAllByquestionId(@PathVariable String questionId, @RequestHeader("auhtorization") String authorization) throws AuthorizationFailedException, InvalidQuestionException
    {
        TypedQuery<AnswerEntity> answerList = answerBusinessService.getAnswersByQuestion(questionId, authorization);
        List<AnswerEntity> resultList = answerList.getResultList();
        List<AnswerDetailsResponse> responseList = resultList.stream()
                .map(answer -> {
                    AnswerDetailsResponse response = new AnswerDetailsResponse();
                    response.setAnswerContent(answer.getAns());
                    response.setQuestionContent(answer.getQuestion().getContent());
                    response.setId(answer.getUuid());
                    return response;
                }).collect(Collectors.toList());
        return new ResponseEntity<>(responseList, HttpStatus.OK);
    }
}