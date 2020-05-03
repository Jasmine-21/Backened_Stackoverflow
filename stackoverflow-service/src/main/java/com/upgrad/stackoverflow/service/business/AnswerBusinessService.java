package com.upgrad.stackoverflow.service.business;

import com.upgrad.stackoverflow.service.dao.AnswerDao;
import com.upgrad.stackoverflow.service.dao.UserDao;
import com.upgrad.stackoverflow.service.entity.AnswerEntity;
import com.upgrad.stackoverflow.service.entity.QuestionEntity;
import com.upgrad.stackoverflow.service.entity.UserAuthEntity;
import com.upgrad.stackoverflow.service.exception.AnswerNotFoundException;
import com.upgrad.stackoverflow.service.exception.AuthorizationFailedException;
import com.upgrad.stackoverflow.service.exception.InvalidQuestionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.TypedQuery;
import java.time.ZonedDateTime;

@Service
public class AnswerBusinessService {


    @Autowired
    private UserDao userDao;

    @Autowired
    private AnswerDao answerDao;


    /**
     * The method implements the business logic for createAnswer endpoint.
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public AnswerEntity createAnswer(AnswerEntity answerEntity, String authorization) throws AuthorizationFailedException {

        UserAuthEntity userAuthEntity = userDao.getUserAuthByAccesstoken(authorization);
        if(userAuthEntity==null){
            throw new AuthorizationFailedException("ATHR-001","User has not signed in");
        }
        else if(userAuthEntity.getLogoutAt()!=null){
            throw new AuthorizationFailedException("ATHR-002","User is signed out.Sign in first to post an answer");
        }
        else {
            answerEntity.setDate(ZonedDateTime.now());
            answerEntity.setUser(userAuthEntity.getUser());
            return  answerDao.createAnswer(answerEntity);
        }

    }

    public QuestionEntity getQuestionByUuid(String Uuid) throws InvalidQuestionException {

        QuestionEntity questionEntity = answerDao.getQuestionByUuid(Uuid);
        if(questionEntity==null){
            throw new InvalidQuestionException("QUES-001","The question entered is invalid");
        }
        return questionEntity;


    }


    /**
     * The method implements the business logic for editAnswerContent endpoint.
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public AnswerEntity editAnswerContent(AnswerEntity answerEntity, String answerId, String authorization) throws AuthorizationFailedException, AnswerNotFoundException {
        UserAuthEntity userAuthEntity = userDao.getUserAuthByAccesstoken(authorization);
        if(userAuthEntity==null){
            throw new AuthorizationFailedException("ATHR-001","User has not signed in");
        }
        else if(userAuthEntity.getLogoutAt()!=null)
        {
            throw new AuthorizationFailedException("ATHR-002","User is signed out.Sign in first to edit an answer");
        }
        else{
            AnswerEntity answerEntity1=answerDao.getAnswerByUuid(answerId);
            if(answerEntity1==null){
                throw new AnswerNotFoundException("ANS-001","Entered answer uuid does not exist");
            }
            else if(answerEntity1.getUser()!=userAuthEntity.getUser())
            {
                throw new AuthorizationFailedException("ATHR-003","Only the answer owner can edit the answer");
            }
            else {
                answerEntity1.setAns(answerEntity.getAns());
                answerEntity1.setDate(ZonedDateTime.now());
                return answerDao.editAnswer(answerEntity1);
            }
        }

    }

    /**
     * The method implements the business logic for deleteAnswer endpoint.
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public AnswerEntity deleteAnswer(String answerId, String authorization) throws AuthorizationFailedException, AnswerNotFoundException {
        UserAuthEntity userAuthEntity = userDao.getUserAuthByAccesstoken(authorization);
        if(userAuthEntity == null) {
            throw new AuthorizationFailedException("ATHR-001", "User has not signed in");
        }
        else if(userAuthEntity.getLogoutAt()!=null) {
            throw new AuthorizationFailedException("ATHR-002", "User is signed out.Sign in first to delete an answer");
        }
        else {
            AnswerEntity answerEntity = this.answerDao.getAnswerByUuid(answerId);
            if (answerEntity == null) {
                throw new AnswerNotFoundException("ANS-001", "Entered answer uuid does not exist");
            } else if (userAuthEntity.getUser() != answerEntity.getUser() && !userAuthEntity.getUser().getRole().equals("admin")) {
                throw new AuthorizationFailedException("ATHR-003", "Only the answer owner or admin can delete the answer");
            } else {
                return this.answerDao.deleteAnswer(answerEntity);
            }
        }

    }

    /**
     * The method implements the business logic for getAllAnswersToQuestion endpoint.
     */
    public TypedQuery<AnswerEntity> getAnswersByQuestion(String questionId, String authorization) throws AuthorizationFailedException, InvalidQuestionException {
        UserAuthEntity userAuthEntity = userDao.getUserAuthByAccesstoken(authorization);
        if(userAuthEntity==null) {
            throw new AuthorizationFailedException("ATHR-001", "User ha not signed in");
        }
        else if(userAuthEntity.getLogoutAt()!=null) {
            throw new AuthorizationFailedException("ATHR-002", "User is signed out.Sign in first to get the answers");
        }
        else {
            QuestionEntity questionEntity = this.answerDao.getQuestionByUuid(questionId);
            if (questionEntity == null) {
                throw new InvalidQuestionException("QUES-001", "The question with entered uuid whose details are to be seen does not exist");
            } else {
                return this.answerDao.getAnswersByQuestion(questionEntity);
            }
        }

    }
}