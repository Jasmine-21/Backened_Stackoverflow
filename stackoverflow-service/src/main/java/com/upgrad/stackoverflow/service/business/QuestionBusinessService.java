package com.upgrad.stackoverflow.service.business;


import com.upgrad.stackoverflow.service.dao.QuestionDao;
import com.upgrad.stackoverflow.service.dao.UserDao;
import com.upgrad.stackoverflow.service.entity.QuestionEntity;
import com.upgrad.stackoverflow.service.entity.UserAuthEntity;
import com.upgrad.stackoverflow.service.entity.UserEntity;
import com.upgrad.stackoverflow.service.exception.AuthorizationFailedException;
import com.upgrad.stackoverflow.service.exception.InvalidQuestionException;
import com.upgrad.stackoverflow.service.exception.UserNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.TypedQuery;
import java.time.ZonedDateTime;
import java.util.UUID;

@Service
public class QuestionBusinessService {
    @Autowired
    private UserDao userDao;
    @Autowired
    private QuestionDao questionDao;

    public QuestionBusinessService() {
    }

    /**
     * The method implements the business logic for createQuestion endpoint.
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public QuestionEntity createQuestion(QuestionEntity questionEntity, String authorization) throws AuthorizationFailedException {
        UserAuthEntity userAuthEntity = this.userDao.getUserAuthByAccesstoken(authorization);
        if (userAuthEntity == null) {
            throw new AuthorizationFailedException("ATHR-001", "User has not signed in");
        } else if (userAuthEntity.getLogoutAt() != null) {
            throw new AuthorizationFailedException("ATHR-002", "User is signed out. Sign in first to post a question");
        } else {
            questionEntity.setDate(ZonedDateTime.now());
            questionEntity.setUuid(UUID.randomUUID().toString());
            questionEntity.setUser(userAuthEntity.getUser());
            return this.questionDao.createQuestion(questionEntity);
        }
    }

    /**
     * The method implements the business logic for getAllQuestions endpoint.
     */
    public TypedQuery<QuestionEntity> getQuestions(String authorization) throws AuthorizationFailedException {
        UserAuthEntity userAuthEntity = this.userDao.getUserAuthByAccesstoken(authorization);
        if (userAuthEntity == null) {
            throw new AuthorizationFailedException("ATHR-001", "User has not signed in");
        } else if (userAuthEntity.getLogoutAt() != null) {
            throw new AuthorizationFailedException("ATHR-002", "User is signed out. Sign in first to get all questions");
        } else {
            return this.questionDao.getQuestions();
        }
    }

    /**
     * The method implements the business logic for editQuestionContent endpoint.
     */
    @Transactional(
            propagation = Propagation.REQUIRED
    )
    public QuestionEntity editQuestionContent(QuestionEntity questionEntity, String questionId, String authorization) throws AuthorizationFailedException, InvalidQuestionException {
        UserAuthEntity userAuthEntity = this.userDao.getUserAuthByAccesstoken(authorization);
        if (userAuthEntity == null) {
            throw new AuthorizationFailedException("ATHR-001", "User has not signed in");
        } else if (userAuthEntity.getLogoutAt() != null) {
            throw new AuthorizationFailedException("ATHR-002", "User has signed out. Sign in first to edit the question");
        } else {
            QuestionEntity questionEntityyy = this.questionDao.getQuestionByUuid(questionId);
            if (questionEntityyy == null) {
                throw new InvalidQuestionException("QUES-001", "Entered question uuid does not exist");
            } else if (userAuthEntity.getUser() == questionEntityyy.getUser()) {
                questionEntityyy.setContent(questionEntity.getContent());
                questionEntityyy.setDate(ZonedDateTime.now());
                return this.questionDao.editQuestion(questionEntityyy);
            } else {
                throw new AuthorizationFailedException("ATHR-003", "Only the question owner can edit the question");
            }
        }
    }

    /**
     * The method implements the business logic for deleteQuestion endpoint.
     */
    @Transactional(
            propagation = Propagation.REQUIRED
    )
    public QuestionEntity deleteQuestion(String questionId, String authorization) throws AuthorizationFailedException, InvalidQuestionException {
        UserAuthEntity userAuthEntity = this.userDao.getUserAuthByAccesstoken(authorization);
        if (userAuthEntity == null) {
            throw new AuthorizationFailedException("ATHR-001", "User has not signed in");
        } else if (userAuthEntity.getLogoutAt() != null) {
            throw new AuthorizationFailedException("ATHR-002", "User has signed out. Sign in first to delete a question");
        } else {
            QuestionEntity questionEntity = this.questionDao.getQuestionByUuid(questionId);
            if (questionEntity == null) {
                throw new InvalidQuestionException("QUES-001", "Entered question uuid does not exist");
            } else if (userAuthEntity.getUser() != questionEntity.getUser() && !userAuthEntity.getUser().getRole().equals("admin")) {
                throw new AuthorizationFailedException("ATHR-003", "Only the question owner or admin can delete the question");
            } else {
                return this.questionDao.deleteQuestion(questionEntity);
            }
        }
    }

    /**
     * The method implements the business logic for getAllQuestionsByUser endpoint.
     */
    public TypedQuery<QuestionEntity> getQuestionsByUser(String userId, String authorization) throws AuthorizationFailedException, UserNotFoundException {
        UserAuthEntity userAuthEntity = this.userDao.getUserAuthByAccesstoken(authorization);
        if (userAuthEntity == null) {
            throw new AuthorizationFailedException("ATHR-001", "User has not signed in");
        } else if (userAuthEntity.getLogoutAt() != null) {
            throw new AuthorizationFailedException("ATHR-002", "User is signed out. Sign in first to get all questions posted by a specific user");
        } else {
            UserEntity userEntity = this.questionDao.getUserByUuid(userId);
            if (userEntity == null) {
                throw new UserNotFoundException("USR-001", "User with entered uuid whose question details are to be seen does not exist");
            } else {
                return this.questionDao.getQuestionsByUser(userEntity);
            }
        }
    }
}