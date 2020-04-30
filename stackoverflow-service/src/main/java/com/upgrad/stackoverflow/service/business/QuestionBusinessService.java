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

@Service
public class QuestionBusinessService {

    @Autowired
    private UserDao userDao;

    @Autowired
    private QuestionDao questionDao;


    /**
     * The method implements the business logic for createQuestion endpoint.
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public QuestionEntity createQuestion(QuestionEntity questionEntity, String authorization) throws AuthorizationFailedException {

        UserAuthEntity userAuthEntity = userDao.getUserAuthByAccesstoken(authorization);

    }

    /**
     * The method implements the business logic for getAllQuestions endpoint.
     */
    public TypedQuery<QuestionEntity> getQuestions(String authorization) throws AuthorizationFailedException {

        UserAuthEntity userAuthEntity = userDao.getUserAuthByAccesstoken(authorization);

    }

    /**
     * The method implements the business logic for editQuestionContent endpoint.
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public QuestionEntity editQuestionContent(QuestionEntity questionEntity, String questionId, String authorization) throws AuthorizationFailedException, InvalidQuestionException {
        UserAuthEntity userAuthEntity = userDao.getUserAuthByAccesstoken(authorization);

    }

    /**
     * The method implements the business logic for deleteQuestion endpoint.
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public QuestionEntity deleteQuestion(String questionId, String authorization) throws AuthorizationFailedException, InvalidQuestionException {
        UserAuthEntity userAuthEntity = userDao.getUserAuthByAccesstoken(authorization);

    }

    /**
     * The method implements the business logic for getAllQuestionsByUser endpoint.
     */
    public TypedQuery<QuestionEntity> getQuestionsByUser(String userId, String authorization) throws AuthorizationFailedException, UserNotFoundException {
        UserAuthEntity userAuthEntity = userDao.getUserAuthByAccesstoken(authorization);

    }

}
