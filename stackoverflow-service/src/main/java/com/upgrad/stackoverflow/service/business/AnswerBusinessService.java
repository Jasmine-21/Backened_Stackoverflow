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

    }

    public QuestionEntity getQuestionByUuid(String Uuid) throws InvalidQuestionException {

        QuestionEntity questionEntity = answerDao.getQuestionByUuid(Uuid);

    }


    /**
     * The method implements the business logic for editAnswerContent endpoint.
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public AnswerEntity editAnswerContent(AnswerEntity answerEntity, String answerId, String authorization) throws AuthorizationFailedException, AnswerNotFoundException {
        UserAuthEntity userAuthEntity = userDao.getUserAuthByAccesstoken(authorization);

    }

    /**
     * The method implements the business logic for deleteAnswer endpoint.
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public AnswerEntity deleteAnswer(String answerId, String authorization) throws AuthorizationFailedException, AnswerNotFoundException {
        UserAuthEntity userAuthEntity = userDao.getUserAuthByAccesstoken(authorization);

    }

    /**
     * The method implements the business logic for getAllAnswersToQuestion endpoint.
     */
    public TypedQuery<AnswerEntity> getAnswersByQuestion(String questionId, String authorization) throws AuthorizationFailedException, InvalidQuestionException {
        UserAuthEntity userAuthEntity = userDao.getUserAuthByAccesstoken(authorization);

    }
}
