package com.upgrad.stackoverflow.service.business;


import com.upgrad.stackoverflow.service.dao.CommonDao;
import com.upgrad.stackoverflow.service.dao.UserDao;
import com.upgrad.stackoverflow.service.entity.UserAuthEntity;
import com.upgrad.stackoverflow.service.entity.UserEntity;
import com.upgrad.stackoverflow.service.exception.AuthorizationFailedException;
import com.upgrad.stackoverflow.service.exception.UserNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CommonBusinessService {

    @Autowired
    private UserDao userDao;

    @Autowired
    private CommonDao commonDao;

    /**
     * The method implements the business logic for userProfile endpoint.
     */
    public UserEntity getUser(String uuid, String authorization) throws UserNotFoundException, AuthorizationFailedException {

        UserAuthEntity userAuthEntity = userDao.getUserAuthByAccesstoken(authorization);

    }
}
