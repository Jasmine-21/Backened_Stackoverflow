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
    public UserEntity getUser(String uuid, String authorization) throws UserNotFoundException, AuthorizationFailedException
    {

        UserAuthEntity userAuthEntity = userDao.getUserAuthByAccesstoken(authorization);
        if (userAuthEntity == null) {
            throw new AuthorizationFailedException("ATHR-001", "User has not signed in");
        }
        else if (userAuthEntity.getLogoutAt() != null)
        {

            throw new AuthorizationFailedException("ATHR-002", "User has signed out. Sign in first to get user details");

        }
        else
        {
            UserEntity userEntity = this.commonDao.getUserByUuid(uuid);
            if (userEntity == null)
            {
                throw new UserNotFoundException("USR-001", "User with entered uuid does not exist");
            }
            else
            {
                return userEntity;
            }
        }
    }
}
