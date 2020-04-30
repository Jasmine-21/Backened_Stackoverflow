package com.upgrad.stackoverflow.api.exception;

import com.upgrad.stackoverflow.api.model.ErrorResponse;
import com.upgrad.stackoverflow.service.exception.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;

/**
 * This class contains all the Exception Handlers for all the exceptions implemented in the project.
 * This is a global code for exception handlers and all the controllers implemented in the project can use this global code.
 */

@ControllerAdvice
public class RestExceptionHandler {

    /**
     * @param exc     - SignUpRestrictedException type object containing error code and error message.
     * @param request - The web request object gives access to all the request parameters.
     * @return - ResponseEntity<ErrorResponse> type object displaying error code and error message along with HttpStatus CONFLICT.
     */
    @ExceptionHandler(SignUpRestrictedException.class)
    public ResponseEntity<ErrorResponse> signUpRestrictedException(SignUpRestrictedException exc, WebRequest request) {
        return new ResponseEntity<ErrorResponse>(
                new ErrorResponse().code(exc.getCode()).message(exc.getErrorMessage()), HttpStatus.CONFLICT
        );
    }

    /**
     * @param exc     - AuthenticationFailedException type object containing error code and error message.
     * @param request - The web request object gives access to all the request parameters.
     * @return - ResponseEntity<ErrorResponse> type object displaying error code and error message along with HttpStatus UNAUTHORIZED.
     */
    @ExceptionHandler(AuthenticationFailedException.class)
    public ResponseEntity<ErrorResponse> authenticationFailedException(AuthenticationFailedException exc, WebRequest request) {
        return new ResponseEntity<ErrorResponse>(
                new ErrorResponse().code(exc.getCode()).message(exc.getErrorMessage()), HttpStatus.UNAUTHORIZED
        );
    }


    /**
     * @param exc     - SignOutRestrictedException type object containing error code and error message.
     * @param request - The web request object gives access to all the request parameters.
     * @return - ResponseEntity<ErrorResponse> type object displaying error code and error message along with HttpStatus UNAUTHORIZED.
     */
    @ExceptionHandler(SignOutRestrictedException.class)
    public ResponseEntity<ErrorResponse> signOutRestrictedException(SignOutRestrictedException exc, WebRequest request) {
        return new ResponseEntity<ErrorResponse>(
                new ErrorResponse().code(exc.getCode()).message(exc.getErrorMessage()), HttpStatus.UNAUTHORIZED
        );
    }

    /**
     * @param exc     - AuthorizationFailedException type object containing error code and error message.
     * @param request - The web request object gives access to all the request parameters.
     * @return - ResponseEntity<ErrorResponse> type object displaying error code and error message along with HttpStatus FORBIDDEN.
     */
    @ExceptionHandler(AuthorizationFailedException.class)
    public ResponseEntity<ErrorResponse> authorizationFailedException(AuthorizationFailedException exc, WebRequest request) {
        return new ResponseEntity<ErrorResponse>(
                new ErrorResponse().code(exc.getCode()).message(exc.getErrorMessage()), HttpStatus.FORBIDDEN
        );
    }

    /**
     * @param exc     - UserNotFoundException type object containing error code and error message.
     * @param request - The web request object gives access to all the request parameters.
     * @return - ResponseEntity<ErrorResponse> type object displaying error code and error message along with HttpStatus NOT_FOUND.
     */
    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ErrorResponse> userNotFoundException(UserNotFoundException exc, WebRequest request) {
        return new ResponseEntity<ErrorResponse>(
                new ErrorResponse().code(exc.getCode()).message(exc.getErrorMessage()), HttpStatus.NOT_FOUND
        );
    }

    /**
     * @param exc     - InvalidQuestionException type object containing error code and error message.
     * @param request - The web request object gives access to all the request parameters.
     * @return - ResponseEntity<ErrorResponse> type object displaying error code and error message along with HttpStatus NOT_FOUND.
     */
    @ExceptionHandler(InvalidQuestionException.class)
    public ResponseEntity<ErrorResponse> invalidQuestionException(InvalidQuestionException exc, WebRequest request) {
        return new ResponseEntity<ErrorResponse>(
                new ErrorResponse().code(exc.getCode()).message(exc.getErrorMessage()), HttpStatus.NOT_FOUND
        );
    }

    /**
     * @param exc     - AnswerNotFoundException type object containing error code and error message.
     * @param request - The web request object gives access to all the request parameters.
     * @return - ResponseEntity<ErrorResponse> type object displaying error code and error message along with HttpStatus NOT_FOUND.
     */
    @ExceptionHandler(AnswerNotFoundException.class)
    public ResponseEntity<ErrorResponse> answerNotFoundException(AnswerNotFoundException exc, WebRequest request) {
        return new ResponseEntity<ErrorResponse>(
                new ErrorResponse().code(exc.getCode()).message(exc.getErrorMessage()), HttpStatus.NOT_FOUND
        );
    }
}
