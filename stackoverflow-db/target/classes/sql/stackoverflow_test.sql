--These records are stored in the database to test the Stackoverflow Application

--Insert values in USERS table
INSERT INTO USERS(ID, UUID, FIRST_NAME, LAST_NAME, USERNAME, EMAIL, PASSWORD, SALT, COUNTRY, ABOUT_ME, DOB, ROLE, CONTACT_NUMBER)
    VALUES (102,'database_uuid','database_firstname','database_lastname','database_username','database_email','database_password','database_salt', 'database_country' ,'database_aboutme' ,'database_dob' , 'admin' , 'database_contactnumber' );
INSERT INTO USERS(ID, UUID, FIRST_NAME, LAST_NAME, USERNAME, EMAIL, PASSWORD, SALT, COUNTRY, ABOUT_ME, DOB, ROLE, CONTACT_NUMBER)
    VALUES (103,'database_uuid1','database_firstname1','database_lastname1','database_username1','database_email1','database_password1','database_salt1', 'database_country1' ,'database_aboutme1' ,'database_dob1' , 'nonadmin' , 'database_contactnumber1' );
INSERT INTO USERS(ID, UUID, FIRST_NAME, LAST_NAME, USERNAME, EMAIL, PASSWORD, SALT, COUNTRY, ABOUT_ME, DOB, ROLE, CONTACT_NUMBER)
    VALUES (104,'database_uuid2','database_firstname2','database_lastname2','database_username2','database_email2','database_password2','database_salt2', 'database_country2' ,'database_aboutme2' ,'database_dob2' , 'nonadmin' , 'database_contactnumber2' );
INSERT INTO USERS(ID, UUID, FIRST_NAME, LAST_NAME, USERNAME, EMAIL, PASSWORD, SALT, COUNTRY, ABOUT_ME, DOB, ROLE, CONTACT_NUMBER)
    VALUES (105,'database_uuid3','database_firstname3','database_lastname3','database_username3','database_email3','database_password3','database_salt3', 'database_country3' ,'database_aboutme3' ,'database_dob3' , 'nonadmin' , 'database_contactnumber3' );
INSERT INTO USERS(ID, UUID, FIRST_NAME, LAST_NAME, USERNAME, EMAIL, PASSWORD, SALT, COUNTRY, ABOUT_ME, DOB, ROLE, CONTACT_NUMBER)
    VALUES (106,'database_uuid4','database_firstname4','database_lastname4','database_username4','database_email4','database_password4','database_salt4', 'database_country4' ,'database_aboutme4' ,'database_dob4' , 'nonadmin' , 'database_contactnumber4' );


--Insert values in USER_AUTH table
INSERT INTO USER_AUTH (ID, UUID, USER_ID, ACCESS_TOKEN, EXPIRES_AT, LOGIN_AT, LOGOUT_AT)
    VALUES(1024, 'database_uuid', 102, 'database_accesstoken', '2020-04-09 21:07:02.07', '2020-04-08 13:07:02.07', null);
INSERT INTO USER_AUTH (ID, UUID, USER_ID, ACCESS_TOKEN, EXPIRES_AT, LOGIN_AT, LOGOUT_AT)
    VALUES(1025 , 'database_uuid1', 103, 'database_accesstoken1', '2020-04-09 21:07:02.07', '2020-04-08 13:07:02.07', null );
INSERT INTO USER_AUTH (ID, UUID, USER_ID, ACCESS_TOKEN, EXPIRES_AT, LOGIN_AT, LOGOUT_AT)
    VALUES(1026 , 'database_uuid2', 104, 'database_accesstoken2', '2020-04-09 21:07:02.07', '2020-04-08 13:07:02.07', null );
INSERT INTO USER_AUTH (ID, UUID, USER_ID, ACCESS_TOKEN, EXPIRES_AT, LOGIN_AT, LOGOUT_AT)
    VALUES(1027, 'database_uuid3', 105, 'database_accesstoken3', '2020-04-09 21:07:02.07', '2020-04-08 13:07:02.07', '2020-04-08 15:07:02.07' );


--Insert values in QUESTION table
INSERT INTO QUESTION (ID, UUID, CONTENT, DATE, USER_ID)
    VALUES(1024, 'database_question_uuid', 'database_question_content', '2020-04-08 19:41:19.593', 102);


--Insert values in ANSWER table
INSERT INTO ANSWER(ID, UUID, ANS, DATE, USER_ID, QUESTION_ID)
    VALUES (1024, 'database_answer_uuid', 'my_answer', '2018-09-17 19:41:19.593', 102, 1024);
