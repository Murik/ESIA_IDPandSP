CREATE DATABASE usersdb;
CREATE USER jboss WITH password '123qweASD';
GRANT ALL privileges ON DATABASE usersdb TO jboss with grant option;
-- psql -h localhost usersdb jboss
create schema users;

CREATE TABLE users.esia_users
(
    userId VARCHAR(36) PRIMARY KEY NOT NULL,
    userName VARCHAR  NOT NULL,
    firstName VARCHAR  NOT NULL,
    lastName VARCHAR  NOT NULL,
    middleName VARCHAR  NOT NULL,
    personINN VARCHAR ,
    personSNILS VARCHAR ,
    personOGRN VARCHAR ,
    personEMail VARCHAR  NOT NULL,
    authnMethod VARCHAR(3) NOT NULL,
--     PWD — аутентификации по логину и паролю; DS — аутентификации по ЭП.
    authToken VARCHAR  NOT NULL,
--     deviceType VARCHAR ,
    personType VARCHAR(1),
--     R — гражданин РФ (Russian); F — иностранный гражданин (Foreigner).
    globalRole VARCHAR(1) NOT NULL,
--     P — физическое лицо (Physical person); E — должностное лицо организации (Employee).
    memberOfGroups VARCHAR  NOT NULL,
    orgAddresses VARCHAR  NOT NULL,
    orgContacts VARCHAR  NOT NULL,
    orgOid VARCHAR  NOT NULL,
    orgKPP VARCHAR  NOT NULL,
    orgLegalForm VARCHAR  NOT NULL,
    orgINN VARCHAR ,
    orgName VARCHAR ,
    orgShortName VARCHAR ,
    orgOGRN VARCHAR ,
    orgPosition VARCHAR  NOT NULL,
    orgType VARCHAR(1),
--     B — индивидуальный предприниматель (Businessman); L — юридическое лицо (Legal entity); A — орган исполнительной власти (Agency).
    password VARCHAR  NOT NULL
);

CREATE TABLE users.roles
(
  userId VARCHAR(36) NOT NULL,
  role VARCHAR  NOT NULL
);

INSERT INTO users.esia_users VALUES ( 2006101,'vasya','Вася','Пупкин','Анатольевич',NULL,NULL,'1047421006764','vasya@exampl.ru','PWD','b0db6fd1-d674-47bb-8f22-9f8291e59255',NULL,'P','CITIZEN','<?xml version="1.0" encoding="UTF-8" standalone="yes"?><orgAddresses><address><addressType>ORG_POSTAL</addressType><contryChar3Code>RUS</contryChar3Code><index>601120</index><region>Владимирская Область</region><district>Петушинский Район</district><house>2</house><corpus>1</corpus><structure>2</structure><flat>3</flat></address><address><addressType>ORG_LEGAL</addressType><contryChar3Code>RUS</contryChar3Code><index>150006</index><region>г Белгород</region><street>ул Ленина</street><house>47</house></address></orgAddresses>','<?xml version="1.0" encoding="UTF-8" standalone="yes"?><orgContacts><contact><contactType>PHN</contactType><value>+7(966)6666666</value><verificationStatus>N</verificationStatus></contact><contact><contactType>EML</contactType><value>kamolin@esia.ru</value><verificationStatus>N</verificationStatus></contact></orgContacts>','7c1d2bf2-a477-4b43-af8a-0642457e2b71','463201001','12165','000-000-000 00','Открытое акционерное общество"Рога и копыта"','ОАО "Рога и копыта"','000000000000000','Директор','B','RuRKoLwh2Kgm15NE3zi+Sw==');
INSERT INTO users.esia_users (userId,userName,firstName,lastName,middleName,personINN ,personSNILS,personOGRN,personEMail,authnMethod,authToken,personType,globalRole,memberOfGroups,orgAddresses,orgContacts,orgOid,orgKPP,orgLegalForm,orgINN,orgName,orgShortName,orgOGRN,orgPosition,orgType,password)
VALUES (2006102,'ivan','Иван','Пупкин','Анатольевич',NULL,null,'1072221005537','ivan@exampl.ru','PWD','b0db6fd1-d674-47bb-8f22-9f8291e59255',null,'E','ADMIN,210fzmoderator','<?xml version="1.0" encoding="UTF-8" standalone="yes"?><orgAddresses><address><addressType>ORG_POSTAL</addressType><contryChar3Code>RUS</contryChar3Code><index>601120</index><region>Владимирская Область</region><district>Петушинский Район</district><house>2</house><corpus>1</corpus><structure>2</structure><flat>3</flat></address><address><addressType>ORG_LEGAL</addressType><contryChar3Code>RUS</contryChar3Code><index>150006</index><region>г Белгород</region><street>ул Ленина</street><house>47</house></address></orgAddresses>','<?xml version="1.0" encoding="UTF-8" standalone="yes"?><orgContacts><contact><contactType>PHN</contactType><value>+7(966)6666666</value><verificationStatus>N</verificationStatus></contact><contact><contactType>EML</contactType><value>kamolin@esia.ru</value><verificationStatus>N</verificationStatus></contact></orgContacts>','48479','463201002','12165','000-000-000 00','Открытое акционерное общество"Рога и копыта2"','ОАО "Рога и копыта2"','000000000000000','Директор','B','RuRKoLwh2Kgm15NE3zi+Sw==');

INSERT INTO users.esia_users (userId,userName,firstName,lastName,middleName,personINN ,personSNILS,personOGRN,personEMail,authnMethod,authToken,personType,globalRole,memberOfGroups,orgAddresses,orgContacts,orgOid,orgKPP,orgLegalForm,orgINN,orgName,orgShortName,orgOGRN,orgPosition,orgType,password)
VALUES (2006103,'uoadmin','Админ','Админов','Админович',NULL,null,'1072221005544','admin@hcs.lanit.ru','PWD','f6457868-acfd-4500-a6cb-75e8d5e700898',null,'E','ADMIN','<?xml version="1.0" encoding="UTF-8" standalone="yes"?><orgAddresses><address><addressType>ORG_POSTAL</addressType><contryChar3Code>RUS</contryChar3Code><index>601120</index><region>Владимирская Область</region><district>Петушинский Район</district><house>2</house><corpus>1</corpus><structure>2</structure><flat>3</flat></address><address><addressType>ORG_LEGAL</addressType><contryChar3Code>RUS</contryChar3Code><index>150006</index><region>г Белгород</region><street>ул Ленина</street><house>47</house></address></orgAddresses>','<?xml version="1.0" encoding="UTF-8" standalone="yes"?><orgContacts><contact><contactType>PHN</contactType><value>+7(966)6666667</value><verificationStatus>N</verificationStatus></contact><contact><contactType>EML</contactType><value>kamolin@esia.ru</value><verificationStatus>N</verificationStatus></contact></orgContacts>','7c1d2bf2-a477-4b43-af8a-0642457e2b71','463201002','12165','000-000-000 00','Открытое акционерное общество"Рога и копыта"','ОАО "Рога и копыта"','000000000000000','Админ','B','RuRKoLwh2Kgm15NE3zi+Sw==');
INSERT INTO users.esia_users (userId,userName,firstName,lastName,middleName,personINN ,personSNILS,personOGRN,personEMail,authnMethod,authToken,personType,globalRole,memberOfGroups,orgAddresses,orgContacts,orgOid,orgKPP,orgLegalForm,orgINN,orgName,orgShortName,orgOGRN,orgPosition,orgType,password)
VALUES (2006104,'uospec','Специалист','Спец','Специалистович',NULL,null,'1072221005758','upspec@hcs.lanit.ru','PWD','4cffa751-9a56-4460-b5c9-7db3c6385096',null,'E','AUTHORIZED_SPECIALIST','<?xml version="1.0" encoding="UTF-8" standalone="yes"?><orgAddresses><address><addressType>ORG_POSTAL</addressType><contryChar3Code>RUS</contryChar3Code><index>601120</index><region>Владимирская Область</region><district>Петушинский Район</district><house>3</house><corpus>2</corpus><structure>3</structure><flat>4</flat></address><address><addressType>ORG_LEGAL</addressType><contryChar3Code>RUS</contryChar3Code><index>150006</index><region>г Белгород</region><street>ул Ленина</street><house>47</house></address></orgAddresses>','<?xml version="1.0" encoding="UTF-8" standalone="yes"?><orgContacts><contact><contactType>PHN</contactType><value>+7(966)6666668</value><verificationStatus>N</verificationStatus></contact><contact><contactType>EML</contactType><value>kamolin@esia.ru</value><verificationStatus>N</verificationStatus></contact></orgContacts>','1b424148-ea6f-421b-8657-470c6d98b468','463201002','12165','000-000-000 00','Закрытое акционерное общество "РОСПИЛ"','ЗАО "РОСПИЛ"','000000000000000','Специалист','L','RuRKoLwh2Kgm15NE3zi+Sw==');

INSERT INTO users.roles (userid, role) VALUES (2006101, 'CITIZEN');
INSERT INTO users.roles (userid, role) VALUES (2006102, 'ADMIN');
INSERT INTO users.roles (userid, role) VALUES (2006103, 'ADMIN');
INSERT INTO users.roles (userid, role) VALUES (2006104, 'AUTHORIZED_SPECIALIST');

