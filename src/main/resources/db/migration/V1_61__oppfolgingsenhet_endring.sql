CREATE SEQUENCE ENHET_SEQ START WITH 1;

CREATE TABLE OPPFOLGINGSENHET_ENDRET (
  AKTOR_ID VARCHAR(20),
  ENHET VARCHAR(20) NOT NULL,
  ENDRET_DATO TIMESTAMP,
  ENHET_SEQ NUMBER
);
