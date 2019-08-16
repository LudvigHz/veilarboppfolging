CREATE TABLE VEILEDER_TILLORDNINGER (
  AKTOR_ID VARCHAR(20) NOT NULL,
  VEILEDER VARCHAR(20) NOT NULL,
  SIST_TILORDNET TIMESTAMP,
  PRIMARY KEY (AKTOERID,VEILEDERID, SIST_TILORDNET)
);

INSERT INTO VEILEDER_TILLORDNINGER (AKTOR_ID, VEILEDER, SIST_TILORDNET)
SELECT (AKTOR_ID, VEILEDER, SIST_TILORDNET) FROM OPPFOLGINGSTATUS;