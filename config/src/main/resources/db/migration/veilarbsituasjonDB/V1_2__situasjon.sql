CREATE TABLE SITUASJON (
  AKTORID VARCHAR(20) NOT NULL,
  OPPFOLGING NUMBER(1,0) NOT NULL,
  GJELDENDE_STATUS NUMBER,
  GJELDENDE_BRUKERVILKAR NUMBER,
  PRIMARY KEY (AKTORID)
);

CREATE TABLE BRUKERVILKAR (
  ID NUMBER NOT NULL,
  AKTORID VARCHAR(20) NOT NULL,
  DATO TIMESTAMP,
  VILKARSTATUS VARCHAR(20),
  TEKST VARCHAR(4000),
  PRIMARY KEY (ID),
  FOREIGN KEY (AKTORID) REFERENCES SITUASJON (AKTORID)
);
CREATE SEQUENCE BRUKERVILKAR_SEQ START WITH 1;

CREATE TABLE STATUS (
  ID NUMBER NOT NULL,
  AKTORID VARCHAR(20) NOT NULL,
  MANUELL NUMBER(1,0),
  DATO TIMESTAMP,
  BEGRUNNELSE VARCHAR(250),
  PRIMARY KEY (ID),
  FOREIGN KEY (AKTORID) REFERENCES SITUASJON (AKTORID)
);
CREATE SEQUENCE STATUS_SEQ START WITH 1;
