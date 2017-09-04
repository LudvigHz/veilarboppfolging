ALTER TABLE SITUASJON
  ADD VEILEDER VARCHAR2(20);

ALTER TABLE SITUASJON
  ADD OPPDATERT TIMESTAMP(3);


UPDATE SITUASJON SIT
SET SIT.VEILEDER = (SELECT VEILEDER
                    FROM AKTOER_ID_TO_VEILEDER A_TO_V
                    WHERE SIT.AKTORID = A_TO_V.AKTOERID),
  SIT.OPPDATERT  = (SELECT OPPDATERT
                    FROM AKTOER_ID_TO_VEILEDER A_TO_V
                    WHERE SIT.AKTORID = A_TO_V.AKTOERID);

BEGIN
  FOR TILORDNING IN
  (SELECT
     AKTOERID,
     VEILEDER,
     OPPDATERT
   FROM AKTOER_ID_TO_VEILEDER A_TO_V
   WHERE AKTOERID NOT IN (SELECT AKTORID
                          FROM SITUASJON))
  LOOP
    INSERT INTO SITUASJON (AKTORID, VEILEDER, OPPDATERT, OPPFOLGING)
    VALUES (TILORDNING.AKTOERID, TILORDNING.VEILEDER, TILORDNING.OPPDATERT, 1);
  END LOOP;
END;


