-- A retained audit append and its head are one statement. The successor
-- comparison stays unsigned across 0x7fffffffffffffff and refuses exhaustion.
CREATE TRIGGER authority_audit_exact_next BEFORE INSERT ON authority_audit
 WHEN NOT EXISTS(SELECT 1 FROM authority_audit_heads h
  WHERE h.org_id=NEW.org_id AND h.project_id=NEW.project_id
   AND h.event_hash=NEW.previous_hash
   AND ((substr(hex(NEW.sequence),1,0)=substr(hex(h.sequence),1,0) AND substr(hex(h.sequence),1,1)!='F' AND substr(hex(NEW.sequence),1,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(h.sequence),1,1)),1) AND substr(hex(h.sequence),2)='FFFFFFFFFFFFFFF' AND substr(hex(NEW.sequence),2)='000000000000000')
   OR (substr(hex(NEW.sequence),1,1)=substr(hex(h.sequence),1,1) AND substr(hex(h.sequence),2,1)!='F' AND substr(hex(NEW.sequence),2,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(h.sequence),2,1)),1) AND substr(hex(h.sequence),3)='FFFFFFFFFFFFFF' AND substr(hex(NEW.sequence),3)='00000000000000')
   OR (substr(hex(NEW.sequence),1,2)=substr(hex(h.sequence),1,2) AND substr(hex(h.sequence),3,1)!='F' AND substr(hex(NEW.sequence),3,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(h.sequence),3,1)),1) AND substr(hex(h.sequence),4)='FFFFFFFFFFFFF' AND substr(hex(NEW.sequence),4)='0000000000000')
   OR (substr(hex(NEW.sequence),1,3)=substr(hex(h.sequence),1,3) AND substr(hex(h.sequence),4,1)!='F' AND substr(hex(NEW.sequence),4,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(h.sequence),4,1)),1) AND substr(hex(h.sequence),5)='FFFFFFFFFFFF' AND substr(hex(NEW.sequence),5)='000000000000')
   OR (substr(hex(NEW.sequence),1,4)=substr(hex(h.sequence),1,4) AND substr(hex(h.sequence),5,1)!='F' AND substr(hex(NEW.sequence),5,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(h.sequence),5,1)),1) AND substr(hex(h.sequence),6)='FFFFFFFFFFF' AND substr(hex(NEW.sequence),6)='00000000000')
   OR (substr(hex(NEW.sequence),1,5)=substr(hex(h.sequence),1,5) AND substr(hex(h.sequence),6,1)!='F' AND substr(hex(NEW.sequence),6,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(h.sequence),6,1)),1) AND substr(hex(h.sequence),7)='FFFFFFFFFF' AND substr(hex(NEW.sequence),7)='0000000000')
   OR (substr(hex(NEW.sequence),1,6)=substr(hex(h.sequence),1,6) AND substr(hex(h.sequence),7,1)!='F' AND substr(hex(NEW.sequence),7,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(h.sequence),7,1)),1) AND substr(hex(h.sequence),8)='FFFFFFFFF' AND substr(hex(NEW.sequence),8)='000000000')
   OR (substr(hex(NEW.sequence),1,7)=substr(hex(h.sequence),1,7) AND substr(hex(h.sequence),8,1)!='F' AND substr(hex(NEW.sequence),8,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(h.sequence),8,1)),1) AND substr(hex(h.sequence),9)='FFFFFFFF' AND substr(hex(NEW.sequence),9)='00000000')
   OR (substr(hex(NEW.sequence),1,8)=substr(hex(h.sequence),1,8) AND substr(hex(h.sequence),9,1)!='F' AND substr(hex(NEW.sequence),9,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(h.sequence),9,1)),1) AND substr(hex(h.sequence),10)='FFFFFFF' AND substr(hex(NEW.sequence),10)='0000000')
   OR (substr(hex(NEW.sequence),1,9)=substr(hex(h.sequence),1,9) AND substr(hex(h.sequence),10,1)!='F' AND substr(hex(NEW.sequence),10,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(h.sequence),10,1)),1) AND substr(hex(h.sequence),11)='FFFFFF' AND substr(hex(NEW.sequence),11)='000000')
   OR (substr(hex(NEW.sequence),1,10)=substr(hex(h.sequence),1,10) AND substr(hex(h.sequence),11,1)!='F' AND substr(hex(NEW.sequence),11,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(h.sequence),11,1)),1) AND substr(hex(h.sequence),12)='FFFFF' AND substr(hex(NEW.sequence),12)='00000')
   OR (substr(hex(NEW.sequence),1,11)=substr(hex(h.sequence),1,11) AND substr(hex(h.sequence),12,1)!='F' AND substr(hex(NEW.sequence),12,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(h.sequence),12,1)),1) AND substr(hex(h.sequence),13)='FFFF' AND substr(hex(NEW.sequence),13)='0000')
   OR (substr(hex(NEW.sequence),1,12)=substr(hex(h.sequence),1,12) AND substr(hex(h.sequence),13,1)!='F' AND substr(hex(NEW.sequence),13,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(h.sequence),13,1)),1) AND substr(hex(h.sequence),14)='FFF' AND substr(hex(NEW.sequence),14)='000')
   OR (substr(hex(NEW.sequence),1,13)=substr(hex(h.sequence),1,13) AND substr(hex(h.sequence),14,1)!='F' AND substr(hex(NEW.sequence),14,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(h.sequence),14,1)),1) AND substr(hex(h.sequence),15)='FF' AND substr(hex(NEW.sequence),15)='00')
   OR (substr(hex(NEW.sequence),1,14)=substr(hex(h.sequence),1,14) AND substr(hex(h.sequence),15,1)!='F' AND substr(hex(NEW.sequence),15,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(h.sequence),15,1)),1) AND substr(hex(h.sequence),16)='F' AND substr(hex(NEW.sequence),16)='0')
   OR (substr(hex(NEW.sequence),1,15)=substr(hex(h.sequence),1,15) AND substr(hex(h.sequence),16,1)!='F' AND substr(hex(NEW.sequence),16,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(h.sequence),16,1)),1) AND substr(hex(h.sequence),17)='' AND substr(hex(NEW.sequence),17)=''))
   AND NOT EXISTS(SELECT 1 FROM authority_audit a WHERE a.org_id=h.org_id
    AND a.project_id=h.project_id AND a.sequence>h.sequence)
   AND (h.sequence=x'0000000000000000' AND h.event_hash=zeroblob(32)
    OR EXISTS(SELECT 1 FROM authority_audit a WHERE a.org_id=h.org_id AND a.project_id=h.project_id
     AND a.sequence=h.sequence AND a.event_hash=h.event_hash AND a.recorded_at<=NEW.recorded_at)))
 BEGIN SELECT RAISE(ABORT,'authority audit requires exact next event'); END;
CREATE TRIGGER authority_audit_project_head AFTER INSERT ON authority_audit
 BEGIN
 UPDATE authority_audit_heads SET sequence=NEW.sequence,event_hash=NEW.event_hash
  WHERE org_id=NEW.org_id AND project_id=NEW.project_id;
 END;

-- A binding is created by the event statement after the event exists. No
-- pending binding can be staged or committed, even with foreign_keys=OFF.
DROP TRIGGER authority_signing_work_audits_exact;
DROP TRIGGER authority_signing_work_events_audit;
CREATE TRIGGER authority_signing_work_audits_exact BEFORE INSERT ON authority_signing_work_audits
 WHEN NOT EXISTS(SELECT 1 FROM authority_signing_work_events e
  JOIN authority_audit a ON a.org_id=e.org_id AND a.project_id=e.project_id
  JOIN authority_audit_heads h ON h.org_id=a.org_id AND h.project_id=a.project_id
   AND h.sequence=a.sequence AND h.event_hash=a.event_hash
  WHERE e.org_id=NEW.org_id AND e.project_id=NEW.project_id AND e.job_id=NEW.job_id
   AND e.phase=NEW.phase AND e.revision=NEW.revision AND e.kind=NEW.kind AND e.updated_at=NEW.updated_at
   AND a.sequence=NEW.audit_sequence AND a.event_hash=NEW.audit_hash
   AND a.kind='signing_'||NEW.phase||'_'||NEW.kind AND a.resource_id=NEW.job_id AND a.recorded_at=NEW.updated_at
   AND NOT EXISTS(SELECT 1 FROM authority_signing_work_events n WHERE n.org_id=e.org_id
    AND n.project_id=e.project_id AND n.job_id=e.job_id AND n.phase=e.phase AND n.revision>e.revision)
   AND NOT EXISTS(SELECT 1 FROM authority_signing_work_audits p WHERE p.org_id=NEW.org_id
    AND p.project_id=NEW.project_id AND p.job_id=NEW.job_id AND p.phase=NEW.phase
    AND p.audit_sequence>=NEW.audit_sequence))
 BEGIN SELECT RAISE(ABORT,'signing work audit requires retained current event'); END;
CREATE TRIGGER authority_signing_work_events_audit BEFORE INSERT ON authority_signing_work_events
 WHEN NOT EXISTS(SELECT 1 FROM authority_audit a JOIN authority_audit_heads h
  ON h.org_id=a.org_id AND h.project_id=a.project_id AND h.sequence=a.sequence AND h.event_hash=a.event_hash
  WHERE a.org_id=NEW.org_id AND a.project_id=NEW.project_id
   AND a.kind='signing_'||NEW.phase||'_'||NEW.kind AND a.resource_id=NEW.job_id AND a.recorded_at=NEW.updated_at
   AND NOT EXISTS(SELECT 1 FROM authority_signing_work_audits b WHERE b.org_id=a.org_id
    AND b.project_id=a.project_id AND (b.audit_sequence=a.sequence OR b.audit_hash=a.event_hash
     OR (b.job_id=NEW.job_id AND b.phase=NEW.phase AND b.revision=NEW.revision)))
   AND NOT EXISTS(SELECT 1 FROM authority_signing_work_audits p WHERE p.org_id=NEW.org_id
    AND p.project_id=NEW.project_id AND p.job_id=NEW.job_id AND p.phase=NEW.phase
    AND p.audit_sequence>=a.sequence))
 BEGIN SELECT RAISE(ABORT,'signing work event requires unconsumed current audit'); END;
CREATE TRIGGER authority_signing_work_events_project_audit AFTER INSERT ON authority_signing_work_events
 BEGIN
 INSERT INTO authority_signing_work_audits
  SELECT NEW.org_id,NEW.project_id,NEW.job_id,NEW.phase,NEW.revision,NEW.kind,NEW.updated_at,h.sequence,h.event_hash
  FROM authority_audit_heads h WHERE h.org_id=NEW.org_id AND h.project_id=NEW.project_id;
 END;

-- Independent live held-obligation enumeration does not trust mutable heads.
CREATE INDEX authority_signing_quota_project_states
 ON authority_signing_quota_reservations(org_id,project_id,state);
CREATE INDEX authority_signing_quota_root_states
 ON authority_signing_quota_reservations(org_id,root_id,state);
