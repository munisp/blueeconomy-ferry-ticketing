-- Boarding-consumed tickets can never be refunded or voided (FE-3).
-- The service layer guards refund/void with ErrTicketBoarded; this trigger is
-- the database-layer backstop so NO code path (present or future, including
-- ad-hoc SQL) can move a boarded ticket to REFUNDED or VOID. Once
-- boarded_at is set (first-scan-wins, atomic) or embarked is true, the
-- passenger traveled and the fare is earned.
-- Idempotent-safe, mirroring 0001/0002.

CREATE OR REPLACE FUNCTION ferry_block_boarded_refund() RETURNS trigger AS $$
BEGIN
    IF NEW.state IN ('REFUNDED', 'VOID')
       AND OLD.state <> NEW.state
       AND (OLD.boarded_at IS NOT NULL OR OLD.embarked) THEN
        RAISE EXCEPTION 'ticket % has consumed boarding; REFUNDED/VOID is not permitted', OLD.ticket_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS tickets_block_boarded_refund ON tickets;
CREATE TRIGGER tickets_block_boarded_refund
    BEFORE UPDATE ON tickets
    FOR EACH ROW
    EXECUTE FUNCTION ferry_block_boarded_refund();
