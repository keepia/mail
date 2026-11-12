-- Keepia Mail, edge role, 0.1.0: the passdb of an edge that has no
-- routing data yet (#5 plan, coordinator decision C11). Every lookup and
-- every password check ends in a temporary failure, so a sender retries
-- later and a client is told to try again: nothing is bounced and no user
-- is reported unknown (R-REPLICA-ATOMIC, R-EDGE-UNKNOWN-4XX).

function auth_passdb_lookup(req)
  return dovecot.auth.PASSDB_RESULT_INTERNAL_FAILURE, "keepia: no routing data yet"
end

function auth_password_verify(req, pass)
  return dovecot.auth.PASSDB_RESULT_INTERNAL_FAILURE, "keepia: no routing data yet"
end
