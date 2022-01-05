pdnslog("pdns-recursor Lua script starting!", pdns.loglevels.Info)

-- user config --
hazard_response_a = "127.0.0.1"
cert_hole_response_a = {"195.187.6.33","195.187.6.34","195.187.6.35"}
-- user config --

hazardMetric = getMetric("blackhole-hazard")
hazard = newDS()
for line in io.lines("/etc/powerdns/hazard_domains.txt") do
    hazard:add {line}
end

malwareMetric = getMetric("blackhole-malware")
malware = newDS()
for line in io.lines("/etc/powerdns/malware_domains.txt") do
    malware:add {line}
end

cert_holeMetric = getMetric("blackhole-cert")
cert_hole = newDS()
for line in io.lines("/etc/powerdns/cert_domains.txt") do
    cert_hole:add {line}
end

function preresolve(dq)
    if hazard:check(dq.qname) then
        if dq.qtype == pdns.A then
            log_entry =
                string.format(
                "hazard domain query type %s from %s, (REWRITE): %s",
                dq.qtype,
                dq.remoteaddr:toString(),
                dq.qname:toString()
            )
            pdnslog(log_entry, pdns.loglevels.Info)
            dq:addAnswer(pdns.A, hazard_response_a)

            hazardMetric:inc()

            return true
        else
            log_entry =
                string.format(
                "hazard domain query type %s from %s, (NODATA): %s",
                dq.qtype,
                dq.remoteaddr:toString(),
                dq.qname:toString()
            )
            pdnslog(log_entry, pdns.loglevels.Info)
            dq.appliedPolicy.policyKind = pdns.policykinds.NODATA

            hazardMetric:inc()
        end
    end

    if cert_hole:check(dq.qname) then
        if dq.qtype == pdns.A then
            log_entry =
                string.format(
                "cert_hole domain query type %s from %s, (REWRITE): %s",
                dq.qtype,
                dq.remoteaddr:toString(),
                dq.qname:toString()
            )
            pdnslog(log_entry, pdns.loglevels.Info)
            for i, a in ipairs(cert_hole_response_a) do
                dq:addAnswer(pdns.A, a)
            end

            cert_holeMetric.inc()

            return true
        else
            log_entry =
                string.format(
                "cert_hole domain query type %s from %s, (NODATA): %s",
                dq.qtype,
                dq.remoteaddr:toString(),
                dq.qname:toString()
            )
            pdnslog(log_entry, pdns.loglevels.Info)
            dq.appliedPolicy.policyKind = pdns.policykinds.NODATA

            cert_holeMetric.inc()
        end
    end

    if malware:check(dq.qname) then
        log_entry =
            string.format(
            "malware domain query type %s from %s, (NXDOMAIN): %s",
            dq.qtype,
            dq.remoteaddr:toString(),
            dq.qname:toString()
        )
        pdnslog(log_entry, pdns.loglevels.Info)
        dq.appliedPolicy.policyKind = pdns.policykinds.NXDOMAIN

        malwareMetric.inc()
    end

    return false
end
