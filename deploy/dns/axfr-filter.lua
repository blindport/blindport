function axfrfilter(_remoteip, _zone, record)
    local qtype = record:qtype()
    if qtype == pdns.RRSIG or qtype == pdns.NSEC or qtype == pdns.NSEC3 or
        qtype == pdns.NSEC3PARAM or qtype == pdns.DNSKEY then
        return 0, {}
    end
    return -1, {}
end
