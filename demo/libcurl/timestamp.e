--
-- timestamp.e
--

include builtins\timedate.e

timedate t0 = parse_date_string("1/1/1970 UTC",{"D/M/YYYY tz"})

object timezone = 0

--DEV passing in a date and time has not been tested
public function timestamp(string name, bool withDot=false, sequence d={})
    if d={} then
        d = date(bMsecs:=true)
    else
        d[DT_MSEC] = 0
    end if
--  d = set_timezone(d,"UTC")
--  d = set_timezone(d,"CST")
--  d = change_timezone(d,"UTC")
--  d = change_timezone(d,"CST")
    if timezone=0 then
        -- (this is probably a temporary file, but good enough for now)
        integer tzfn = open("timezone.txt","r")
        if tzfn=-1 then
            -- specify dst even when out-of-season, so it kicks in naturally.
            puts(1,"Enter daylight savings timezone (eg BST rather than GMT):")
            timezone = upper(trim(gets(0)))
        else
            timezone = trim(gets(tzfn))
            close(tzfn)
        end if
        -- this will crash if timezone is not in timedate.e/timezones:
        d = set_timezone(d,timezone)
        d = change_timezone(d,"UTC")
        if tzfn=-1 then
            tzfn = open("timezone.txt","w")
            puts(tzfn,timezone)
            close(tzfn)
        end if
    else
        d = set_timezone(d,timezone)
        d = change_timezone(d,"UTC")
    end if
    d = adjust_timedate(d,timedelta(milliseconds:=get_drift(name)))
    string res = sprintf("%d%s%03d",{timedate_diff(t0,d,DT_SECOND),
                                     iff(withDot?".":""),
                                     d[DT_MSEC]})
--  sleep(0.001)    -- (ensure uniqueness - probably not necessary)
    if name="Poloniex" and length(res)!=13 then ?9/0 end if
    return res
end function

public function timestamp_ms(string name)
    sequence d = date(bMsecs:=true)
    d = set_timezone(d,timezone)
    d = change_timezone(d,"UTC")
    atom drift = get_drift(name)
    atom delta = timedelta(milliseconds:=drift)
    d = adjust_timedate(d,delta)
    atom res = timedate_diff(t0,d,DT_SECOND)*1000+d[DT_MSEC]
    return res
end function

public function db_date(object td)
    if not timedate(td) then
        return "TimeDate Error"
    end if
    return format_timedate(td, "YYYY-MM-DD hh:mm:ss.ms")
end function

public function date_string_to_timedate(string s, string pattern = "YYYY-MM-DD hh:mm:ss")
--
-- convert a string to a timedate
-- common patterns:
--   "2018-04-27T00:48:01.334000Z"
--   "2019-04-18 22:23:23" from poloniex /returnOpenOrders

    integer dot = find('.',s)
    if dot > 0 then
        s = s[1..dot+3]
        pattern = "YYYY-MM-DD'T'hh:mm:ss.ms"
    end if
    return parse_date_string(s,{pattern})
end function


