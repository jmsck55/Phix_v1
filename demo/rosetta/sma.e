--
-- demo\rosetta\sma.e
-- ==================
--
-- Part of demo\rosetta\Averages_SimpleMovingAverage.exw
-- This is in a separate file to encapsulate the private variables:

sequence sma = {}       -- {{period,history,circnxt}}  (private to sma.e)
integer sma_free = 0

global function new_sma(integer period)
integer res
    if sma_free then
        res = sma_free
        sma_free = sma[sma_free]
        sma[res] = {period,{},0}
    else
        sma = append(sma,{period,{},0})
        res = length(sma)
    end if
    return res
end function

global procedure add_sma(integer sidx, atom val)
integer period, circnxt
sequence history
    {period,history,circnxt} = sma[sidx]
    sma[sidx][2] = 0 -- (kill refcount)
    if length(history)<period then
        history = append(history,val)
    else
        circnxt += 1
        if circnxt>period then
            circnxt = 1
        end if
        sma[sidx][3] = circnxt
        history[circnxt] = val
    end if
    sma[sidx][2] = history
end procedure

global function get_sma_average(integer sidx)
sequence history = sma[sidx][2]
integer l = length(history)
    if l=0 then return 0 end if
    return sum(history)/l
end function

global function moving_average(integer sidx, atom val)
    add_sma(sidx,val)
    return get_sma_average(sidx)
end function

global procedure free_sma(integer sidx)
    sma[sidx] = sma_free
    sma_free = sidx
end procedure


