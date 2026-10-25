"""The Lua scripts the AI call limiters (app/ai/slots.py) run on Redis: each is one atomic step, timed by
the Redis server's own clock (TIME), so pods whose clocks differ still agree."""

#: KEYS[1] the slots · KEYS[2] the limit a 429 set · ARGV[1] the cap (0 = none) · ARGV[2] the lease's seconds
#: · ARGV[3] the call's id. 1 = taken, 0 = every slot is busy. No cap and no limit: always taken.
TAKE_FREE_SLOT_SCRIPT = """
local now_parts = redis.call('TIME')
local now = tonumber(now_parts[1]) + tonumber(now_parts[2]) / 1000000
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
local cap = tonumber(ARGV[1])
local limit = tonumber(redis.call('HGET', KEYS[2], 'limit'))
if limit and (cap == 0 or limit < cap) then cap = math.floor(limit) end
if cap > 0 and redis.call('ZCARD', KEYS[1]) >= cap then return 0 end
redis.call('ZADD', KEYS[1], now + tonumber(ARGV[2]), ARGV[3])
return 1
"""

#: KEYS[1] the slots · KEYS[2] the limit · ARGV[1] the call's id · ARGV[2] '1': the call was answered, which
#: raises a 429's limit by 1 / limit (nothing while none is set).
FREE_SLOT_SCRIPT = """
redis.call('ZREM', KEYS[1], ARGV[1])
if ARGV[2] == '1' then
  local limit = tonumber(redis.call('HGET', KEYS[2], 'limit'))
  if limit then redis.call('HSET', KEYS[2], 'limit', tostring(limit + 1 / limit)) end
end
return 0
"""

#: KEYS[1] the slots · KEYS[2] the limit. A 429 cuts it to half the calls in flight when that is lower, at
#: most once every ARGV[2] s, never below ARGV[1], and renews its time to live, ARGV[3] s. The limit a cut
#: set, else 0.
CUT_LIMIT_SCRIPT = """
local limit = tonumber(redis.call('HGET', KEYS[2], 'limit'))
local now_parts = redis.call('TIME')
local now = tonumber(now_parts[1]) + tonumber(now_parts[2]) / 1000000
local cut = 0
if not limit or now - tonumber(redis.call('HGET', KEYS[2], 'cut_at')) >= tonumber(ARGV[2]) then
  redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
  cut = math.max(tonumber(ARGV[1]), math.floor(redis.call('ZCARD', KEYS[1]) / 2))
  if limit and cut >= math.floor(limit) then cut = 0 end  -- not lower: the limit and its raises stay
  if cut > 0 then redis.call('HSET', KEYS[2], 'limit', cut, 'cut_at', tostring(now)) end
end
redis.call('EXPIRE', KEYS[2], ARGV[3])
return cut
"""

#: KEYS[1] the slots · ARGV[1] the lease's seconds · ARGV[2...] the calls still running. XX: a slot already
#: freed is never brought back.
RENEW_LEASES_SCRIPT = """
local now_parts = redis.call('TIME')
local ends = tonumber(now_parts[1]) + tonumber(now_parts[2]) / 1000000 + tonumber(ARGV[1])
for i = 2, #ARGV do redis.call('ZADD', KEYS[1], 'XX', ends, ARGV[i]) end
return 0
"""

#: KEYS[1] the slots. The number of calls in progress now.
COUNT_SLOTS_SCRIPT = """
local now_parts = redis.call('TIME')
local now = tonumber(now_parts[1]) + tonumber(now_parts[2]) / 1000000
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
return redis.call('ZCARD', KEYS[1])
"""

#: KEYS[1] the next send time · ARGV[1] seconds between two requests · ARGV[2] the longest wait accepted.
#: The seconds to wait, that send time then reserved; -1, nothing reserved, when the wait would be longer.
RESERVE_SEND_TIME_SCRIPT = """
local now_parts = redis.call('TIME')
local now = tonumber(now_parts[1]) + tonumber(now_parts[2]) / 1000000
local send_at = math.max(now, tonumber(redis.call('GET', KEYS[1]) or now))
local wait = send_at - now
if wait > tonumber(ARGV[2]) then
  return '-1'
end
local interval = tonumber(ARGV[1])
redis.call('SET', KEYS[1], tostring(send_at + interval), 'PX', math.ceil((wait + interval) * 1000))
return tostring(wait)
"""
