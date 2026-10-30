"""The Lua scripts the AI call limiters (app/ai/slots.py) run on Redis: each is one atomic step, timed by
the Redis server's own clock (TIME), so pods whose clocks differ still agree."""

#: KEYS[1] the slots · KEYS[2] the limit a 429 set · KEYS[3] the waiting line · KEYS[4] each waiter's last
#: poll · ARGV[1] the cap (0 = none) · ARGV[2] the lease's seconds · ARGV[3] the call's id · ARGV[4] seconds
#: after its last poll a waiter leaves the line · ARGV[5] the caller's wait · ARGV[6] '1': its last try, so a
#: refusal also takes it out of the line. 1 = taken, 0 = not its turn. No cap and no limit: always taken, no
#: line. With one, the line decides: a free slot goes to the first in it. A waiter's place is when it stops
#: waiting (its first poll + its wait), so the API's callers (30 s) go ahead of every worker (whose wait only
#: its lease ends), each in the order they came. ARGV[7...]: this process's slots whose release a Redis
#: failure missed, freed first, so no finished call still counts as in flight.
#: ponytail: a waiter that stops without its last try (a lost lease, a dead pod) keeps its place for up to
#: ARGV[4] s; leave the line on LeaseLost if those pauses ever matter.
TAKE_FREE_SLOT_SCRIPT = """
local now_parts = redis.call('TIME')
local now = tonumber(now_parts[1]) + tonumber(now_parts[2]) / 1000000
for i = 7, #ARGV do redis.call('ZREM', KEYS[1], ARGV[i]) end
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
local cap = tonumber(ARGV[1])
local limit = tonumber(redis.call('HGET', KEYS[2], 'limit'))
if limit and (cap == 0 or limit < cap) then cap = math.floor(limit) end
if cap > 0 then
  for _, waiter in ipairs(redis.call('ZRANGEBYSCORE', KEYS[4], '-inf', now - tonumber(ARGV[4]))) do
    redis.call('ZREM', KEYS[3], waiter)
    redis.call('ZREM', KEYS[4], waiter)
  end
  redis.call('ZADD', KEYS[3], 'NX', now + tonumber(ARGV[5]), ARGV[3])
  local served = redis.call('ZRANK', KEYS[3], ARGV[3]) < cap - redis.call('ZCARD', KEYS[1])
  if served or ARGV[6] == '1' then
    redis.call('ZREM', KEYS[3], ARGV[3])
    redis.call('ZREM', KEYS[4], ARGV[3])
  else
    redis.call('ZADD', KEYS[4], now, ARGV[3])
  end
  if not served then return 0 end
end
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

#: KEYS[1] a model's next send time: the seconds until it (0 when past), reserving nothing.
SECONDS_TO_SEND_TIME_SCRIPT = """
local now_parts = redis.call('TIME')
local now = tonumber(now_parts[1]) + tonumber(now_parts[2]) / 1000000
return tostring(math.max(0, tonumber(redis.call('GET', KEYS[1]) or now) - now))
"""

#: KEYS[1] a model's next send time, moved to at least ARGV[1] s from now: a 429 pauses it on every pod.
PAUSE_SEND_TIME_SCRIPT = """
local now_parts = redis.call('TIME')
local now = tonumber(now_parts[1]) + tonumber(now_parts[2]) / 1000000
local pause_end = now + tonumber(ARGV[1])
if pause_end > tonumber(redis.call('GET', KEYS[1]) or 0) then
  redis.call('SET', KEYS[1], tostring(pause_end), 'PX', math.ceil(tonumber(ARGV[1]) * 1000))
end
return 1
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
