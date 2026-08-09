-- wrk pipelining script: send N GETs per connection in one write.
-- usage: wrk -t28 -c600 -d10s -s scripts/pipeline.lua https://host:port/ -- <depth>
init = function(args)
  local depth = tonumber(args[1]) or 16
  local r = {}
  for i = 1, depth do r[i] = wrk.format("GET", "/") end
  req = table.concat(r)
end

request = function() return req end
