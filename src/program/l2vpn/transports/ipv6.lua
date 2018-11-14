local ipv6 = require("lib.protocol.ipv6")
local packet = require("core.packet")

local transport = subClass(nil)

local function maybe_pton (addr)
   if type(addr) == "string" then
      return ipv6:pton(addr)
   else
      return addr
   end
end

function transport:new (conf, tunnel_proto, logger)
   local o = transport:superClass().new(self)
   assert(conf and conf.src and conf.dst,
          "missing transport configuration")
   o.header = ipv6:new({ next_header = tunnel_proto,
                         hop_limit = conf.hop_limit or nil,
                         src = maybe_pton(conf.src),
                         dst = maybe_pton(conf.dst) })
   o.peer = ipv6:ntop(maybe_pton(conf.dst))
   o.logger = logger
   return o
end

function transport:encapsulate (datagram, header, tunnel_header)
   header:payload_length(tunnel_header:sizeof()
                            + datagram:packet().length)
end

return transport
