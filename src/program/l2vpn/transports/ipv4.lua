local ipv4 = require("lib.protocol.ipv4")
local packet = require("core.packet")

local transport = subClass(nil)

function transport:new (conf, tunnel_proto, logger)
   local o = transport:superClass().new(self)
   assert(conf and conf.src and conf.dst,
          "missing transport configuration")
   for _, key in ipairs({'src', 'dst'}) do
      if type(conf[key]) == "string" then
         conf[key] = ipv4:pton(conf[key])
      end
   end
   o.header = ipv4:new({ protocol = tunnel_proto,
                         ttl = conf.hop_limit or nil,
                         src = conf.src,
                         dst = conf.dst })
   o.header:checksum()
   o.total_header_size = o.header:sizeof() + tunnel_header:sizeof()
   o.peer = ipv4:ntop(conf.dst)
   o.logger = logger
   return o
end

function transport:encapsulate (datagram, tunnel_header)
   local h = self.header
   local old_length = h:total_length()
   local new_length = self.total_header_size + datagram:packet().length
   self.header:total_length(new_length)
   -- Incremental computation of new checksum, see RFC1624
   local old_csum = self.header:header().checksum
   local new_csum = bit.bnot(bit.bnot(old_csum) + bit.bnot(new_length)
                                + old_length)
   self.header:header().checksum = lib.htons(new_csum)
end

return transport
