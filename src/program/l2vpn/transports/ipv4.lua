local lib = require("core.lib")
local ipv4 = require("lib.protocol.ipv4")
local packet = require("core.packet")
require("lib.checksum_h")
local ffi = require("ffi")
local C = ffi.C

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
                         ttl = conf.hop_limit or 64,
                         src = conf.src,
                         dst = conf.dst })
   -- Offsets in units of uint16_t
   o.csum_offset = ffi.offsetof(o.header:header(), 'checksum')/2
   o.length_offset = ffi.offsetof(o.header:header(), 'total_length')/2
   o.peer = ipv4:ntop(conf.dst)
   o.logger = logger
   return o
end

function transport:encapsulate (datagram, header, tunnel_header)
   local new_length = header:sizeof() + tunnel_header:sizeof() +
      datagram:packet().length
   local h_ptr = ffi.cast("uint16_t *", header:header_ptr())
   C.checksum_update_incremental_16(h_ptr + self.csum_offset,
                                    h_ptr + self.length_offset, new_length)
end

return transport
