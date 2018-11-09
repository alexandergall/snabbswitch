module(..., package.seeall)
local ffi = require("ffi")
local lib = require("core.lib")
local ethernet = require("lib.protocol.ethernet")

af_demux = subClass(nil)
af_demux._name = "Address family demultiplexer"

function af_demux:new ()
   local o = af_demux:superClass().new(self)
   o.ether = ethernet:new({})
   return o
end

function af_demux:push ()
   local from_south = self.input.south
   local to_v4, to_v6 = self.output.ipv4, self.output.ipv6
   for _ = 1, link.nreadable(from_south) do
      local p = link.receive(from_south)
      local ether = ffi.cast(self.ether._header.ptr_t, p.data)
      local type = lib.ntohs(ether.ether_type)
      if type == 0x0800 or type == 0x0806 then
         link.transmit(to_v4, p)
      elseif type == 0x86dd then
         link.transmit(to_v6, p)
      else
         packet.free(p)
      end
   end

   local from_v4, from_v6 = self.input.ipv4, self.input.ipv6
   local to_south = self.output.south
   for _ = 1, link.nreadable(from_v4) do
      link.transmit(to_south, link.receive(from_v4))
   end
   for _ = 1, link.nreadable(from_v6) do
      link.transmit(to_south, link.receive(from_v6))
   end
end
