module(..., package.seeall)
local ffi = require("ffi")
local lib = require("core.lib")
local ethernet = require("lib.protocol.ethernet")

af_demux = subClass(nil)
af_demux._name = "Address family demultiplexer"

function af_demux:new ()
   local o = af_demux:superClass().new(self)
   o.discard = link.new("discard")
   o.type2link = ffi.new("struct link *[65536]", o.discard)
   o.ether = ethernet:new({})
   return o
end

function af_demux:link ()
   for name, l in pairs(self.output) do
      if type(name) == "string" then
         if name == "ipv4" then
            self.type2link[0x0800] = l -- IPv4
            self.type2link[0x0806] = l -- ARP
         elseif name == "ipv6" then
            self.type2link[0x86dd] = l -- IPv6
         end
      end
   end
end

function af_demux:push ()
   local isouth = self.input.south
   for _ = 1, link.nreadable(isouth) do
      local p = link.receive(isouth)
      local ether = ffi.cast(self.ether._header.ptr_t, p.data)
      local type = lib.ntohs(ether.ether_type)
      link.transmit(self.type2link[type], p)
   end

   for _ = 1, link.nreadable(self.discard) do
      packet.free(link.receive(self.discard))
   end
   
   local iv4, iv6 = self.input.ipv4, self.input.ipv6
   local osouth = self.output.south
   for _ = 1, link.nreadable(iv4) do
      link.transmit(osouth, link.receive(iv4))
   end
   for _ = 1, link.nreadable(iv6) do
      link.transmit(osouth, link.receive(iv6))
   end
end
