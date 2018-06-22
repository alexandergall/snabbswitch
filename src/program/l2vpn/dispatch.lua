-- This app is a multiplexer/demultiplexer based on the IPv6 source
-- and/or destination address of a packet.  It has a well-known port
-- called "south" that connects to the network and carries the
-- multiplexed traffic.
--
-- The app is created with a list of mappings of port names to IPv6
-- source and/or destination addresses.  A BPF filter that matches the
-- given address(es) is created for each port.
--
-- The push() method first processes all packets coming in from the
-- south port and applies the filters in turn.  When a match is found,
-- the packet is transmitted on the associated port and no more
-- filters are processed.  This implements the de-multiplexing of
-- incoming packets to specific upstream apps.
--
-- The push() method then visits each upstream port in turn and
-- multiplexes all queued packets onto the south port.

module(..., package.seeall)
local ffi = require("ffi")
local ipv6 = require("lib.protocol.ipv6")
local ctable = require("lib.ctable")

dispatch = subClass(nil)
dispatch._name = "IPv6 dispatcher"

local ipv6_header_t = ffi.typeof [[
/* All values in network byte order.  */
struct {
   uint32_t v_tc_fl;               // version:4, traffic class:8, flow label:20
   uint16_t payload_length;
   uint8_t  next_header;
   uint8_t  hop_limit;
   uint8_t  src_ip[16];
   uint8_t  dst_ip[16];
   uint8_t  payload[0];
} __attribute__((packed))
]]
local ipv6_header_ptr_t = ffi.typeof("$*", ipv6_header_t)

local key_t = ffi.typeof[[
         union {
            struct {
               uint8_t src[16];
               uint8_t dst[16];
            } addrs;
            uint8_t bytes [32];
         } __attribute((packed))]]
local value_t = ffi.typeof("struct link*")

local function perfect_hash (config)
   local npws = 0
   for _, _ in pairs(config) do npws = npws + 1 end
   local params = {
      key_type = key_t,
      value_type = value_t,
      initial_size = npws * 10,
      max_occupancy_rate = 0.5,
   }
   local ctab
   local key = key_t()
   for _ = 1, 10 do
      ctab = ctable.new(params)
      for k, addrs in pairs(config) do
         key.addrs.src = addrs.source
         key.addrs.dst = addrs.destination
         ctab:add(key, ffi.cast("struct link *", 0ULL))
      end
      if ctab.max_displacement == 0 then
         break
      end
   end
   if ctab.max_displacement ~= 0 then
      print("dispatcher: hash is not perfect")
   end
   return ctab
end

-- config: table with mappings of link names to tuples of IPv6 source
-- and/or destination addresses.
-- config = { link1 = { source = source_addr, destination = destination_addr },
--            ... }
function dispatch:new (config)
   assert(config, "missing configuration")
   local o = dispatch:superClass().new(self)
   o._pwtable = perfect_hash(config)
   o._key = key_t()
   o._config = config
   o._pw_index = 0
   return o
end

function dispatch:link ()
   for name, link in pairs(self.output) do
      if type(name) == "string" and name ~= "south" then
         local addrs = assert(self._config[name])
         self._key.addrs.src = addrs.source
         self._key.addrs.dst = addrs.destination
         local entry = assert(self._pwtable:lookup_ptr(self._key))
         entry.value = link
      end
   end

   self._pw_inputs = {}
   for name, link in pairs(self.input) do
      if type(name) == "string" and name ~= "south" then
         table.insert(self._pw_inputs, link)
      end
   end
   self._npw_inputs = #self._pw_inputs
end

local empty, full, receive, transmit = link.empty, link.full, link.receive, link.transmit
function dispatch:push()

   local l_out = self.output.south
   for i = 1, self._npw_inputs do
      local l_in = self._pw_inputs[i]
      for _ = 1, link.nreadable(l_in) do
         transmit(l_out, receive(l_in))
      end
   end

   local l_in = self.input.south
   for _ = 1, link.nreadable(l_in) do
      local p = receive(l_in)
      local h = ffi.cast(ipv6_header_ptr_t, p.data + 14)
      self._key.addrs.src = h.src_ip
      self._key.addrs.dst = h.dst_ip
      local entry = self._pwtable:lookup_ptr(self._key)
      if entry then
         transmit(entry.value, p)
      else
         packet.free(p)
      end
   end

end
