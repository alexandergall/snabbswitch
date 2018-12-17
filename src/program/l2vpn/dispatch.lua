-- Use of this source code is governed by the Apache 2.0 license; see COPYING.

-- This app is a multiplexer/demultiplexer based on the IP source and
-- destination address of a packet.  It has a well-known port called
-- "south" that connects to the network and carries the multiplexed
-- traffic.
--
-- The app is created with a list of mappings of port names to IP
-- source and destination addresses for a particular address family
-- (ipv4 or ipv6).
--

module(..., package.seeall)
local ffi = require("ffi")
local lib = require("core.lib")
local ethernet = require("lib.protocol.ethernet")
local ctable = require("lib.ctable_perfect")

dispatch = {}

local params = {
   afi = { required = true },
   links = {
      keysof =
         {
            src = { required = true },
            dst = { required = true }
         }
   }
}

local afs = {
   ipv4 = {
      offset = 12,
      key_t = ffi.typeof([[
        struct {
          uint8_t src[4];
          uint8_t dst[4];
        }
      ]])
   },
   ipv6 = {
      offset = 8,
      key_t = ffi.typeof([[
        struct {
          uint8_t src[16];
          uint8_t dst[16];
        }
      ]])
  }
}

function dispatch:new (args)
   local o = {}
   local conf = lib.parse(args, params)
   local af = afs[conf.afi]
   assert(af, "Invalid address family identifier "..conf.afi)

   local key_t = af.key_t
   o.offset = ethernet:sizeof() + af.offset
   o.key_ptr_t = ffi.typeof("$*", key_t)
   o.discard = link.new("dispatch_discard")

   o.links, o.keys_by_name = {}, {}
   local keys = {}
   for name, addrs in pairs(conf.links) do
      local key = key_t()
      key.src = addrs.src
      key.dst = addrs.dst
      table.insert(keys, key)
      table.insert(o.links, name)
      o.keys_by_name[name] = key
   end
   o.ctab = ctable.new({
         key_type = key_t,
         value_type = ffi.typeof("struct link *"),
         keys = keys,
         default_value = o.discard })
   o.nlinks = #o.links

   return setmetatable(o, { __index = dispatch })
end

function dispatch:link ()
   for name, l in pairs(self.output) do
      if type(name) == "string" and name ~= "south" then
         local key = assert(self.keys_by_name[name])
         self.ctab:update(key, l)
      end
   end
end

function dispatch:push()
   local sin = self.input.south
   local sout = self.output.south

   for _ = 1, link.nreadable(sin) do
      local p = link.receive(sin)
      local key = ffi.cast(self.key_ptr_t, p.data + self.offset)
      local entry = self.ctab:lookup_ptr(key)
      link.transmit(entry.value, p)
   end

   local discard = self.discard
   for _ = 1, link.nreadable(discard) do
      packet.free(link.receive(discard))
   end

   for i = 1, self.nlinks do
      local name = self.links[i]

      local lin = self.input[name]
      for _ = 1, link.nreadable(lin) do
         link.transmit(sout, link.receive(lin))
      end
   end

end
