-- Use of this source code is governed by the Apache 2.0 license; see COPYING.

module(...,package.seeall)

local shm = require("core.shm")
local interlink = require("lib.interlink")

local Transmitter = {name="apps.interlink.Transmitter"}

function Transmitter:new (_, name)
   local self = {}
   self.shm_name = "group/interlink/"..name..".interlink"
   self.backlink = "interlink/transmitter/"..name..".interlink"
   self.interlink = interlink.attach_transmitter(self.shm_name)
   shm.alias(self.backlink, self.shm_name)
   return setmetatable(self, {__index=Transmitter})
end

function Transmitter:push ()
   local i, r = self.input.input, self.interlink
   while not (interlink.full(r) or link.empty(i)) do
      local p = link.receive(i)
      packet.account_free(p) -- stimulate breathing
      interlink.insert(r, p)
   end
   interlink.push(r)
end

function Transmitter:stop ()
   interlink.detach_transmitter(self.interlink, self.shm_name)
   shm.unlink(self.backlink)
end

-- Detach transmitters to prevent leaking interlinks opened by pid.
--
-- This is an internal API function provided for cleanup during
-- process termination.
function Transmitter.shutdown (pid)
   for _, name in ipairs(shm.children("/"..pid.."/interlink/transmitter")) do
      local backlink = "/"..pid.."/interlink/transmitter/"..name..".interlink"
      local shm_name = "/"..pid.."/group/interlink/"..name..".interlink"
      -- Call protected in case /<pid>/group is already unlinked.
      local ok, r = pcall(interlink.open, shm_name)
      if ok then interlink.detach_transmitter(r, shm_name) end
      shm.unlink(backlink)
   end
end

return Transmitter
