module(..., package.seeall)
local ffi = require("ffi")
local ctable = require("lib.ctable")

local retries = 10
local increment = 1.2
local steps = 5

function create (key_t, value_t, keys)
   local params = {
      key_type = key_t,
      value_type = value_t,
      initial_size = #keys,
      max_occupancy_rate = 0.6,
   }
   local ctab
   local value = value_t()
   for _ = 1, steps do
      for _ = 1, retries do
         ctab = ctable.new(params)
         for _, key in ipairs(keys) do
            ctab:add(key, value)
         end
         if ctab.max_displacement == 0 then
            goto done
         end
         params.initial_size = math.ceil(params.initial_size * increment)
      end
   end
   ::done::
   if ctab.max_displacement ~= 0 then
      print("perfect hash not found")
   end
   return ctab
end
