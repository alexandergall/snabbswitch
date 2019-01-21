local ffi = require("ffi")

local d1 = ffi.new("struct { int c; }")
local d2 = ffi.new("struct { int c; }")
print(d1, d2)

local function foo(data, i)
   data.c = i
end

require("jit").on()

for i = 1, 100 do
   foo(d1, i)
end
for i = 1, 100 do
   foo(d1, i)
end

for i = 1, 118 do
   foo(d2, i)
end
