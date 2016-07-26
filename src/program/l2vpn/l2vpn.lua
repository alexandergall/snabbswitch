-- This program provisions a complete endpoint for one or more L2 VPNs.
--
-- Each VPN provides essentially a multi-point L2 VPN over IPv6,
-- a.k.a. Virtual Private LAN Service (VPLS). A point-to-point VPN,
-- a.k.a. Virtual Private Wire Service (VPWS) is provided as a
-- degenerate case of a VPLS with exactly two endpoints (i.e. a single
-- pseudowire).  The general framework is described in RFC4664.
--
-- The configuration is split into two parts.  The first part defines
-- the interfaces which are available for uplinks and attachment
-- circuits as well as their L2 and L3 properties.
--
-- The second part defines the actual VPN endpoints which contain
-- references to the interfaces defined in the first part.
--
-- An interface definition is composed of the following elements.
--
--   A unique handle for reference by the VPN configuration
--   A unique name that identifies the interface on the host.
--     Currently, the convention is to use the full PCI address
--     for this purpose.  This name is set as ifDescr for the
--     interface if SNMP is enabled.
--   An optional verbose description of the interface.  This string is set as
--     ifAlias if SNMP is enabled
--   A driver configuraition consisting of
--     The Lua module that represents the driver
--     A driver-specific configuration
--   A L2 configuration consisting of
--     The VLAN trunking mode and encapsulation (802.1Q or 802.1ad)
--     The MTU (including the full L2 header)
--     The physical MAC address
--   Zero or more L3 configurations called "subinterfaces" named "native"
--     or "vlanXXX", where XXX is a number in the range 1-4094.  In
--     non-trunking mode, there must either be no L3 configuration or one
--     name "native", otherwise any or none are allowed.  Each configuration
--     consists of
--       A verbose description
--       A IPv6 address with implied netmask /64
--       A IPv6 next-hop address in the same subnet serving as a default route
--       An optional static MAC address for the next-hop
--       An optional flag whether to perform inbound dynamic ND in the presence
--         of a static next-hop MAC address
--
-- A VPN endpoint definition is composed of the following elements.
--
--   A set of VPLS instances defined by
--      A VC ID
--      An optional verbose description
--      An IPv6 address (local endpoint of all associated pseudowires)
--      A reference to an interface in the form <handle>.<subinterface> to
--        be used as uplink
--      A bridge type (either "flooding" or "learning", defaults to "flooding")
--      The MTU of the L2 domain (excluding the tag on a AC with trunking
--        enabled
--      An optional default tunnel configuration
--      An optional default control-channel configuration
--      An optional directory for PW shared memory segments
--      A set of attachment circuits referencing an interface in the form
--        <handle>.<subinterface>
--      A set of pseudowires defined by
--         The IPv6 address of the remote endpoint
--         An optional tunnel configuration
--         An optional control-channel configuration
--
-- The module constructs a network of apps from such a specification
-- as follows.
--
-- For each interface, the corresponding driver is instantiated with
-- the given configuration.  In non-trunking mode, the L3
-- configuration is either empty or contains exactly one subinterface
-- called "native".  In the first case, initialization is finished and
-- other apps can link to the interface via the "rx" and "tx" links of
-- the driver.  In the second case, one of three possible neighbor
-- discovery modules is attached to the "rx" and "tx" links of the
-- driver.  If dynamic ND is selected in both directions, nd_light
-- module is selected.  If a static MAC address for the next-hop is
-- configured and dynamic inbound ND is selected, the ns_responder ND
-- module is selected.  If both sides use static MAC addresses, the
-- nd_static module is selected.  In either case, apps connect to the
-- "north" links of the ND module.
--
-- If the interface is in trunking mode, an instance of the VlanMux
-- app from apps.vlan.vlan is instantiated and its "trunk" port is
-- connected to the interface's "rx" and "tx" links.  The L3
-- configuration may contain any number of subinterfaces (including
-- "native") or none.  For each subinterface, a ND module is selected
-- as described above and connected to the corresponding link on the
-- VlanMux app (carrying the same name as the subinterface,
-- e.g. "native", "vlan1", etc.)  By definition, the "native" VLAN is
-- untagged.
--
-- Each uplink of the VPLS configuration must reference a subinterface
-- of a previously defined physical interface.  For each VPLS, the
-- "uplink" link of the pseudowire-dispatch app is connected to the
-- "north" link of the ND module of its uplink interface.
--
-- The dispatch app provides the demultiplexing of incoming packets
-- based on the source and destination IPv6 addresses, which uniquely
-- identify a single pseudowire within one of the VPLS instances.
--
-- An instance of apps.bridge.learning or apps.bridge.flooding is
-- created for every VPLS, depending on the selected bridge type.  The
-- bridge connects all pseudowires and attachment circuits of the
-- VPLS.  The pseudowires are assigned to a split horizon group,
-- i.e. packets arriving on any of those links are only forwarded to
-- the attachment circuits and not to any of the other pseudowires
-- (this is a consequence of the full-mesh topology of the pseudowires
-- of a VPLS).  If an AC interface is in non-trunking mode, it must be
-- referenced as <handle>.native and the driver's "rx" and "tx" links
-- are connected to the bridge module.  If the AC interface is in
-- trunking mode, it must be referenced either as <handle>.native or
-- as <handle>.vlan<vid> and the corresping link of the VlanMux app is
-- connected to the bridge module.  The subinterface used for as an AC
-- must not be configured as a L3 subinterface.
--
-- Every pseudowire can have its own tunnel configuration or it can
-- inherit a default configuration for the entire VPLS instance.
--
-- Finally, all pseudowires of the VPLS instance are connected to the
-- dispatcher on the "ac" side.
--
-- If a VPLS consists of a single PW and a single AC, the resulting
-- two-port bridge is optimized away by creating a direct link between
-- the two.  The VPLS thus turns into a VPWS.

module(...,package.seeall)
local usage_msg = require("program.l2vpn.README_inc")
local lib = require("core.lib")
local app = require("core.app")
local c_config = require("core.config")
local nd = require("apps.ipv6.nd_light").nd_light
local dispatch = require("program.l2vpn.dispatch").dispatch
local pseudowire = require("program.l2vpn.pseudowire").pseudowire
local ethernet = require("lib.protocol.ethernet")
local ipv6 = require("lib.protocol.ipv6")
local vmux = require("apps.vlan.vlan").VlanMux

-- config = {
--   interfaces = {
--     <handle1> = {
--       name = <name>,
--       [ description = <description>, ]
--       driver = {
--         module = <module>,
--         config = <driver-config>,
--       },
--       [ trunk = { enabled = true | false,
--                   encapsulation = dot1q | dot1ad | <ethertype> }, ]
--       [ mac = <mac-address>, ]
--       mtu = <mtu>
--     },
--     <handle2> = ...
--   },
--   vpls = {
--     <vpls1> = {
--       [ description = <description> ,]
--       vc_id = <vc_id>,
--       mtu = <mtu>,
--       address = <ipv6-address>,
--       uplink = <handle>.<subintf>,
--       bridge = {
--         type = "flooding"|"learning",
--         [ config = <bridge-config> ]
--       },
--       [ tunnel = <tunnel-config>, ]
--       [ cc = <cc-config>, ]
--       [ shmem_dir = <shmem_dir>, ]
--       ac = {
--         <ac1> = <handle>.<subintf>
--         <ac2> = ...
--       },
--       pw = {
--         <pw1> = {
--            address = <ipv6-address>,
--            [ tunnel = <tunnel-config> ],
--            [ cc = <cc-config> ]
--         },
--         <pw2> = ...
--       },
--     },
--     <vpls2> = ...
--   }
-- }

local bridge_types = { flooding = true, learning = true }

local function ether_pton (addr)
   if type(addr) == "string" then
      return ethernet:pton(addr)
   else
      return addr
   end
end

local function ipv6_pton (addr)
   if type(addr) == "string" then
      return ipv6:pton(addr)
   else
      return addr
   end
end

local function sort_keys (t)
   local s = {}
   for n in pairs(t) do
      table.insert(s, n)
   end
   table.sort(s)
   return s
end

local long_opts = {
   duration = "D",
   logfile = "l",
   debug = "d",
   jit = "j",
   help = "h",
}

function usage ()
   print(usage_msg)
   main.exit(0)
end

local configured_ifs = {}
function config_if (c, subintf, app_c)
   if not configured_ifs[c.name] then
      -- Physical interface
      c_config.app(app_c, c.name, c.module, c.config)

      -- Multiplexer for VLAN trunk
      if c.vmux then
         c_config.app(app_c, c.vmux.name, c.vmux.module, c.vmux.config)
         c_config.link(app_c, c.vmux.links[1])
         c_config.link(app_c, c.vmux.links[2])
      end
      configured_ifs[c.name] = true
   end

   -- ND for L3 subinterfaces
   if subintf then
      local nd = c.subintfs[subintf].nd
      c_config.app(app_c, nd.name, nd.module, nd.config)
      c_config.link(app_c, nd.links[1])
      c_config.link(app_c, nd.links[2])
   end
end

function parse_if (name, config)
   local result = { name = name, subintfs = {} }
   print("Setting up interface "..name)
   assert(config.name, "Missing interface name")
   print("\tName: "..config.name)
   if config.description then
      print("\tDescription: "..config.description)
   end
   assert(config.l2, "Missing layer-2 configuration")
   local l2_c = config.l2
   assert(l2_c.mtu, "Missing MTU in l2 configuration")
   result.mtu = l2_c.mtu
   assert(config.driver, "Missing driver configuration")
   local drv_c = config.driver
   assert(drv_c.module and drv_c.config, "Incomplete driver configuration")
   drv_c.config.mtu = l2_c.mtu
   if drv_c.config.snmp then
      drv_c.config.snmp.ifAlias = config.description or nil
      drv_c.config.snmp.ifDescr = config.name
   end
   result.module = drv_c.module
   result.config = drv_c.config
   local l3_links = { input = name..".rx",
                      output = name..".tx" }
   local vmux_name = "vmux_"..name
   print("\tL2 configuration")
   print("\t\tMTU: "..l2_c.mtu)
   if l2_c.mac then
      local mac = l2_c.mac
      l2_c.mac = ether_pton(l2_c.mac)
      print("\t\tMAC: "..mac)
   end
   if l2_c.trunk then
      local trunk = l2_c.trunk
      assert(type(trunk) == "table")
      if trunk.enable then
         -- The interface is configured as a VLAN trunk. Attach an
         -- instance of the VLAN multiplexer.
         print("\t\tTrunking mode: enabled")
         local encap = trunk.encapsulation or "dot1q"
         assert(encap == "dot1q" or encap == "dot1ad" or
                   (type(encap) == "number"),
                "Illegal encapsulation mode "..encap)
         print("\t\t\tEncapsulation "..
                  (type(encap) == "string" and encap
                      or string.format("ether-type 0x%04x", encap)))
         result.vmux = {
            name = vmux_name,
            module = vmux,
            config = { encapsulation = encap },
            links = { l3_links.output.." -> "..vmux_name..".trunk",
                      vmux_name..".trunk -> "..l3_links.input }
         }
      else
         print("\t\tTrunking mode: disabled")
      end
   end
   local l3_c = config.l3
   if l3_c then
      local function setup_l3 (config, intf, subintf, l3_links)
         assert(config.address, "Missing address on "..subintf
                   .." sub-interface")
         local c = { address = ipv6_pton(config.address),
                     next_hop = ipv6_pton(config.next_hop),
                     neighbor_mac = config.neighbor_mac and
                        ether_pton(config.neighbor_mac) or nil,
                     neighbor_nd = config.neighbor_nd,
                     nd = "nd_"..intf.."_"..subintf }
         print("\t\tSub-interface: "..subintf)
         -- FIXME: check fo uniqueness of subnet
         print("\t\t\tAddress: "..config.address.."/64")
         print("\t\t\tNext-Hop: "..config.next_hop)
         local nd_name = c.nd
         local nd_c = { name = nd_name }
         result.subintfs[subintf] = { nd = nd_c }
         if c.neighbor_mac then
            print("\t\t\tUsing static neighbor MAC address "
                     ..config.neighbor_mac)
            if c.neighbor_nd then
               print("\t\t\tUsing dynamic outbound ND")
               nd_c.module = require("apps.ipv6.ns_responder").ns_responder
               nd_c.config = { local_ip  = c.address,
                               local_mac = l2_c.mac,
                               remote_mac = c.neighbor_mac }
            else
               print("\t\t\tDynamic outbound ND disabled")
               nd_c.module = require("apps.ipv6.nd_static").nd_static
               nd_c.config = { remote_mac  = c.neighbor_mac,
                               local_mac = l2_c.mac }
            end
         else
            assert(config.next_hop, "Missing next-hop on "..subintf
                      .." sub-interface")
            print("\t\t\tUsing dynamic ND")
            nd_c.module = nd
            nd_c.config = { local_ip  = config.address,
                            local_mac = l2_c.mac,
                            next_hop = config.next_hop }
         end
         nd_c.links = { l3_links.output.." -> "..nd_name..".south",
                        nd_name..".south -> "..l3_links.input }
         return(c)
      end

      print("\tL3 configuration")
      assert(l2_c.mac, "Missing MAC address in l2 configuration")
      -- The "native" L3 configuration can exist in trunking and
      -- non-trunking mode.  In non-trunking mode, the ND module
      -- connects directly to the driver.  In trunking mode, the
      -- ND module connects to the "native" port of the vmux.
      if l3_c.native then
         if not l2_c.trunk then
            result.native = setup_l3(l3_c.native, name, "native", l3_links)
         else
            result.native = setup_l3(l3_c.native, name, "native",
                                     { input = vmux_name..".native",
                                       output = vmux_name..".native" })
         end
      end

      local l3_c_sorted = sort_keys(l3_c)
      for _, subintf in ipairs(l3_c_sorted) do
         local config = l3_c[subintf]
         if subintf == "native" then goto continue end
         assert(l2_c.trunk,
                "VLAN configurations not allowed in non-trunking mode")
         local vid = tonumber(subintf:match("vlan(%d+)"))
         assert(vid and vid > 0 and vid < 4095, "Illegal VLAN ID "..vid)
         result[subintf] = setup_l3(config, name, "vlan"..vid,
                                    { input = vmux_name.."."..subintf,
                                      output = vmux_name.."."..subintf })
         ::continue::
      end
   end
   return(result)
end

function run (parameters)
   local duration = 0
   local jit_conf = {}
   local opt = {}
   function opt.D (arg)
      if arg:match("^[0-9]+$") then
         duration = tonumber(arg)
      else
         usage()
      end
   end
   function opt.l (arg)
      local logfh = assert(io.open(arg, "a"))
      lib.logger_default.fh = logfh
   end
   function opt.h (arg) usage() end
   function opt.d (arg) _G.developer_debug = true end
   function opt.j (arg)
      if arg:match("^v") then
         local file = arg:match("^v=(.*)")
         if file == '' then file = nil end
         require("jit.v").start(file)
      elseif arg:match("^p") then
         jit_conf.p = {}
         local p = jit_conf.p
         p.opts, p.file = arg:match("^p=([^,]*),?(.*)")
         if p.file == '' then p.file = nil end
      elseif arg:match("^dump") then
         jit_conf.dump = {}
         local dump = jit_conf.dump
         dump.opts, dump.file = arg:match("^dump=([^,]*),?(.*)")
         if dump.file == '' then dump.file = nil end
      end
   end

   -- Execute command line arguments
   parameters = lib.dogetopt(parameters, opt, "hdj:D:l:", long_opts)
   -- Defaults: sizemcode=32, macmcode=512
   require("jit.opt").start('sizemcode=128', 'maxmcode=1024')
   if #parameters ~= 1 then usage () end

   local file = table.remove(parameters, 1)
   local conf_f = assert(loadfile(file))
   local config = conf_f()

   local c = c_config.new()
   local intfs = {}
   local interfaces = config.interfaces
   assert(interfaces, "missing interfaces configuration")
   local interfaces_sorted = sort_keys(interfaces)
   for _, name in ipairs(interfaces_sorted) do
      local conf = interfaces[name]
      intfs[name] = parse_if(name, conf)
   end

   local uplinks = {}
   local vpls_bridges = {}
   assert(config.vpls, "Missing vpls configuration")
   for vpls, vpls_config in pairs(config.vpls) do
      print("Creating VPLS instance "..vpls
            .." ("..(vpls_config.description or "<no description>")..")")
      assert(vpls_config.mtu, "Missing MTU")
      assert(vpls_config.vc_id, "Missing VC ID")
      print("\tMTU: "..vpls_config.mtu)
      print("\tVC ID: "..vpls_config.vc_id)

      local uplink = vpls_config.uplink
      assert(uplink, "Missing uplink configuarion")
      assert(type(uplink) == "string",
             "Uplink interface specifier must be a string")
      local intf, subintf = uplink:match("(%w+)%.(%w+)")
      assert(intf and subintf, "Illegal interface specifier "..uplink)
      assert(intfs[intf], "Interface "..intf.." referenced "
                .."by uplink does not exist")
      assert(intfs[intf].subintfs[subintf],
             "Sub-Interface "..subintf.." of "..intf..
                " referenced by uplink does not exist")
      print("\tUplink is on "..uplink)
      if not uplinks.uplink then
         uplinks[uplink] = intfs[intf].subintfs[subintf]
         config_if(intfs[intf], subintf, c)
      end

      local bridge_config = { ports = {},
                              split_horizon_groups = { pw = {} } }
      if (vpls_config.bridge) then
         local bridge = vpls_config.bridge
         if bridge.type then
            assert(bridge_types[bridge.type],
                   "invalid bridge type: "..bridge.type)
         else
            bridge.type = "flooding"
         end
         bridge_config.config = bridge.config
      end
      assert(vpls_config.address, "Missing address")
      vpls_config.address = ipv6_pton(vpls_config.address)
      assert(vpls_config.ac, "Missing ac configuration")
      assert(vpls_config.pw, "Missing pseudowire configuration")

      local pws = {}
      local acs = {}
      local tunnel_config = vpls_config.tunnel

      print("\tCreating attachment circuits")
      for ac, ac_config in pairs(vpls_config.ac) do
         assert(ac_config, "Missing configuration for AC "..ac)
         assert(type(ac_config) == "string",
                "AC interface specifier must be a string")
         local ac_name = vpls.."_ac_"..ac
         print("\t\t"..ac_name)
         local intf, subintf = ac_config:match("(%w+)%.(%w+)")
         assert(intf and subintf, "Illegal interface specifier "
                   ..ac_config)
         local vid = tonumber(subintf:match("vlan(%d+)"))
         assert(vid and vid > 0 and vid < 4095,
                "Illegal VLAN specifier "..subintf)
         assert(intfs[intf], "Interface "..intf.." referenced "
                   .."by AC "..ac.." does not exist")
         print("\t\t\tAC is on "..ac_config)
         local ac_intf = intfs[intf]
         assert(not ac_intf.subintfs[subintf],
                "Sub-Interface "..subintf.." already configured for L3")
         if ac_intf.ac then
            error("Sub-Interface "..subintf
                     .." already assigned to AC "..ac_intf.ac.ac
                     .." of VPLS instance "..ac_intf.ac.vpls)
         end
         ac_intf.ac = { ac = ac, vpls = vpls }

         -- The effective MTU of the AC must match the MTU of the
         -- VPLS, where the effective MTU is given by
         --
         --   - The actual MTU if the AC is not a trunk
         --   - The actual MTU minus 4 if the AC is a trunk
         --
         -- If the AC is the native VLAN on a trunk, the actual packets
         -- can carry frames which exceed the nominal MTU by 4 bytes.
         local effective_mtu = ac_intf.vmux and ac_intf.mtu-4 or ac_intf.mtu
         assert(vpls_config.mtu == effective_mtu, "MTU mismatch between "
                   .."VPLS ("..vpls_config.mtu..") and interface "
                   ..intf.." (real: "..ac_intf.mtu..", effective: "
                   ..effective_mtu..")")
         config_if(intfs[intf], nil, c)
         local ac_input, ac_output
         if ac_intf.vmux then
            ac_input = ac_intf.vmux.name.."."..subintf
            ac_output = ac_intf.vmux.name.."."..subintf
         else
            ac_input = intf..".rx"
            ac_output = intf..".tx"
         end
         table.insert(bridge_config.ports, ac_name)
         table.insert(acs, { name = ac_name,
                             intf = ac_intf,
                             input = ac_input,
                             output = ac_output })
      end

      print("\tCreating pseudowire instances")
      for pw, pw_config in pairs(vpls_config.pw) do
         assert(tunnel_config or pw_config.tunnel,
                "Missing tunnel configuration for pseudowire "..pw
                   .." and no default specified")
         assert(pw_config.address,
                "Missing remote address configuration for pseudowire "..pw)
         pw_config.address = ipv6_pton(pw_config.address)
         local pw = vpls..'_pw_'..pw
         print("\t\t"..pw)
         c_config.app(c, pw, pseudowire,
                      { name = pw,
                        vc_id = vpls_config.vc_id,
                        mtu = vpls_config.mtu,
                        shmem_dir = vpls_config.shmem_dir or nil,
                        description = vpls_config.description,
                        -- For a p2p VPN, pass the name of the AC
                        -- interface so the PW module can set up the
                        -- proper service-specific MIB
                        interface = (#vpls_config.pw == 1 and
                                        #acs == 1 and
                                        acs[1].intf.config.name) or '',
                        transport = { type = 'ipv6',
                                      src = vpls_config.address,
                                      dst = pw_config.address },
                        tunnel = pw_config.tunnel or tunnel_config,
                        cc = pw_config.cc or vpls_config.cc or nil
                     })
         table.insert(pws, pw)
         table.insert(bridge_config.split_horizon_groups.pw, pw)
         if not uplinks[uplink].dispatch then
            uplinks[uplink].dispatch = {}
         end
         uplinks[uplink].dispatch[pw] = { source      = pw_config.address,
                                         destination = vpls_config.address }
      end

      if #pws == 1 and #acs == 1 then
         -- Optimize a two-port bridge as a direct attachment of the
         -- PW and AC
         print("\tShort-Circuit "..pws[1].." <-> "..acs[1].name)
         c_config.link(c, pws[1]..".ac -> "..acs[1].input)
         c_config.link(c, acs[1].output.." -> "..pws[1]..".ac")
      else
         local vpls_bridge = vpls.."_bridge"
         table.insert(vpls_bridges, vpls_bridge)
         print("\tCreating bridge "..vpls_bridge)
         c_config.app(c, vpls_bridge,
                      require("apps.bridge."..vpls_config.bridge.type).bridge,
                      bridge_config)
         for _, pw in ipairs(pws) do
            c_config.link(c, pw..".ac -> "..vpls_bridge.."."..pw)
            c_config.link(c, vpls_bridge.."."..pw.." -> "..pw..".ac")
         end
         for _, ac in ipairs(acs) do
            c_config.link(c, vpls_bridge.."."..ac.name.." -> "..ac.input)
            c_config.link(c, ac.output.." -> "..vpls_bridge.."."..ac.name)
         end
      end
   end

   -- Create dispatchers for active uplinks and attach PWs
   for uplink, uplink_c in pairs(uplinks) do
      local dispatcher = "dispatcher_"..string.gsub(uplink, "%.", "_")
      c_config.app(c, dispatcher, dispatch, uplink_c.dispatch)
      for pw, pw_c in pairs(uplink_c.dispatch) do
         c_config.link(c, dispatcher.."."..pw.." -> "..pw..".uplink")
         c_config.link(c, pw..".uplink -> "..dispatcher.."."..pw)
      end
      c_config.link(c, uplink_c.nd.name..".north -> "..dispatcher..".south")
      c_config.link(c, dispatcher..".south -> "..uplink_c.nd.name..".north")
   end
   engine.configure(c)
   -- Remove when the app link() method lands on the l2vpn branch
   for _, bridge in ipairs(vpls_bridges) do
      engine.app_table[bridge]:post_config()
   end
   for _, intf in pairs(intfs) do
      if intf.vmux and engine.app_table[intf.vmux.name] then
         engine.app_table[intf.vmux.name]:link()
      end
   end

   local engine_opts = {}
   if duration ~= 0 then engine_opts.duration = duration end
   jit.flush()
   if jit_conf.p then
      require("jit.p").start(jit_conf.p.opts, jit_conf.p.file)
   end
   if jit_conf.dump then
      require("jit.dump").start(jit_conf.dump.opts, jit_conf.dump.file)
   end
   engine.main(engine_opts)
   if jit_conf.p then
      require("jit.p").stop()
   end
end
