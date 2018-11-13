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
-- See the README.md for details about the configuration.
--
-- The module constructs a network of apps from such a specification
-- as follows.
--
-- For each interface, the corresponding driver is instantiated with
-- the given configuration.  In non-trunking mode and without a L3
-- configuration, initialization is finished and other apps can link
-- directly to the driver.  For a L3 interface, the nd_light app is
-- attached to the driver and other apps attach to nd_light instead.
--
-- If the interface is in trunking mode, an instance of the VlanMux
-- app from apps.vlan.vlan is instantiated and its "trunk" port is
-- connected to the interface.  For each sub-interface that contains a
-- L3 configuration, an instance of the nd_light app is attached to
-- the appropriate "vlan" link of the VlanMux app (for vlan = 0, the
-- corresponding VlanMux link is called "native").
--
-- Each uplink of the VPLS configuration must reference a
-- L3-(sub-)interface of a previously defined physical interface.  For
-- each VPLS, the "uplink" link of the pseudowire-dispatch app is
-- connected to the "north" link of the ND module of its uplink
-- interface.
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
-- of a VPLS).  All attachment circuits defined for a VPLS must
-- reference a L2 interface or sub-interface.  In non-trunking mode,
-- the interface driver is connected directly to the bridge module.
-- In trunking mode, the corresponding "vlan" links of the VlanMux app
-- are connected to the bridge instead.
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

-- config = {
--   [ shmem_dir = <shmem_dir> , ]
--   [ snmp = { enable = true | false,
--              interval = <interval> }, ]
--   interfaces = {
--     {
--       name = <name>,
--       [ description = <description>, ]
--       driver = {
--         path = <path>,
--         name = <name>,
--         config = {
--           pciaddr = <pciaddress>,
--         },
--         [ extra_config = <extra_config>, ]
--       },
--       [ mirror = {
--           [ rx = true | false | <rx_name>, ]
--           [ tx = true | false | <tx_name>, ]
--           [ type = 'tap' | 'pcap', ]
--         }, ]
--       mtu = <mtu>,
--       [ -- only allowed if trunk.enable == false
--         afs = {
--           ipv6 = {
--             address = <address>,
--             next_hop = <next_hop>,
--             [ next_hop_mac = <neighbor_mac> ]
--           }
--         }, ]
--       [ trunk = {
--           enable = true | false,
--           encapsulation = "dot1q" | "dot1ad" | <number>,
--           vlans = {
--             {
--               [ description = <description>, ]
--               [ mtu = mtu, ]
--               vid = <vid>,
--               [ afs = {
--                   ipv6 = {
--                     address = <address>,
--                     next_hop = <next_hop>,
--                     [ next_hop_mac = <next_hop_mac> ]
--                   }
--                 } ]
--              },
--              ...
--           }
--         } ]
--     }
--   },
--   vpls = {
--     <vpls1> = {
--       [ description = <description> ,]
--       vc_id = <vc_id>,
--       mtu = <mtu>,
--       af  = 'ipv4' | 'ipv6',
--       address = <address>,
--       uplink = <int>,
--       bridge = {
--         type = "flooding"|"learning",
--         [ config = <bridge-config> ]
--       },
--       [ tunnel = <tunnel-config>, ]
--       [ cc = <cc-config>, ]
--       ac = {
--         <ac1> = <int>
--         <ac2> = ...
--       },
--       pw = {
--         <pw1> = {
--            address = <address>,
--            [ tunnel = <tunnel-config> ],
--            [ cc = <cc-config> ]
--         },
--         <pw2> = ...
--       },
--     },
--     <vpls2> = ...
--   }
-- }
module(...,package.seeall)

local ffi = require("ffi")
local C = ffi.C
local usage_msg = require("program.l2vpn.README_inc")
local lib = require("core.lib")
local counter = require("core.counter")
local macaddress = require("lib.macaddress")
local shm = require("core.shm")
local const = require("syscall.linux.constants")
local S = require("syscall")
local app_graph = require("core.config")
local ethernet = require("lib.protocol.ethernet")
local ipv6 = require("lib.protocol.ipv6")
local ipv4 = require("lib.protocol.ipv4")
local dipatch = require("program.l2vpn.dispatch").dispatch
local Tap = require("apps.tap.tap").Tap
local Tee = require("apps.basic.basic_apps").Tee
local PcapWriter = require("apps.pcap.pcap").PcapWriter
local Sink = require("apps.basic.basic_apps").Sink
local VlanMux = require("apps.vlan.vlan").VlanMux
local nd_light = require("apps.ipv6.nd_light").nd_light
local arp = require("apps.ipv4.arp").ARP
local af_demux = require("program.l2vpn.af_demux").af_demux
local dispatch = require("program.l2vpn.dispatch").dispatch
local pseudowire = require("program.l2vpn.pseudowire").pseudowire
local ifmib = require("lib.ipc.shmem.iftable_mib")
local frag_ipv6 = require("apps.ipv6.fragment").Fragmenter
local reass_ipv6 = require("apps.ipv6.reassemble").Reassembler

local bridge_types = { flooding = true, learning = true }

function usage ()
   print(usage_msg)
   main.exit(0)
end

local state
local function clear_state ()
   state =  {
      apps = {},
      links = {},
      intfs = {},
      nds = {},
      arps = {},
   }
end

local App = {}
function App:new (name, class, initial_arg)
   -- assert(not state.apps[name], "Duplicate app "..name)
   local self = setmetatable({}, { __index = App })
   state.apps[name] = self
   self._name = name
   self._class = class
   self:arg(initial_arg)
   return self
end

function App:name ()
   return self._name
end

function App:class ()
   return self._class
end

function App:arg (arg)
   if arg == nil then return self._arg end
   self._arg = arg
end

function connector (app_in, input, app_out, output)
   assert(input)
   local output = output or input
   return {
      input = function ()
         return app_in:name()..'.'..input
      end,
      output = function ()
         return app_out:name()..'.'..output
      end
   }
end

function App:connector (input, output)
   return connector(self, input, self, output)
end

local function connect (from, to)
   table.insert(state.links, from.output()..' -> '..to.input())
end

local function connect_duplex (from, to)
   connect(from, to)
   connect(to, from)
end

local function normalize_name (name)
   return string.gsub(name, '[/%.]', '_')
end

-- Helper functions to abstract from driver-specific behaviour.  The
-- key into this table is the full path to the module used to create
-- the driver object. For each driver, the following functions must be
-- defined
--   link_names ()
--     Return the name of the links used for input and ouput
--   stats_path (driver)
--     This function is called after the driver has been created
--     and receives the driver object as input.  It returns the
--     path to the shm frame where the driver stores its stats counters.
local driver_helpers = {
   ['apps.intel_mp.intel_mp.Intel'] = {
      link_names = function ()
         return 'input', 'output'
      end,
      stats_path = function (intf)
         return 'pci/'..intf.pci_address
      end
   },
   ['apps.tap.tap.Tap'] = {
      link_names = function ()
         return 'input', 'output'
      end,
      stats_path = function (intf)
         return 'apps/'..intf.app:name()
      end
   },
}

-- Mapping of address family identifiers to classes
af_classes = {
   ipv4 = ipv4,
   ipv6 = ipv6,
}

function parse_intf(config)
   assert(config.name, "Missing interface name")
   print("Setting up interface "..config.name)
   print("  Description: "..(config.description or "<none>"))
   local intf = {
      description = config.description,
      name = config.name,
      -- The normalized name is used in app and link names
      nname = normalize_name(config.name),
   }

   -- NIC driver
   assert(config.driver, "Missing driver configuration")
   local drv_c = config.driver
   assert(drv_c.path and drv_c.name and
             drv_c.config, "Incomplete driver configuration")
   if type(drv_c.config) == "table" then
      if (drv_c.config.pciaddr) then
         print("  PCI address: "..drv_c.config.pciaddr)
	 intf.pci_address = drv_c.config.pciaddr
      end
      drv_c.config.mtu = config.mtu
      if drv_c.extra_config then
         -- If present, extra_config must be a table, whose elements
         -- are merged with the regular config.  This feature allows
         -- for more flexibility when the configuration is created by
         -- a Lua-agnostic layer on top, e.g. by a NixOS module
         assert(type(drv_c.extra_config) == "table",
                "Driver extra configuration must be a table")
         for k, v in pairs(drv_c.extra_config) do
            drv_c.config[k] = v
         end
      end
   end
   intf.app = App:new('intf_'..intf.nname,
                      require(drv_c.path)[drv_c.name], drv_c.config)
   local driver_helper = driver_helpers[drv_c.path.."."..drv_c.name]
   assert(driver_helper,
          "Unsupported driver (missing driver helper)"
             ..drv_c.path.."."..drv_c.name)
   intf.driver_helper = driver_helper
   intf.l2 = intf.app:connector(driver_helper.link_names())

   -- L2 configuration
   print("  L2 configuration")
   assert(config.mtu, "Missing MTU")
   print("    MTU: "..config.mtu)
   intf.mtu = config.mtu

   -- Port mirror configuration
   if config.mirror then
      local mirror = config.mirror
      local mtype = mirror.type or 'tap'
      assert(type(mtype) == "string", "Mirror type must be a string")
      for _, dir in ipairs({ 'rx', 'tx' }) do
         local mirror_connector
         if mirror[dir] then
            if mtype == "pcap" then
               local file
               if type(mirror[dir]) == "string" then
                  file = mirror[dir]
               else
                  file = '/tmp/'..string.gsub(config.name, "/", "-")
                     .."_"..dir..".pcap"
               end
               local mirror = App:new('tap_'..intf.nname..'_pcap_'..dir,
                                      PcapWriter, file)
               mirror_connector = mirror:connector('input')
               print("    "..dir.." port-mirror on pcap file "..file)
            elseif mtype == "tap" then
               local tap_name
               if type(mirror[dir]) == "string" then
                  tap_name = mirror[dir]
               else
                  tap_name = string.gsub(config.name, "/", "-")
                  tap_name = string.sub(tap_name, 0, const.IFNAMSIZ-3).."_"..dir
               end
               local mirror = App:new('tap_'..intf.nname..'_'..dir,
                                      Tap, { name = tap_name, mtu = config.mtu})
               mirror_connector = mirror:connector('input', 'output')
               local sink = App:new('sink_'..intf.nname..'_tap_'..dir,
                                    Sink)
               connect(mirror_connector, sink:connector('input'))
               print("    "..dir.." port-mirror on tap interface "..tap_name)
            else
               error("Illegal mirror type: "..mtype)
            end
            local tee = App:new('tee_'..intf.nname..'_'..dir, Tee)
            connect(tee:connector('mirror'), mirror_connector)
            if dir == "rx" then
               connect(intf.l2, tee:connector('input'))
               intf.l2.output = tee:connector('pass').output
            else
               connect(tee:connector('pass'), intf.l2)
               intf.l2.input = tee:connector('input').input
            end
         end
      end
   end

   local function vid_suffix (vid)
      return (vid and "_"..vid) or ''
   end

   local afs_procs = {
      ipv6 = function (config, vid, connector_in, indent)
         assert(config.address, "Missing address")
         assert(config.next_hop, "Missing next-hop")
         -- FIXME: check fo uniqueness of subnet
         print(indent.."    Address: "..config.address.."/64")
         print(indent.."    Next-Hop: "..config.next_hop)
         if config.next_hop_mac then
            print(indent.."    Next-Hop MAC address: "
                     ..config.next_hop_mac)
         end

         local nd = App:new('nd_'..intf.nname..vid_suffix(vid),
                            nd_light,
                            { local_ip  = config.address,
                              local_mac = "00:00:00:00:00:00",
                              remote_mac = config.next_hop_mac,
                              next_hop = config.next_hop,
                              quiet = true })
         state.nds[nd:name()] = { app = nd, intf = intf }
         connect_duplex(nd:connector('south'), connector_in)

         fragmenter = App:new('frag_'..intf.nname..vid_suffix(vid),
                              frag_ipv6,
                              { mtu = intf.mtu - 14, pmtud = true,
                                pmtu_local_addresses = {} })
         local reassembler = App:new('reass_'..intf.nname..vid_suffix(vid),
                                     reass_ipv6,
                                     {})
         local nd_north = nd:connector('north')
         connect(nd_north, fragmenter:connector('south'))
         connect(fragmenter:connector('output'), nd_north)
         connect(fragmenter:connector('north'),
                 reassembler:connector('input'))
         return connector(fragmenter, 'input', reassembler, 'output'), fragmenter
      end,

      ipv4 = function (config, vid, connector_in, indent)
         assert(config.address, "Missing address")
         assert(config.next_hop, "Missing next-hop")
         -- FIXME: check fo uniqueness of subnet
         print(indent.."    Address: "..config.address.."/24")
         print(indent.."    Next-Hop: "..config.next_hop)
         if config.next_hop_mac then
            print(indent.."    Next-Hop MAC address: "
                     ..config.next_hop_mac)
         end

         local arp = App:new('arp_'..intf.nname..vid_suffix(vid),
                             arp,
                             { self_ip  = ipv4:pton(config.address),
                               self_mac = ethernet:pton("00:00:00:00:00:00"),
                               next_mac = config.next_hop_mac and
                                  ethernet:pton(config.next_hop_mac or nil),
                               next_ip = ipv4:pton(config.next_hop) })
         state.arps[arp:name()] = { app = arp, intf = intf }
         connect_duplex(arp:connector('south'), connector_in)
         return arp:connector('north')
      end
   }

   local function process_afs (af_configs, vid, connector, indent)
      print(indent.."  Address family configuration")
      local afs = {
         ipv4 = {
            name = 'IPv4',
            conn_in = connector,
            configured = false,
         },
         ipv6 = {
            name = 'IPv6',
            conn_in = connector,
            configured = false,
         }
      }

      if af_configs.ipv4 and af_configs.ipv6 then
         -- Add a demultiplexer for IPv4/IPv6
         local afd = App:new('af_demux_'..intf.nname..vid_suffix(vid),
                             af_demux)
         connect_duplex(afd:connector('south'), connector)
         for _, afi in ipairs({ 'ipv4', 'ipv6' }) do
            afs[afi].conn_in = afd:connector(afi)
         end
      end
      for afi, config in pairs(af_configs) do
         local af = afs[afi]
         assert(af, "Unsupported address family "..afi)
         print(indent.."    "..af.name)
         af.conn_out, af.fragmenter =
            afs_procs[afi](config, vid, af.conn_in, indent.."  ")
         af.configured = true
      end
      return afs
   end

   local trunk = config.trunk or { enable = false }
   assert(type(trunk) == "table", "Trunk configuration must be a table")
   if trunk.enable then
      -- The interface is configured as a VLAN trunk. Attach an
      -- instance of the VLAN multiplexer.
      print("    Trunking mode: enabled")
      intf.subintfs = {}
      assert(not config.afs,
             "Address family configuration not allowed in trunking mode")
      local encap = trunk.encapsulation or "dot1q"
      assert(encap == "dot1q" or encap == "dot1ad" or
                (type(encap) == "number"),
             "Illegal encapsulation mode "..encap)
      print("      Encapsulation "..
               (type(encap) == "string" and encap
                   or string.format("ether-type 0x%04x", encap)))
      local vmux = App:new('vmux_'..intf.nname, VlanMux,
                           { encapsulation = encap })
      connect_duplex(vmux:connector('trunk'), intf.l2)

      -- Process VLANs and create sub-interfaces
      assert(trunk.vlans, "Missing VLAN configuration on trunk port")
      print("  Sub-Interfaces")
      for n, vlan in ipairs(trunk.vlans) do
         local vid = vlan.vid
         assert(vid, "Missing VLAN ID for sub-interface #"..n)
         assert(type(vid) == "number" and vid >= 0 and vid < 4095,
                "Invalid VLAN ID "..vid.." for sub-interface #"..n)
         local name = config.name..'.'..vid
         assert(not intf.subintfs[name], "Duplicate VID: "..vid)

         local mtu = vlan.mtu or intf.mtu
         assert(mtu <= intf.mtu,
                string.format("MTU %d on sub-interface %s "
                                 .."exceeds MTU %d of physical interface",
                              mtu, name, intf.mtu))
         local subintf = {
            name = name,
            -- The normalized name is used in app and link names
            nname = normalize_name(name),
            description = vlan.description,
            vlan = true,
            phys_intf = intf,
            mtu = mtu,
         }
         intf.subintfs[name] = subintf
         print("    "..config.name.."."..vid)
         print("      Description: "..(vlan.description or '<none>'))
         print("      L2 configuration")
         print("        VLAN ID: "..(vid > 0 and vid or "<untagged>"))
         print("        MTU: "..subintf.mtu)
         local connector = vmux:connector((vid == 0 and 'native') or 'vlan'..vid)
         if vlan.afs then
            subintf.l3 = process_afs(vlan.afs, vid,
                                     connector, "    ")
         else
            subintf.l2 = connector
         end

         -- Store a copy of the vmux connector to find the proper shm
         -- frame for the interface counters later on
         subintf.vmux_connector = connector
      end
   else
      print("    Trunking mode: disabled")
      if config.afs then
         intf.l3 = process_afs(config.afs, nil, intf.l2, "")
      end
   end

   return intf
end

function parse_config (main_config)
   local intfs_config = main_config.interfaces
   assert(intfs_config, "Missing interfaces configuration")
   local intfs = state.intfs
   for _, config in ipairs(intfs_config) do
      local intf = parse_intf(config)
      assert(not intfs[intf.name], "Duplicate interface name: "..intf.name)
      intfs[intf.name] = intf
      for name, subintf in pairs(intf.subintfs or {}) do
         intfs[name] = subintf
      end
   end

   local vpls_config = main_config.vpls
   assert(vpls_config, "Missing VPLS configuration")

   local dispatchers = { ipv4 = {}, ipv6 = {} }
   local bridge_groups = {}
   for vpls_name, vpls in pairs(vpls_config) do
      local function assert_vpls (cond, msg)
         assert(cond, "VPLS "..vpls_name..": "..msg)
      end

      print("Creating VPLS instance "..vpls_name
            .." ("..(vpls.description or "<no description>")..")")
      assert_vpls(vpls.vc_id, "Missing VC ID")
      print("  VC ID: "..vpls.vc_id)
      assert_vpls(vpls.mtu, "Missing MTU")
      print("  MTU: "..vpls.mtu)

      assert(vpls.afi, "Missing address family identifier")
      local af = af_classes[vpls.afi]
      assert(af, "Invalid address family identifier"..vpls.afi)
      assert_vpls(vpls.address, "Mssing address")
      assert(af:pton(vpls.address),
             "Invalid "..vpls.afi.." address "..vpls.address)
      print("  Address: "..vpls.address)

      assert_vpls(vpls.ac, "Missing ac configuration")
      assert_vpls(vpls.pw, "Missing pseudowire configuration")

      local uplink = vpls.uplink
      assert_vpls(uplink, "missing uplink")
      assert(type(uplink) == "string",
             "Uplink interface specifier must be a string")
      local intf = intfs[uplink]
      assert_vpls(intf, "Uplink interface "..uplink.." does not exist")
      assert_vpls(intf.l3, "Uplink interface "..uplink
                     .." is L2 when L3 is expected")
      print("  Uplink is on "..uplink)
      intf.used = true
      assert(intf.l3[vpls.afi],
             "Address family "..vpls.afi.." not enabled on uplink")

      local tunnel = vpls.tunnel
      local cc = vpls.cc

      local dispatcher = dispatchers[vpls.afi][uplink]
      if not dispatcher then
         dispatcher = App:new('disp_'..normalize_name(uplink).."_"..vpls.afi,
                              dispatch, { afi = vpls.afi, links = {} })
         dispatchers[vpls.afi][uplink] = dispatcher
         local south = dispatcher:connector('south')
         connect_duplex(south, intf.l3[vpls.afi].conn_out)
         intf.l3[vpls.afi].used = true
      end
      local bridge_group = {
         config = vpls.bridge or { type = 'flooding' },
         pws = {},
         acs = {}
      }
      assert(bridge_types[bridge_group.config.type],
             "Invalid bridge type: "..bridge_group.config.type)
      bridge_groups[vpls_name] = bridge_group
      print("  Creating pseudowires")
      for name, pw in pairs(vpls.pw) do
         print("    "..name)
         assert(tunnel or pw.tunnel,
                "Missing tunnel configuration for pseudowire"
                   .." and no default specified")
         assert(pw.address, "Missing remote address configuration")
         assert(af:pton(pw.address),
                "Invalid "..vpls.afi.." address "..pw.address)
         print("      Address: "..pw.address)
         local link_name = vpls_name..'_'..name
         dispatcher:arg().links[link_name] = { source = af:pton(pw.address),
                                               destination = af:pton(vpls.address) }
         local app = App:new('pw_'..vpls_name..'_'..name,
                             pseudowire,
                             { name = link_name,
                               vc_id = vpls.vc_id,
                               mtu = vpls.mtu,
                               shmem_dir = main_config.shmem_dir,
                               description = vpls.description,
                               transport = { type = vpls.afi,
                                             src = vpls.address,
                                             dst = pw.address },
                               tunnel = pw.tunnel or tunnel,
                               cc = pw.cc or cc or nil })
         connect_duplex(dispatcher:connector(link_name),
                        app:connector('uplink'))
         table.insert(bridge_group.pws, app)
      end
      -- XXX remove once frag for ipv4 is implemented
      if intf.l3[vpls.afi].fragmenter then
         table.insert(intf.l3[vpls.afi].fragmenter:arg().pmtu_local_addresses,
                      vpls.address)
      end

      print("  Creating attachment circuits")
      for name, ac in pairs(vpls.ac) do
         print("    "..name)
         assert(type(ac) == "string",
                "AC interface specifier must be a string")
         print("      AC is on "..ac)
         local intf = intfs[ac]
         assert_vpls(intf, "AC interface "..ac.." does not exist")
         assert_vpls(not intf.l3, "AC interface "..ac
                        .." is L3 when L2 is expected")
         table.insert(bridge_group.acs, intf)
         intf.used = true
         -- Note: if the AC is the native VLAN on a trunk, the actual packets
         -- can carry frames which exceed the nominal MTU by 4 bytes.
         local eff_mtu = intf.mtu
         if intf.vlan then
            -- Subtract size of service-delimiting tag
            eff_mtu = eff_mtu - 4
         end
         assert(vpls.mtu == eff_mtu, "MTU mismatch between "
                   .."VPLS ("..vpls.mtu..") and interface "
                   ..ac.." ("..eff_mtu..")")
      end
   end

   for vpls_name, bridge_group in pairs(bridge_groups) do
      if #bridge_group.pws == 1 and #bridge_group.acs == 1 then
         -- No bridge needed for a p2p VPN
         local pw, ac = bridge_group.pws[1], bridge_group.acs[1]
         local pw_connector = pw:connector('ac')
         connect_duplex(pw:connector('ac'), ac.l2)
         -- For a p2p VPN, pass the name of the AC
         -- interface so the PW module can set up the
         -- proper service-specific MIB
         pw:arg().interface = bridge_group.acs[1].name
      else
         local bridge =
            App:new('bridge_'..vpls_name,
                    require("apps.bridge."..bridge_group.config.type).bridge,
                    { ports = {},
                      split_horizon_groups = { pw = {} },
                      config = bridge_group.config.config })
         for _, pw in ipairs(bridge_group.pws) do
            connect_duplex(pw:connector('ac'),
                           bridge:connector(pw:name()))
            table.insert(bridge:arg().split_horizon_groups.pw, pw:name())
         end
         for _, ac in ipairs(bridge_group.acs) do
            local ac_name = normalize_name(ac.name)
            connect_duplex(ac.l2,
                           bridge:connector(ac_name))
            table.insert(bridge:arg().ports, ac_name)
         end
      end
   end

   for name, intf in pairs(intfs) do
      if not intf.used and not intf.subintfs then
         -- Create sink for interfaces not used as uplink or AC
         local sink = App:new('sink_'..intf.nname,
                              Sink, {})
         connect_duplex(intf.l2, sink:connector('input'))
      else
         if intf.l3 then
            for afi, state in pairs(intf.l3) do
               if state.configured and not state.used then
                  -- Create sink for a L3 interface not connected to
                  -- a dispatcher
                  local sink = App:new('sink_'..intf.nname..'_'..afi,
                                       Sink, {})
                  connect_duplex(state.conn_out, sink:connector('input'))
               end
            end
         end
      end
   end
end

local function setup_shm_and_snmp (main_config)
   -- For each interface, attach to the shm frame that stores
   -- the statistics counters
   for _, intf in pairs(state.intfs) do
      if not intf.vlan then
         local stats_path = intf.driver_helper.stats_path(intf)
         intf.stats = shm.open_frame(stats_path)
      end
   end
   -- Commit all counters to the backing store to make them available
   -- immediately through the read-only frames we just created
   counter.commit()

   local snmp = main_config.snmp or { enable = false }
   if snmp.enable then
      for name, intf in pairs(state.intfs) do
         if not intf.vlan then
            -- Set up SNMP for physical interfaces
            local stats = intf.stats
            if stats then
               ifmib.init_snmp( { ifDescr = name,
                                  ifName = name,
                                  ifAlias = intf.description, },
                  string.gsub(name, '/', '-'), stats,
                  main_config.shmem_dir, snmp.interval or 5)
            else
               print("Can't enable SNMP for interface "..name
                        ..": no statistics counters available")
            end
         else
            -- Set up SNMP for sub-interfaces
            counter_t = ffi.typeof("struct counter")
            local counters = {}
            local function map (c)
               return (c and ffi.cast("struct counter *", c)) or nil
            end
            counters.type = counter_t()
            if intf.l3 then
               counters.type.c = 0x1003ULL -- l3ipvlan
            else
               counters.type.c = 0x1002ULL -- l2vlan
            end
            -- Inherit the operational status, MAC address, MTU, speed
            -- from the physical interface
            local stats = intf.phys_intf.stats
            counters.status = map(stats.status)
            counters.macaddr = map(stats.macaddr)
            counters.mtu = map(stats.mtu)
            counters.speed = map(stats.speed)

            -- Create mappings to the counters of the relevant VMUX
            -- link The VMUX app replaces the physical network for a
            -- sub-interface.  Hence, its output is what the
            -- sub-interface receives and its input is what the
            -- sub-interface transmits to the "virtual wire".
            local function find_linkspec (pattern)
               pattern = string.gsub(pattern, '%.', '%%.')
               for _, linkspec in ipairs(state.links) do
                  if string.match(linkspec, pattern) then
                     return linkspec
                  end
               end
               error("No links match pattern: "..pattern)
            end
            local tstats = shm.open_frame(
               'links/'..
                  find_linkspec('^'..intf.vmux_connector.output()))
            local rstats = shm.open_frame(
               'links/'..
                  find_linkspec(intf.vmux_connector.input()..'$'))
            counters.rxpackets = map(tstats.txpackets)
            counters.rxbytes = map(tstats.txbytes)
            counters.rxdrop = map(tstats.txdrop)
            counters.txpackets = map(rstats.rxpackets)
            counters.txbytes = map(rstats.rxbytes)
            ifmib.init_snmp( { ifDescr = name,
                               ifName = name,
                               ifAlias = intf.description, },
               string.gsub(name, '/', '-'), counters,
               main_config.shmem_dir, snmp.interval or 5)
         end
      end
   end
end

local function create_app_graph ()
   local graph = app_graph.new()
   for name, app in pairs(state.apps) do
      -- Copy arg to allow app reconfiguration
      app_graph.app(graph, app:name(), app:class(), lib.deepcopy(app:arg()))
   end
   for _, linkspec in ipairs(state.links) do
      app_graph.link(graph, linkspec)
   end
   return graph
end

local long_opts = {
   duration = "D",
   reconfig = "r",
   logfile = "l",
   debug = "d",
   jit = "j",
   help = "h",
}

function run (parameters)
   local duration = 0
   local reconfig = false
   local jit_conf = {}
   local jit_opts = {}
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
      elseif arg:match("^opt") then
         local opt = arg:match("^opt=(.*)")
         table.insert(jit_opts, opt)
      end
   end
   function opt.r (arg) reconfig = true end

   -- Parse command line arguments
   parameters = lib.dogetopt(parameters, opt, "hdj:D:l:r", long_opts)
   if (reconfig and not (duration > 0)) then
      print("--reconfig requires --duration > 0 to take effect")
      usage()
   end

   -- Defaults: sizemcode=32, maxmcode=512
   require("jit.opt").start('sizemcode=256', 'maxmcode=2048')
   if #jit_opts then
      require("jit.opt").start(unpack(jit_opts))
   end
   if #parameters ~= 1 then usage () end

   local file = table.remove(parameters, 1)

   local engine_opts = { no_report = true, measure_latency = false }
   if duration ~= 0 then engine_opts.duration = duration end
   if jit_conf.p then
      require("jit.p").start(jit_conf.p.opts, jit_conf.p.file)
   end
   if jit_conf.dump then
      require("jit.dump").start(jit_conf.dump.opts, jit_conf.dump.file)
   end
   local mtime = 0
   local loop = true
   while loop do
      local stat, err = S.stat(file)
      if not stat then
         error("Can't stat "..file..": "..tostring(err))
      end
      if mtime ~= stat.mtime then
         -- This is a very crude and disruptive way to pick up changes
         -- of the configuration while the system is running. It
         -- requires setting -D to a reasonable non-zero value. By
         -- default, the configuration is instantiated only once and
         -- engine.main() runs indefinitely.  The proper way to do
         -- this is to write a YANG schema and use core.config.
         print("Instantiating configuration")
         clear_state()
         local main_config = assert(loadfile(file))()
         parse_config(main_config)
         engine.configure(create_app_graph())
         setup_shm_and_snmp(main_config)
         -- Reconfigure ND/ARP apps with proper MAC addresses from the
         -- interfaces to which they are attached
         for name, nd in pairs(state.nds) do
            nd.app:arg().local_mac =
               macaddress:new(counter.read(nd.intf.stats.macaddr)).bytes
         end
         for name, arp in pairs(state.arps) do
            arp.app:arg().self_mac =
               macaddress:new(counter.read(arp.intf.stats.macaddr)).bytes
         end
         engine.configure(create_app_graph())
         jit.flush()
      end
      mtime = stat.mtime
      engine.main(engine_opts)
      loop = reconfig
   end
   if jit_conf.p then
      require("jit.p").stop()
   end
end
