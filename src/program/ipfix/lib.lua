module(..., package.seeall)

local lib         = require("core.lib")
local app_graph   = require("core.config")
local pci         = require("lib.hardware.pci")
local basic       = require("apps.basic.basic_apps")
local ipfix       = require("apps.ipfix.ipfix")
local tap         = require("apps.tap.tap")
local rss         = require("apps.rss.rss")
local iftable     = require("apps.snmp.iftable")
local Receiver    = require("apps.interlink.receiver")
local Transmitter = require("apps.interlink.transmitter")
local pcap        = require("apps.pcap.pcap")
local vlan        = require("apps.vlan.vlan")

local Graph = {}
function Graph:new ()
   return setmetatable(
      {
         apps = {},
         links ={},
      }, { __index = Graph })
end

function Graph:add_app (app)
   local name = app:name()
   assert(not self.apps[name], "Duplicate app "..name)
   self.apps[name] = app
end

function Graph:connect (from, to)
   assert(self.apps[from.app:name()])
   assert(self.apps[to.app:name()])
   assert(not from.connected)
   assert(not to.connected)
   from.connected = true
   to.connected = true
   table.insert(self.links, from.output..' -> '..to.input)
end

function Graph:app_graph ()
   local graph = app_graph.new()
   for name, app in pairs(self.apps) do
      app_graph.app(graph, app:name(), app:class(), app:config())
   end
   for _, linkspec in ipairs(self.links) do
      app_graph.link(graph, linkspec)
   end
   return graph
end

function Graph:embed (graph)
   for name, app in pairs(graph.apps) do
      assert(not self.apps[name], "Graph:copy: duplicate app "..name)
      self.apps[name] = app
   end
   for _, link in ipairs(graph.links) do
      table.insert(self.links, link)
   end
end

local App = {}
function App:new (graph, name, class, config)
   local self = setmetatable({}, { __index = App })
   self._name = name
   self._class = class
   self:config(config)
   graph:add_app(self)
   return self
end

function App:name ()
   return self._name
end

function App:class ()
   return self._class
end

function App:config (config)
   if config == nil then return self._config end
   self._config = config
end

function App:update (config)
   for k, v in pairs(config) do
      self._config[k] = v
   end
end

function App:socket (name)
   local full_name = self._name.."."..name
   return {
      connected = false,
      app = self,
      input = full_name,
      output = full_name
   }
end

function graph ()
   return Graph:new()
end

function ipfix_app (graph, config)
   return App:new(graph, "ipfix_"..assert(config.instance),
                  ipfix.IPFIX, config)
end

function tap_app (graph, mtu, log_date)
   local tap_name = "ipfixexport"
   local tap = App:new(graph, tap_name, tap.Tap, {
                          name = tap_name,
                          mtu = mtu,
                          overwrite_dst_mac = true,
                          forwarding = true })
   local sink = App:new(graph, "submit_sink",
                        basic.Sink)
   local ifmib = App:new(graph, "submit_ifmib",
                         iftable.MIB, {
                            target_app = tap_name,
                            ifname = "ipfixexport",
                            ifalias = "IPFIX export",
                            log_date = log_date })
   local join = App:new(graph, "submit_join", basic.Join)
   graph:connect(join:socket('output'), tap:socket('input'))
   return join
end

function interlink_pair (xmt_graph, rcv_graph, name, size)
   local full_name = "interlink_"..name
   local xmt = App:new(xmt_graph, full_name, Transmitter, { size = size })
   local rcv = App:new(rcv_graph, full_name, Receiver, { size = size })
   return xmt, rcv
end

function pcap_app (graph, pcap_file, rss_group)
   return App:new(graph, "pcap_"..rss_group,
                  pcap.PcapReader, pcap_file)
end

local function normalize_pci_name (device)
   return pci.qualified(device):gsub("[:%.]", "_")
end

local function pci_input (graph, config)
   config = lib.parse(config, {
      device={required=true},
      rxq={required=true},
      receive_queue_size={required=true},
      log_date={required=true},
      vlan_tag={},
      name={},
      description={}
   })

   local pci_name = normalize_pci_name(config.device)
   local in_name = "input_"..pci_name.."_rxq"..config.rxq
   local device_info = pci.device_info(config.device)
   assert(device_info.usable == "yes",
          ("Unsupported device %s (%x:%x)"):format(config.device,
                                                   device_info.vendor,
                                                   device_info.device))
   local driver = require(device_info.driver).driver
   local conf
   if device_info.driver == 'apps.intel_mp.intel_mp' then
      conf = {
         pciaddr = config.device,
         rxq = config.rxq,
         rxcounter = config.rxq,
         ring_buffer_size = config.receive_queue_size
      }
   elseif device_info.driver == 'apps.mellanox.connectx' then
      conf = {
         pciaddress = config.device,
         queue = config.rxq
      }
   end

   local driver = App:new(graph, in_name, driver, conf)
   local ifmib = App:new(graph, "nic_ifmib_"..in_name, iftable.MIB, {
                            target_app = in_name, stats = 'stats',
                            ifname = config.name or pci_name,
                            ifalias = config.description,
                            log_date = config.log_date })
   return pci_name, driver:socket(device_info.tx)
end

function pci_links (graph, inputs)
   local links = {}
   local tags = {}
   for _, pci_config in ipairs(inputs) do
      local pci_name, socket = pci_input(graph, pci_config)
      local link_name = 'input_'..pci_name
      if (pci_config.vlan_tag) then
         local tag = pci_config.vlan_tag
         if tags[tag] then
            error(pci_name..": VLAN tag "..tag.." already assigned to "..tags[tag])
         end
         -- NB: adhere to the naming convention of the "pseudo
         -- VLAN-tagging" feature of the rss app
         link_name = "vlan"..tag
         tags[tag] = pci_name
      end
      table.insert(links, { socket, link_name })
   end
   return links
end

function join_app (graph, rss_group)
   return App:new(graph, "join_"..rss_group, basic.Join)
end

function rss_app (graph, config, rss_group)
    return App:new(graph, "rss"..rss_group, rss.rss, config)
end

function vlan_tagger_app (graph, tag)
   return App:new(graph, "vlan_"..tag, vlan.Tagger, { tag = tonumber(tag) })
end

function configure_mlx_controller (devices)
   -- Create a trivial app graph that only contains the control apps
   -- for the Mellanox driver, which sets up the queues and
   -- maintains interface counters.
   local ctrl_graph, need_ctrl = app_graph.new(), false
   for device, spec in pairs(devices) do
      spec = lib.parse(spec, {
         queues={required=true},
         recvq_size={required=true},
         log_date={required=true},
         name={},
         alias={}
      })
      local conf = {
         pciaddress = device,
         queues = spec.queues,
         recvq_size = spec.recvq_size
      }
      local pci_name = normalize_pci_name(device)
      local driver = pci.device_info(device).driver
      app_graph.app(ctrl_graph, "ctrl_"..pci_name,
                    require(driver).ConnectX, conf)
      app_graph.app(ctrl_graph, "nic_ifmib_"..pci_name, iftable.MIB, {
         target_app = "ctrl_"..pci_name, stats = 'stats',
         ifname = spec.name or pci_name,
         ifalias = spec.alias,
         log_date = spec.log_date
      })
      need_ctrl = true
   end
   return ctrl_graph, need_ctrl
end
