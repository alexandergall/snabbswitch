module(..., package.seeall)

local yang = require("lib.yang.yang")
local yang_util = require("lib.yang.util")
local path_data = require("lib.yang.path_data")
local mem = require("lib.stream.mem")
local ptree = require("lib.ptree.ptree")
local cpuset = require("lib.cpuset")
local pci = require("lib.hardware.pci")
local lib = require("core.lib")
local app_graph = require("core.config")

local ipfix = require("apps.ipfix.ipfix")
local probe = require("program.ipfix.lib")

local probe_schema = 'snabb-snabbflow-v1'

local usage = require("program.ipfix.probe.README_inc")

local long_opts = {
   help = "h",
   name = "n",
   busywait ="b",
   ["real-time"] = "r",
   ["no-profile"] = "p",
   ["test-pcap"] = "T"
}
local opt = "hn:brpT:"
local opt_handler = {}
local name
local busywait, real_time, profile = false, false, true
function opt_handler.h () print(usage) main.exit(0) end
function opt_handler.n (arg) name = arg end
function opt_handler.b () busywait = true end
function opt_handler.r () real_time = true end
function opt_handler.p () profile = false end
local pcap_input
function opt_handler.T (arg) pcap_input = arg end

function run (args)
   args = lib.dogetopt(args, opt_handler, opt, long_opts)
   if #args ~= 1 then
      print(usage)
      main.exit(1)
   end
   local confpath = args[1]
   local manager = start(name, confpath)
   manager:main()
end

local probe_cpuset = cpuset.new()

local function update_cpuset (cpu_pool)
   local cpu_set = {}
   if cpu_pool then
      for _, cpu in ipairs(cpu_pool.cpu or {}) do
         if not probe_cpuset:contains(cpu) then
            probe_cpuset:add(cpu)
         end
         cpu_set[cpu] = true
      end
      for _, cpu in ipairs(probe_cpuset:list()) do
         if not cpu_set[cpu] then
            probe_cpuset:remove(cpu)
         end
      end
   end
end

local probe_group_freelist_size

local function update_group_freelist_size (nchunks)
   if not probe_group_freelist_size then
      probe_group_freelist_size = nchunks
   elseif probe_group_freelist_size ~= nchunks then
      error("Can not change group-freelist-size after probe has started.")
   end
   return probe_group_freelist_size
end

local function warn (msg, ...)
   io.stderr:write("Warning: "..msg:format(...).."\n")
   io.stderr:flush()
end



function start (name, confpath)
   local conf = yang.load_configuration(confpath, {schema_name=probe_schema})
   update_cpuset(conf.snabbflow_config.rss.cpu_pool)
   return ptree.new_manager{
      log_level = 'INFO',
      setup_fn = setup_workers,
      initial_configuration = conf,
      schema_name = probe_schema,
      cpuset = probe_cpuset,
      name = name,
      worker_default_scheduling = {
         busywait = busywait,
         real_time = real_time,
         profile = profile,
         group_freelist_size = update_group_freelist_size(
            conf.snabbflow_config.rss.software_scaling.group_freelist_size
         ),
         max_packets = conf.snabbflow_config.rss.software_scaling.maximum_packets,
         jit_opt = {
            sizemcode=256,
            maxmcode=8192,
            maxtrace=8000,
            maxrecord=50000,
            maxsnap=20000,
            maxside=10000
         }
      },
   }
end

local ipfix_default_config = lib.deepcopy(ipfix.IPFIX.config)
for _, key in ipairs({
      "collector_ip",
      "collector_port",
      "observation_domain",
      "exporter_mac",
      "templates",
      "instance"
}) do
   ipfix_default_config[key] = nil
end

local software_scaling_parser = path_data.parser_for_schema_by_name(
   probe_schema, '/snabbflow-config/rss/software-scaling/pipeline[name=""]'
)
local default_software_scaling =
   software_scaling_parser(mem.open_input_string(''))

function setup_workers (config)
   local interfaces = config.snabbflow_config.interface
   local rss = config.snabbflow_config.rss
   local flow_director = config.snabbflow_config.flow_director
   local ipfix = config.snabbflow_config.ipfix

   update_group_freelist_size(rss.software_scaling.group_freelist_size)

   local collector_pools = {}
   for name, p in pairs(ipfix.collector_pool) do
      local collectors = {}
      for _, entry in ipairs(p.collector) do
         table.insert(collectors, {
            ip = yang_util.ipv4_ntop(entry.ip),
            port = entry.port
         })
      end
      collector_pools[name] = collectors
   end

   local function select_collector (pool)
      -- Select the collector ip and port from the front of the
      -- pool and rotate the pool's elements by one
      assert(collector_pools[pool] and #collector_pools[pool] > 0,
               "Undefined or empty collector pool: "..pool)
      local collector = table.remove(collector_pools[pool], 1)
      table.insert(collector_pools[pool], collector)
      return collector
   end

   if flow_director.default_class.pipeline then
      assert(not flow_director.class[flow_director.default_class.pipeline],
             "Pipeline for the default traffic class can not be the pipeline for a defined class.")
   end

   local observation_domain = ipfix.observation_domain_base
   local function next_observation_domain ()
      local ret = observation_domain
      observation_domain = observation_domain + 1
      return ret
   end
   
   local workers = {}
   local worker_opts = {}

   local mellanox = {}

   update_cpuset(rss.cpu_pool)

   local function ensure_device_unique (device, interfaces)
      for other in pairs(interfaces) do
         if device ~= other then
            if pci.qualified(device) == pci.qualified(other) then
               error("Duplicate interfaces: "..device..", "..other..
                     "\nNot applying configuration. Remove one of them via"..
                     ("\n  snabb config remove <snabbflow> /snabbflow-config/interface[device=%q]")
                     :format(other))
            end
         end
      end
   end

   -- Derive the base configuration of the IPFIX app from the YANG
   -- configuration instance. It will be replicated and modified to
   -- obtain per-instance configurations.
   local base_config = {}
   for key in pairs(ipfix_default_config) do
      if key == "maps" then
         base_config.maps = {}
         for name, map in pairs(ipfix.maps) do
            base_config.maps[name] = map.file
         end
      elseif key == "exporter_ip" then
         base_config.exporter_ip = yang_util.ipv4_ntop(ipfix.exporter_ip)
      else
         base_config[key] = ipfix[key]
      end
   end
   local function pipeline_config(pipeline, instance_prefix)
      local configs = {}
      for name, spec in pairs(pipeline.exporter) do
         local exporter = ipfix.exporter[name]

         -- Create a clone of the configuration for parameters
         -- specific to the instance
         local config = lib.deepcopy(base_config)

         -- Flow table Overrides
         for k, v in pairs(exporter) do
            if not (k == "template" or k == "collector_pool" or k == "name"
                    or k == "scan_protection") then
               config[k] = v
            end
         end

         -- Scan protection overrides
         for k, v in pairs(exporter.scan_protection) do
            config.scan_protection[k] = v
         end

         -- Hint for the caller, must be removed before instantiating
         -- the IPFIX app
         config.extrude = {
            extrude = spec.extrude,
            acquire_cpu = spec.acquire_cpu
         }

         config.instance = name
         config.templates = exporter.template
         config.add_packet_metadata = false

         local collector = select_collector(exporter.collector_pool)
         config.collector_ip = collector.ip
         config.collector_port = collector.port
         config.log_date = ipfix.log_date
         local od = next_observation_domain()
         config.observation_domain = od
         if ipfix.maps.log_directory then
            config.maps_logfile =
               ipfix.maps.log_directory.."/"..od..".log"
         end

         -- Subtract Ethernet overhead from MTU
         config.mtu = config.mtu - 14

         table.insert(configs, config)
      end
      return configs
   end

   -- App graph for an instance of the tap app that submits all
   -- IPFIX export packets to the kernel
   local submit_graph = probe.graph()
   local submit_join = probe.tap_app(submit_graph, base_config.mtu, base_config.log_date)

   for rss_group = 1, rss.hardware_scaling.rss_groups do
      local inputs, sockets, rss_links = {}, {}, {}
      -- App graph that will be run in the RSS worker process
      local rss_graph = probe.graph()

      -- Populate the list of inputs from interface configurations
      for device, opt in pairs(interfaces) do
         ensure_device_unique(device, interfaces)
         local input = lib.deepcopy(opt)
         input.device = device
         input.rxq = rss_group - 1
         input.log_date = ipfix.log_date
         table.insert(inputs, input)

         -- The mellanox driver requires a master process that sets up
         -- all queues for the interface. We collect all queues per
         -- device of this type here.
         local device_info = pci.device_info(device)
         if device_info.driver == 'apps.mellanox.connectx' then
            local spec = mellanox[device]
            if not spec then
               spec = { name = input.name,
                        alias = input.description,
                        queues = {},
                        recvq_size = input.receive_queue_size,
                        log_date = ipfix.log_date }
               mellanox[device] = spec
            end
            table.insert(spec.queues, { id = input.rxq })
         else
            -- Silently truncate receive-queue-size for other drivers.
            -- (We are not sure what they can handle.)
            input.receive_queue_size = math.min(input.receive_queue_size, 8192)
         end
      end

      -- Configure exporter pipelines. Each pipline consists of a list
      -- of exporters that will be chained together back-to-back. The
      -- same exporter can appear in multiple pipelines but at most
      -- once in a single pipeline. Populates the sockets and
      -- rss_links tables.
      for name, pipeline in pairs(ipfix.pipeline) do
         local software_scaling = (rss.software_scaling.pipeline and
                                    rss.software_scaling.pipeline[name])
                               or default_software_scaling
         local num_instances = 1
         if not software_scaling.embed then
            num_instances = software_scaling.instances
         end

         local function add_worker_with_restart(name, graph, acquire_cpu)
            local acquire
            if acquire_cpu ~= nil then
               acquire = acquire_cpu
            else
               acquire = software_scaling.acquire_cpu
            end
            workers[name] = graph:app_graph()
            worker_opts[name] = {
               restart_intensity = software_scaling.restart.intensity,
               restart_period = software_scaling.restart.period,
               acquire_cpu = acquire
            }
         end

         local rss_class = flow_director.class[name]
         -- NB: The link base name must adhere to the naming
         -- conventions of the rss app.
         if flow_director.class[name] then
            rss_class = name
         elseif name == flow_director.default_class.pipeline then
            rss_class = 'default'
         else
            -- No traffic class configured for pipeline, do not create
            -- instances.
            warn("No traffic class configured for pipeline '%s'.", name)
            break
         end

         local sp_scale_factor = rss.hardware_scaling.rss_groups * num_instances
         local ext_seq = 0
         for i = 1, num_instances do
            -- Outermost App graph of the pipeline. It will be either
            -- embeded into rss_graph or run as a separate worker
            local outer_graph = probe.graph()
            -- App graph that follows extrusions
            local inner_graph = outer_graph
            local head, prev, acquire_cpu, prev_acquire_cpu
            local function ext_worker_name ()
               ext_seq = ext_seq + 1
               return "rss"..rss_group.."_"..i.."_"..name.."_extrude_"..ext_seq
            end
            for _, config in ipairs(pipeline_config(pipeline)) do
               -- Make the RSS group and instance id discoverable from
               -- the app name for the YANG get-state logic
               config.instance = "rss"..rss_group.."_"..i.."_"..name.."_"..config.instance

               -- Scale the scan protection parameters by the number of
               -- ipfix instances in this RSS class
               config.scan_protection.threshold_rate =
                  config.scan_protection.threshold_rate / sp_scale_factor
               config.scan_protection.export_rate =
                  config.scan_protection.export_rate / sp_scale_factor

               local extrude = config.extrude
               config.extrude = nil
               local tmp_graph = probe.graph()
               local ipfix = probe.ipfix_app(tmp_graph, config)
               local xmit, rcv = probe.interlink_pair(tmp_graph, submit_graph,
                                                      config.instance.."_submit",
                                                      rss.software_scaling.interlink_size)
               tmp_graph:connect(ipfix:socket('output'), xmit:socket('input'))
               submit_graph:connect(rcv:socket('output'), submit_join:socket(config.instance))
               if not head then
                  head = ipfix
                  inner_graph:embed(tmp_graph)
               elseif extrude.extrude then
                  acquire_cpu = extrude.acquire_cpu
                  local xmit, rcv =
                     probe.interlink_pair(inner_graph, tmp_graph,
                                          config.instance.."_extrude_",
                                          rss.software_scaling.interlink_size)
                  inner_graph:connect(prev:socket('passthru'), xmit:socket('input'))
                  if inner_graph ~= outer_graph then
                     -- The inner graph is now complete, start as worker
                     add_worker_with_restart(ext_worker_name(), inner_graph,
                                             prev_acquire_cpu)
                  end
                  prev_acquire_cpu = acquire_cpu
                  tmp_graph:connect(rcv:socket('output'), ipfix:socket('input'))
                  inner_graph = tmp_graph
               else
                  inner_graph:embed(tmp_graph)
                  inner_graph:connect(prev:socket('passthru'), ipfix:socket('input'))
               end
               prev = ipfix
            end
            if inner_graph ~= outer_graph then
               -- The last inner graph is complete, start as worker
               add_worker_with_restart(ext_worker_name(), inner_graph,
                                       prev_acquire_cpu)
            end

            -- Outgoing link of the rss app
            local rss_link = rss_class.."_"..i
            table.insert(rss_links, rss_link)
            -- Globally unique name for interlink apps and worker
            -- processes
            local rss_link_id = "rss"..rss_group.."_"..rss_link
            if software_scaling.embed then
               rss_graph:embed(outer_graph)
               table.insert(sockets, head:socket('input'))
            else
               -- Run this graph in a worker
               local xmt, rcv =
                  probe.interlink_pair(rss_graph, outer_graph, rss_link_id,
                                       rss.software_scaling.interlink_size)
               outer_graph:connect(rcv:socket('output'), head:socket('input'))
               add_worker_with_restart(rss_link_id, outer_graph)
               table.insert(sockets, xmt:socket('input'))
            end
         end
      end

      local rss_config = {
         default_class = flow_director.default_class.pipeline ~= nil,
         classes = {},
         remove_extension_headers = flow_director.remove_ipv6_extension_headers
      }
      for i, class in ipairs(flow_director.class) do
         table.insert(rss_config.classes, {
            name = class.pipeline,
            filter = class.filter,
            continue = class.continue
         })
      end

      -- Instantiate the graph for the RSS worker, applying
      -- optimizations for special cases
      if #sockets == 1 and string.find(sockets[1].app:name(), "ipfix") then
         -- We have a single pipeline within a single process (no flow
         -- director classes, and a single embedded pipeline
         -- instance.)
         -- This is the simple case: omit creating a software RSS app.
         -- NB: IPFIX app has to extract metadata as software RSS app
         -- is not present.
         local socket = sockets[1]
         socket.app:update({ add_packet_metadata = true })
         local socket_out

         -- Replace the pseudo VLAN tagging feature of the RSS app
         -- with explicit tagging if tagging is requested for an
         -- interface by inserting an instance of the VLAN tagger app.
         local function maybe_add_vlan (name, socket)
            local tag = string.match(name, '^vlan(%d+)')
            if tag then
               local tagger = probe.vlan_tagger_app(rss_graph, tag)
               rss_graph:connect(socket, tagger:socket('input'))
               return tagger:socket('output')
            else
               -- Pass through
               return socket
            end
         end

         if pcap_input then
            socket_out = probe.pcap_app(rss_graph, pcap_input,
                                        rss_group):socket('output')
         else
            local links = probe.pci_links(rss_graph, inputs)
            if #links == 1 then
               -- Only one input, connect straight to the embeded
               -- pipeline
               local socket, name = table.unpack(links[1])
               socket_out = maybe_add_vlan(name, socket)
            else
               -- Join all inputs
               local join = probe.join_app(rss_graph, rss_group)
               for _, link in ipairs(links) do
                  local socket, name = table.unpack(link)
                  socket = maybe_add_vlan(name, socket)
                  rss_graph:connect(socket, join:socket(name))
               end
               socket_out = join:socket('output')
            end
         end
         rss_graph:connect(socket_out, socket)
      else
         -- Otherwise we have the general case: configure a software
         -- RSS app to distribute inputs over flow director classes
         -- and pipeline instances.
         local rss = probe.rss_app(rss_graph, rss_config, rss_group)
         if pcap_input then
            local pcap = probe.pcap_app(rss_graph, pcap_input, rss_group)
            rss_graph:connect(pcap:socket('output'), rss:socket('pcap'))
         else
            for _, link in ipairs(probe.pci_links(rss_graph, inputs)) do
               local socket, name = table.unpack(link)
               rss_graph:connect(socket, rss:socket(name))
            end
         end
         for i, socket in ipairs(sockets) do
            rss_graph:connect(rss:socket(rss_links[i]), socket)
         end
      end
      workers["rss"..rss_group] = rss_graph:app_graph()
   end
   workers["submit"] = submit_graph:app_graph()
   worker_opts["submit"] = { acquire_cpu = false }

   if not pcap_input then
      -- Create a trivial app graph that only contains the control apps
      -- for the Mellanox driver, which sets up the queues and
      -- maintains interface counters.
      local ctrl_graph, need_ctrl = probe.configure_mlx_controller(mellanox)

      if need_ctrl then
         workers["mlx_ctrl"] = ctrl_graph
         worker_opts["mlx_ctrl"] = {acquire_cpu=false}
      end
   end

   if false then -- enable to debug
      for name, graph in pairs(workers) do
         print("worker", name)
         print("", "apps:")
         for name, _ in pairs(graph.apps) do
            print("", "", name)
         end
         print("", "links:")
         for spec in pairs(graph.links) do
            print("", "", spec)
         end
      end
   end

   return workers, worker_opts
end
