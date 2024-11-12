# Purpose: This script is used to generate a model with coreLang assets and save it to a JSON file.

import logging

import maltoolbox
from maltoolbox.language import LanguageGraph, LanguageClassesFactory
from maltoolbox.model import Model, AttackerAttachment
from maltoolbox.ingestors import neo4j


logger = logging.getLogger(__name__)

lang_file = '../../org.mal-lang.coreLang-1.0.0.mar'
lang_graph = LanguageGraph.from_mar_archive(lang_file)
lang_classes_factory = LanguageClassesFactory(lang_graph)
model = Model('M1', lang_classes_factory)

# ComputeResources Section

## Hardware
hw_1 = lang_classes_factory.ns.Hardware(name = "Hw Computer_1_Employee_1")
hw_2 = lang_classes_factory.ns.Hardware(name = "Hw Server_1")
#hw_3 = lang_classes_factory.ns.Hardware(name = "Server S2")

model.add_asset(hw_1)
model.add_asset(hw_2)
#model.add_asset(hw_3)

## Applications
app_1_0 = lang_classes_factory.ns.Application(name = "App 1.0_OS_Windows")
app_2_0 = lang_classes_factory.ns.Application(name = "App 2.0_Server_Windows")
app_2_1 = lang_classes_factory.ns.Application(name = "App 2.1_Server_HTTP")
app_2_2 = lang_classes_factory.ns.Application(name = "App 2.2_Docker")
app_2_3 = lang_classes_factory.ns.Application(name = "App 2.3_FirewallConfig")

model.add_asset(app_1_0)
model.add_asset(app_2_0)
model.add_asset(app_2_1)
model.add_asset(app_2_2)
model.add_asset(app_2_3)

assoc_hw_1_app_1_0 =\
    lang_classes_factory.ns.SysExecution(
    hostHardware = [hw_1],
    sysExecutedApps = [app_1_0]
    )
model.add_association(assoc_hw_1_app_1_0)

assoc_hw_2_app_2_0 =\
    lang_classes_factory.ns.SysExecution(
    hostHardware = [hw_2],
    sysExecutedApps = [app_2_0]
    )
model.add_association(assoc_hw_2_app_2_0)

assoc_app_2_0_apps =\
    lang_classes_factory.ns.AppExecution(
    hostApp = [app_2_0],
    appExecutedApps = [app_2_1, app_2_2, app_2_3]
    )
model.add_association(assoc_app_2_0_apps)


## PhysicalZone
pz_1 = lang_classes_factory.ns.PhysicalZone(name = "Zone 1")
pz_2 = lang_classes_factory.ns.PhysicalZone(name = "Zone 2")
model.add_asset(pz_1)
model.add_asset(pz_2)

assoc_pz_1 =\
    lang_classes_factory.ns.ZoneInclusion(
    physicalZones = [pz_1],
    hardwareSystems = [hw_1]
    )
model.add_association(assoc_pz_1)


assoc_pz_2 =\
    lang_classes_factory.ns.ZoneInclusion(
    physicalZones = [pz_2],
    hardwareSystems = [hw_2]
    )
model.add_association(assoc_pz_2)


# DataResource Section

## Data



# Networking Section

## Routing Firewall
fw_1 = lang_classes_factory.ns.RoutingFirewall(name = "Router FW_1")
model.add_asset(fw_1)

## LAN network
net_1 = lang_classes_factory.ns.Network(name = "Net LAN_1")
model.add_asset(net_1)

### Connection Rules
cr_net_1_fw_1 = lang_classes_factory.ns.ConnectionRule(name = "CR Net_LAN_1->Router_FW_1")
cr_net_1_app_1_0 = lang_classes_factory.ns.ConnectionRule(name = "CR Net_LAN_1<->App_1.0")
cr_net_1_app_2_0 = lang_classes_factory.ns.ConnectionRule(name = "CR Net_LAN_1<->App_2.0")


model.add_asset(cr_net_1_fw_1)
model.add_asset(cr_net_1_app_1_0)
model.add_asset(cr_net_1_app_2_0)


### Associations
assoc_cr_net_1_app_1_0 =\
    lang_classes_factory.ns.ApplicationConnection(
    applications = [app_1_0],
    appConnections = [cr_net_1_app_1_0]
    )
model.add_association(assoc_cr_net_1_app_1_0)

assoc_cr_net_1_app_2_0 =\
    lang_classes_factory.ns.ApplicationConnection(
    applications = [app_2_0],
    appConnections = [cr_net_1_app_2_0]
    )
model.add_association(assoc_cr_net_1_app_2_0)


assoc_netcon_crs_net_1_Out =\
    lang_classes_factory.ns.InNetworkConnection(
    inNetworks = [net_1],
    ingoingNetConnections = [cr_net_1_fw_1]
    )
model.add_association(assoc_netcon_crs_net_1_Out)

assoc_netcon_crs_net_1 =\
    lang_classes_factory.ns.NetworkConnection(
    networks = [net_1],
    netConnections = [cr_net_1_app_1_0, cr_net_1_app_2_0]
    )
model.add_association(assoc_netcon_crs_net_1)



## Routing Firewall and networks associations
assoc_netcon_fwcrs =\
    lang_classes_factory.ns.FirewallConnectionRule(
    routingFirewalls = [fw_1],
    connectionRules = [cr_net_1_fw_1]
    )
model.add_association(assoc_netcon_fwcrs)

assoc_fw_app =\
    lang_classes_factory.ns.ManagedBy(
    managedRoutingFw = [fw_1],
    managerApp = [app_2_3]
    )
model.add_association(assoc_fw_app)



# IAM Section

## Identities

id_u1 = lang_classes_factory.ns.Identity(name = "Id Admin_1")
id_u2 = lang_classes_factory.ns.Identity(name = "Id Employee_1")

model.add_asset(id_u1)
model.add_asset(id_u2)


assoc_exec_privs_u1 =\
    lang_classes_factory.ns.HighPrivilegeApplicationAccess(
    highPrivAppIAMs = [id_u1],
    highPrivApps = [app_1_0, app_2_0]
    )
model.add_association(assoc_exec_privs_u1)

assoc_exec_privs_u2 =\
    lang_classes_factory.ns.LowPrivilegeApplicationAccess(
    lowPrivAppIAMs = [id_u2],
    lowPrivApps = [app_1_0]
    )
model.add_association(assoc_exec_privs_u2)


# User Section
## User
user_1 = lang_classes_factory.ns.User(name = "User Admin_1")
user_2 = lang_classes_factory.ns.User(name = "User Employee_1")

model.add_asset(user_1)
model.add_asset(user_2)

### Associations
assoc_user_id_u1 =\
    lang_classes_factory.ns.UserAssignedIdentities(
    users = [user_1],
    userIds = [id_u1]
    )
model.add_association(assoc_user_id_u1)

assoc_user_id_u2 =\
    lang_classes_factory.ns.UserAssignedIdentities(
    users = [user_2],
    userIds = [id_u2]
    )
model.add_association(assoc_user_id_u2)


assoc_user_1_hw =\
    lang_classes_factory.ns.HardwareAccess(
    users = [user_1],
    hardwareSystems = [hw_1, hw_2]
    )
model.add_association(assoc_user_1_hw)

assoc_user_2_hw =\
    lang_classes_factory.ns.HardwareAccess(
    users = [user_2],
    hardwareSystems = [hw_1]
    )
model.add_association(assoc_user_2_hw)




# Attack Vectors Section
# Attacker section
#attacker1 = malmodel.Attacker()
#attacker1.entry_points = [(net_2, ["fullAccess"])]
#model.add_attacker(attacker1)

# Save model configurations to a JSON file
model.save_to_file('model_3.json')