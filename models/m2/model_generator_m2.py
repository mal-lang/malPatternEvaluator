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

model.add_asset(hw_1)
model.add_asset(hw_2)

## Applications
app_1_0 = lang_classes_factory.ns.Application(name = "App 1.0_OS_Windows")
app_2_0 = lang_classes_factory.ns.Application(name = "App 2.0_Server_Windows")

model.add_asset(app_1_0)
model.add_asset(app_2_0)


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

## SoftwareProduct
swProd_1 = lang_classes_factory.ns.SoftwareProduct(name = "SWProd 1.0_OS_Windows")
model.add_asset(swProd_1)

assoc_swProd_1_app_1_0 =\
    lang_classes_factory.ns.AppSoftwareProduct(
    appSoftProduct = [swProd_1],
    softApplications = [app_1_0]
    )
model.add_association(assoc_swProd_1_app_1_0)




# DataResource Section

## Data
data_s1_1 = lang_classes_factory.ns.Data(name = "Data Secret")
model.add_asset(data_s1_1)

assoc_app_2_0_data_s1_1 =\
    lang_classes_factory.ns.AppContainment(
    containedData = [data_s1_1],
    containingApp = [app_2_0]
    )
model.add_association(assoc_app_2_0_data_s1_1)

## Information
info_s1_1 = lang_classes_factory.ns.Information(name = "Info Secret")
model.add_asset(info_s1_1)

assoc_data_s1_1_info_s1_1 =\
    lang_classes_factory.ns.InfoContainment(
    containerData = [data_s1_1],
    information = [info_s1_1]
    )
model.add_association(assoc_data_s1_1_info_s1_1)

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

assoc_net_1_dataTransit =\
    lang_classes_factory.ns.DataInTransit(
    transitData = [data_s1_1],
    transitNetwork = [net_1]
    )
model.add_association(assoc_net_1_dataTransit)


## Routing Firewall and networks associations
assoc_netcon_fwcrs =\
    lang_classes_factory.ns.FirewallConnectionRule(
    routingFirewalls = [fw_1],
    connectionRules = [cr_net_1_fw_1]
    )
model.add_association(assoc_netcon_fwcrs)





# IAM Section

## Identities

id_u1 = lang_classes_factory.ns.Identity(name = "Id Admin_1")
id_u2 = lang_classes_factory.ns.Identity(name = "Id Employee_1")

model.add_asset(id_u1)
model.add_asset(id_u2)



### Associations

assoc_exec_privs_u1 =\
    lang_classes_factory.ns.HighPrivilegeApplicationAccess(
    highPrivAppIAMs = [id_u1],
    highPrivApps = [app_1_0]
    )
model.add_association(assoc_exec_privs_u1)

assoc_exec_privs_u2 =\
    lang_classes_factory.ns.LowPrivilegeApplicationAccess(
    lowPrivAppIAMs = [id_u2],
    lowPrivApps = [app_1_0]
    )
model.add_association(assoc_exec_privs_u2)

assoc_writePrivs_data_s1_1 =\
    lang_classes_factory.ns.WritePrivileges(
    writingIAMs = [id_u1,id_u2],
    writePrivData = [data_s1_1]
    )
model.add_association(assoc_writePrivs_data_s1_1)






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
    users = [user_2],
    hardwareSystems = [hw_1]
    )
model.add_association(assoc_user_1_hw)


# Vulnerability Section
## Software Vulnerabilities

sw_vuln_1 = lang_classes_factory.ns.SoftwareVulnerability(name = "Vuln SW_1")
model.add_asset(sw_vuln_1)

assoc_sw_vuln_1_app_1_0 =\
    lang_classes_factory.ns.ApplicationVulnerability(
    vulnerabilities = [sw_vuln_1],
    application = [app_1_0]
    )
model.add_association(assoc_sw_vuln_1_app_1_0)


# Attack Vectors Section
# Attacker section
#attacker1 = malmodel.Attacker()
#attacker1.entry_points = [(net_2, ["fullAccess"])]
#model.add_attacker(attacker1)

# Save model configurations to a JSON file
model.save_to_file('model_2.json')