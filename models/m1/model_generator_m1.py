# Purpose: This script is used to statically create and generate a model with coreLang assets and save it to a JSON file.

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
app_2_1 = lang_classes_factory.ns.Application(name = "App 2.1_RemoteAccess_TeamViewer")

model.add_asset(app_1_0)
model.add_asset(app_2_0)
model.add_asset(app_2_1)

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

assoc_app_2_0_app_2_1 =\
    lang_classes_factory.ns.AppExecution(
    hostApp = [app_2_0],
    appExecutedApps = [app_2_1]
    )
model.add_association(assoc_app_2_0_app_2_1)





# DataResource Section

## Data
data_s1_1 = lang_classes_factory.ns.Data(name = "Data Secret")
model.add_asset(data_s1_1)

assoc_app_1_0_data_s1_1 =\
    lang_classes_factory.ns.AppContainment(
    containedData = [data_s1_1],
    containingApp = [app_1_0]
    )
model.add_association(assoc_app_1_0_data_s1_1)




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
    lang_classes_factory.ns.OutNetworkConnection(
    outNetworks = [net_1],
    outgoingNetConnections = [cr_net_1_fw_1]
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



# IAM Section

## Identities
id_u1 = lang_classes_factory.ns.Identity(name = "Id Admin_1")
id_u2 = lang_classes_factory.ns.Identity(name = "Id Employee_1")
id_u3 = lang_classes_factory.ns.Identity(name = "Id ServiceAccount_1")

grp_1 = lang_classes_factory.ns.Group(name = "Group Employees")

cred_u1 = lang_classes_factory.ns.Credentials(name = "Cred Admin_1")
cred_u2 = lang_classes_factory.ns.Credentials(name = "Cred Employee_1")

model.add_asset(id_u1)
model.add_asset(id_u2)
model.add_asset(id_u3)
model.add_asset(grp_1)
model.add_asset(cred_u1)
model.add_asset(cred_u2)


### Associations
assoc_id_u1_cred_u1 =\
    lang_classes_factory.ns.IdentityCredentials(
    identities = [id_u1],
    credentials = [cred_u1]
    )
model.add_association(assoc_id_u1_cred_u1)

assoc_id_u2_cred_u2 =\
    lang_classes_factory.ns.IdentityCredentials(
    identities = [id_u2],
    credentials = [cred_u2]
    )
model.add_association(assoc_id_u2_cred_u2)

assoc_exec_privs_low_grp1 =\
    lang_classes_factory.ns.LowPrivilegeApplicationAccess(
    lowPrivAppIAMs = [grp_1],
    lowPrivApps = [app_1_0]
    )
model.add_association(assoc_exec_privs_low_grp1)

assoc_exec_privs_high_u1 =\
    lang_classes_factory.ns.HighPrivilegeApplicationAccess(
    highPrivAppIAMs = [id_u1],
    highPrivApps = [app_1_0, app_2_0]
    )
model.add_association(assoc_exec_privs_high_u1)


assoc_exec_privs_exec_u2 =\
    lang_classes_factory.ns.ExecutionPrivilegeAccess(
    executionPrivIAMs = [id_u2],
    execPrivApps = [app_2_1, app_1_0]
    )
model.add_association(assoc_exec_privs_exec_u2)

assoc_group_1 =\
    lang_classes_factory.ns.MemberOf(
    memberOf = [grp_1],
    groupIds = [id_u2]
    )
model.add_association(assoc_group_1)

assoc_exec_privs_u3 =\
    lang_classes_factory.ns.HighPrivilegeApplicationAccess(
    highPrivAppIAMs = [id_u3],
    highPrivApps = [app_2_0]
    )
model.add_association(assoc_exec_privs_u3)

assoc_group_1_privRead =\
    lang_classes_factory.ns.ReadPrivileges(
    readingIAMs = [grp_1],
    readPrivData = [data_s1_1]
    )
model.add_association(assoc_group_1_privRead)

assoc_privWrite_u2 =\
    lang_classes_factory.ns.WritePrivileges(
    writingIAMs = [id_u2],
    writePrivData = [data_s1_1]
    )
model.add_association(assoc_privWrite_u2)

assoc_managerIAM_u1 =\
    lang_classes_factory.ns.AccountManagement(
    managers = [id_u1],
    managedIAMs = [id_u3]
    )
model.add_association(assoc_managerIAM_u1)


## Privileges
#priv_1 = lang_classes_factory.ns.Privileges(name = "Priv group_1")
#model.add_asset(priv_1)



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

# Attack Vectors Section

## Software Vulnerabilities


# Attacker section
#attacker1 = malmodel.Attacker()
#attacker1.entry_points = [(net_2, ["fullAccess"])]
#model.add_attacker(attacker1)

# Save model configurations to a JSON file
model.save_to_file('model_1.json')