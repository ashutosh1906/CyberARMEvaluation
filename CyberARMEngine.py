import ProjectConfigFile,Utitilities,DistributedCDMOptimizationTestThresholdTactic
from z3 import *
import time

def select_threat(threat_list,asset_enterprise_list,threat_id_for_all_assets):
    for asset_type_index in range(len(asset_enterprise_list)):
        for i in range(len(asset_enterprise_list[asset_type_index])):
            threat_id_for_all_assets.append([])
    for threat in threat_list:
        for i in range(len(threat.threat_impact_asset)):
            if threat.threat_impact_asset[i] > 0:
                threat_id_for_all_assets[i].append(threat.primary_key)


def select_security_controls(security_control_list,threat_action_list,threat_action_name_to_id,risk_threat_action,asset_enterprise_list,threat_list,
                             threat_name_to_id,affordable_risk,budget,threat_action_id_to_name):
    ################################################################################## Global Variables ################################################################
    threat_action_name_list = []
    selected_security_controls = []
    threat_id_for_all_assets = []
    threat_action_id_list_for_all_assets = []
    affordable_budget = [200000, 200000]
    # affordable_risk = [2000000, 180000]
    ################################################################################## End Global Variables ################################################################
    for i in range(len(risk_threat_action)):
        for threat_action_specific_asset_list in risk_threat_action[i]:
            threat_action_name_list_specific_asset = []
            for threat_action_specific_asset in threat_action_specific_asset_list.keys():
                if threat_action_specific_asset_list[threat_action_specific_asset] > ProjectConfigFile.THREAT_PRIORITIZATION_THRESHOLD:
                    ta_index = 0
                    for ta in threat_action_name_list_specific_asset:
                        if ta[1] < threat_action_specific_asset_list[threat_action_specific_asset]:
                            break
                        ta_index += 1
                    threat_action_name_list_specific_asset.insert(ta_index,[threat_action_name_to_id[threat_action_specific_asset],threat_action_specific_asset_list[threat_action_specific_asset]])
            threat_action_name_list.append(threat_action_name_list_specific_asset)
    # Utitilities.printThreatActionNameListIter(threat_action_name_list)
    ######################################################################### Prune The Threat Action Name List Here ####################
    for threat_action_list_specific_asset_index in range(len(threat_action_name_list)):
        threat_action_name_list[threat_action_list_specific_asset_index] = threat_action_name_list[threat_action_list_specific_asset_index][0:ProjectConfigFile.CHOSEN_NUMBER_THREAT_ACTION]
    ######################################################################### End of Pruning The Threat Action Name List Here ###################
    # Utitilities.printThreatActionNameListIter(threat_action_name_list)

    for i in range(len(threat_action_name_list)):
        threat_action_id_list_for_all_assets.append([])
        for threat_action_id in threat_action_name_list[i]:
            threat_action_id_list_for_all_assets[i].append(threat_action_id[0])
    # print "Threat Action ID %s" % (threat_action_id_list_for_all_assets)

    asset_index = 0
    for asset_type_index in range(len(asset_enterprise_list)):
        for i in range(len(asset_enterprise_list[asset_type_index])):
            asset_name = asset_enterprise_list[asset_type_index][i][0]
            selected_security_controls_asset = []
            for threat_action in threat_action_name_list[asset_index]:
                for security_control in threat_action_list[threat_action[0]].applicable_security_controls:
                    if threat_action[1] < security_control_list[security_control].investment_cost:
                        continue
                    if security_control not in selected_security_controls_asset:
                        selected_security_controls_asset.append(security_control)
            selected_security_controls.append(selected_security_controls_asset)
            asset_index += 1
    # Utitilities.printSelectThreatActionName(threat_action_name_list,threat_action_list)
    # Utitilities.printSelectedSecurityControls(security_control_list,selected_security_controls)
    # TestCases.securityControlCoverage(security_control_list,selected_security_controls,threat_action_name_list)
    # startProcessing(security_control_list,selected_security_controls,threat_action_name_list,threat_action_list,asset_enterprise_list,risk_threat_action,threat_list,threat_name_to_id)
    ######################################################### STart of the test and alternative approach ###########################################

    ################################################################### Determine Cost Effectiveness #######################################################
    cost_effectiveness_sc = []
    Utitilities.determineCostEffectiveness(selected_security_controls, security_control_list, risk_threat_action,
                                           threat_action_id_list_for_all_assets, threat_action_id_to_name,
                                           cost_effectiveness_sc)
    ################################################################### End of Cost Effectiveness ##########################################################

    select_threat(threat_list, asset_enterprise_list,threat_id_for_all_assets)
    # Utitilities.printThreatIdForAllAssets(threat_id_for_all_assets,threat_list)
    return DistributedCDMOptimizationTestThresholdTactic.SMT_Environment(security_control_list, selected_security_controls, threat_action_name_list,
                                        threat_action_list, threat_action_id_list_for_all_assets,
                                        threat_id_for_all_assets, threat_list,
                                        asset_enterprise_list,affordable_risk,budget)






