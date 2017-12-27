import ProjectConfigFile,Utitilities
# import DistributedCDMOptimizationTestThresholdTactic,DistributedCDMOptimizationTestThresholdTacticIterative
import DistributedCDMOptimizationTestThresholdTacticIterativeCost,DistributedCDMOptimizationTestThresholdTacticBinarySearchCost
import DistributedCDMOptimizationTestThreshold_RiskList_TacticBinarySearchCost
import PreProcessingSMTModels

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
                             threat_name_to_id,affordable_risk,budget,global_risk_threat_action,threat_action_id_to_name):
    ################################################################################## Global Variables ################################################################
    threat_action_name_list = []
    selected_security_controls = []
    threat_id_for_all_assets = []
    threat_action_id_list_for_all_assets = []
    min_threat_action_consequence = []

    for i in range(len(asset_enterprise_list)):
        for j in range(len(asset_enterprise_list[i])):
            threat_action_name_list.append([])
            min_threat_action_consequence.append(global_risk_threat_action[0][0]) # Put the maximum threat action value

    # print "Global Risk Threat Action %s" % (global_risk_threat_action)
    for threat_action_row in global_risk_threat_action:
        threat_action_name_list[threat_action_row[1]].append([threat_action_name_to_id[threat_action_row[2]],threat_action_row[0]])
    # Utitilities.printThreatActionNameListIter(threat_action_name_list)

    for i in range(len(threat_action_name_list)):
        threat_action_id_list_for_all_assets.append([])
        for threat_action_id in threat_action_name_list[i]:
            threat_action_id_list_for_all_assets[i].append(threat_action_id[0])
            if threat_action_id[1] < min_threat_action_consequence[i]:
                min_threat_action_consequence[i] = threat_action_id[1]
    # print "Threat Action ID %s" % (threat_action_id_list_for_all_assets)
    # print "Min Threat Action Value %s" % (min_threat_action_consequence)

    asset_index = 0
    number_selected_security_controls = 0
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
            number_selected_security_controls += len(selected_security_controls_asset)
            asset_index += 1

    ################################################################## Selection of all the threat actions of the candidate set of security controls #########################################
    # print "Before Threat Coverage:"
    # Utitilities.printThreatActionList(threat_action_id_list_for_all_assets)
    asset_index = 0
    for i in range(len(risk_threat_action)):
        for j in range(len(risk_threat_action[i])):
            # print "Asset Index %s Selected Security Controls %s" % (asset_index,selected_security_controls[asset_index])
            for security_control_id in selected_security_controls[asset_index]:
                # print "Security Control ID %s \n\t Threat Action Enforcement %s" % (security_control_id,security_control_list[security_control_id].threat_action)
                for threat_action_id in security_control_list[security_control_id].threat_action:
                    if threat_action_id not in threat_action_id_list_for_all_assets[asset_index]:
                        if threat_action_id_to_name[threat_action_id] not in risk_threat_action[i][j].keys():
                            continue
                        if risk_threat_action[i][j][threat_action_id_to_name[threat_action_id]] >= min_threat_action_consequence[asset_index]/float(ProjectConfigFile.THREAT_ACTION_MINIMUM_CONSEQUENCE):
                            threat_action_id_list_for_all_assets[asset_index].append(threat_action_id)
            asset_index += 1
    # print "After Threat Coverage"
    # Utitilities.printThreatActionList(threat_action_id_list_for_all_assets)
    ################################################################## End of Selection of all the threat actions of the candidate set of security controls #########################################

    ################################################################### Determine Cost Effectiveness #######################################################
    cost_effectiveness_sc = []
    Utitilities.determineCostEffectiveness(selected_security_controls,security_control_list,risk_threat_action,threat_action_id_list_for_all_assets,
                                           threat_action_id_to_name,cost_effectiveness_sc)
    ################################################################### End of Cost Effectiveness ##########################################################

    # Utitilities.printSelectThreatActionName(threat_action_name_list,threat_action_list)
    # Utitilities.printSelectedSecurityControls(security_control_list,selected_security_controls)
    # TestCases.securityControlCoverage(security_control_list,selected_security_controls,threat_action_name_list)
    # startProcessing(security_control_list,selected_security_controls,threat_action_name_list,threat_action_list,asset_enterprise_list,risk_threat_action,threat_list,threat_name_to_id)
    print "Number of Selected Security Controls %s" % (number_selected_security_controls)
    ProjectConfigFile.OUTPUT_FILE_NAME.write("Number of Selected Security Controls %s\n" % (number_selected_security_controls))
    ######################################################### STart of the test and alternative approach ###########################################
    select_threat(threat_list, asset_enterprise_list,threat_id_for_all_assets)
    # Utitilities.printThreatIdForAllAssets(threat_id_for_all_assets,threat_list)
    risk_ratio_threat_action = Utitilities.calculateRiskRatioBasedOnSelectedThreatAction(threat_action_id_list_for_all_assets,risk_threat_action,threat_action_id_to_name)

    ######################################################################### Create Common Environment For All #############################################################################
    risk_list = []
    threat_action_id_to_position_roll = []
    threat_id_to_position_roll = []
    minimum_affordable_risk = []
    minimum_threat_specific_risk = []
    number_of_unique_asset = len(threat_action_id_list_for_all_assets)
    risk_asset_specific = [0.0 for i in range(number_of_unique_asset)]  ######Risk Value For All Assets
    global_risk_related_variable = {}
    PreProcessingSMTModels.PreprocessingSMT_Environment(security_control_list,selected_security_controls,threat_action_name_list,threat_action_list,
                    threat_action_id_list_for_all_assets,threat_id_for_all_assets,threat_list,asset_enterprise_list,affordable_risk,budget,cost_effectiveness_sc,risk_ratio_threat_action,
                                 risk_list,risk_asset_specific,threat_action_id_to_position_roll,threat_id_to_position_roll,
                                 minimum_threat_specific_risk,minimum_affordable_risk,global_risk_related_variable)
    ######################################################################### End of Creating Common Environment For All #############################################################################

    recommended_CDM_Different_Approach = []
    recommended_CDM_Different_Approach.append(DistributedCDMOptimizationTestThresholdTacticBinarySearchCost.SMT_Environment(security_control_list,selected_security_controls,threat_action_name_list,
                                                                                                threat_action_list,threat_action_id_list_for_all_assets,threat_id_for_all_assets,
                                                                                                threat_list,asset_enterprise_list,affordable_risk,budget,cost_effectiveness_sc,
                                                                                                risk_ratio_threat_action,risk_list,
                                                                                                global_risk_related_variable[ProjectConfigFile.GLOBAL_TOTAL_COST_KEY],
                                                                                                global_risk_related_variable[ProjectConfigFile.GLOBAL_ESTIMATED_RISK_KEY],
                                                                                                global_risk_related_variable[ProjectConfigFile.GLOBAL_MIN_RISK_KEY],
                                                                                                risk_asset_specific,global_risk_related_variable[ProjectConfigFile.MIN_SEC_CONTROL_COST_KEY],
                                                                                                threat_action_id_to_position_roll,threat_id_to_position_roll,
                                                                                                minimum_threat_specific_risk,minimum_affordable_risk))
    recommended_CDM_Different_Approach.append(
        DistributedCDMOptimizationTestThreshold_RiskList_TacticBinarySearchCost.SMT_Environment(security_control_list,selected_security_controls,threat_action_name_list,
                                                                                                threat_action_list,threat_action_id_list_for_all_assets,threat_id_for_all_assets,
                                                                                                threat_list,asset_enterprise_list,affordable_risk,budget,cost_effectiveness_sc,
                                                                                                risk_ratio_threat_action,risk_list,
                                                                                                global_risk_related_variable[ProjectConfigFile.GLOBAL_TOTAL_COST_KEY],
                                                                                                global_risk_related_variable[ProjectConfigFile.GLOBAL_ESTIMATED_RISK_KEY],
                                                                                                global_risk_related_variable[ProjectConfigFile.GLOBAL_MIN_RISK_KEY],
                                                                                                risk_asset_specific,global_risk_related_variable[ProjectConfigFile.MIN_SEC_CONTROL_COST_KEY],
                                                                                                threat_action_id_to_position_roll,threat_id_to_position_roll,
                                                                                                minimum_threat_specific_risk,minimum_affordable_risk))
    ProjectConfigFile.OUTPUT_FILE_NAME.close()
    return recommended_CDM_Different_Approach




