import ProjectConfigFile,Utitilities
# import DistributedCDMOptimizationTestThresholdTactic,DistributedCDMOptimizationTestThresholdTacticIterative
import DistributedCDMOptimizationTestThresholdTacticIterativeCost,DistributedCDMOptimizationTestThresholdTacticBinarySearchCost
import DistributedCDMOptimizationTestThreshold_RiskList_TacticBinarySearchCost
import DistributedCDMOptimizationTestThresholdTacticIterativeCost_CostAllocation
import PreProcessingSMTModels
import BinarySearchCost_Constraints
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


def select_security_controls(security_control_list,threat_action_list,threat_action_name_to_id,risk_threat,risk_threat_action,asset_enterprise_list,threat_list,
                             threat_name_to_id,affordable_risk,budget,global_risk_threat_action,threat_action_id_to_name,risk_elimination,max_sec_control_threat_action_index):
    ################################################################################## Global Variables ################################################################
    threat_action_name_list = []
    selected_security_controls = []
    threat_id_for_all_assets = []
    threat_action_id_list_for_all_assets = []
    min_threat_action_consequence = []
    # print("Asset Enterprise List %s" % (asset_enterprise_list))
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

    ######################################################### Select Affordable Risk and Cost ######################################################################
    if ProjectConfigFile.SPLIT_ASSET == True:
        Utitilities.writeInFiles(risk_threat[0],asset_enterprise_list[0],selected_security_controls,security_control_list)

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

    # TestCases.securityControlCoverage(security_control_list,selected_security_controls,threat_action_name_list)
    # startProcessing(security_control_list,selected_security_controls,threat_action_name_list,threat_action_list,asset_enterprise_list,risk_threat_action,threat_list,threat_name_to_id)
    print "Number of Selected Security Controls %s" % (number_selected_security_controls)
    ProjectConfigFile.appendSelectedControls(number_selected_security_controls)
    # ProjectConfigFile.OUTPUT_FILE_NAME_ITERATIVE_COST_ALLOCATION_SEARCH.write(
    #     "Number of Selected Security Controls %s\n" % (number_selected_security_controls))
    ######################################################### STart of the test and alternative approach ###########################################
    select_threat(threat_list, asset_enterprise_list,threat_id_for_all_assets)
    # Utitilities.printThreatIdForAllAssets(threat_id_for_all_assets,threat_list)
    risk_ratio_threat_action = Utitilities.calculateRiskRatioBasedOnSelectedThreatAction(threat_action_id_list_for_all_assets,risk_threat_action,threat_action_id_to_name)

    ######################################### Classified Security Controls Based On Threat Action #######################################################################
    classified_selected_security_controls_threat_action = Utitilities.chosen_security_controls_threat_action_classified(len(selected_security_controls),threat_action_name_list,threat_action_list,security_control_list)
    # Utitilities.printClassifiedSecurityControl_ThreatAction(classified_selected_security_controls_threat_action,threat_action_id_to_name)
    ########################################## Classified Security Controls Based On Threat Action #######################################################################

    ######################################################################### Create Common Environment For All #############################################################################
    risk_list = []
    threat_action_id_to_position_roll = []
    threat_id_to_position_roll = []
    minimum_affordable_risk = []
    minimum_threat_specific_risk = []
    number_of_unique_asset = len(threat_action_id_list_for_all_assets)
    risk_asset_specific = [0.0 for i in range(number_of_unique_asset)]  ######Risk Value For All Assets
    global_risk_related_variable = {}

    #########################################  Create the environment for all the selected security controls ##############################
    security_control_cost_effectiveness = []
    for asset_index in range(len(selected_security_controls)):
        asset_specific_security_control_cost_effectiveness = {}
        for sec_control in selected_security_controls[asset_index]:
            security_control_list[sec_control].prepare_global_asset_threat_action_list(
                threat_action_id_list_for_all_assets)
            security_control_list[sec_control].prepare_cost_effectiveness_for_each_asset(risk_threat_action,threat_action_id_to_name)
            asset_specific_security_control_cost_effectiveness[sec_control] = security_control_list[sec_control].global_asset_effectiveness[asset_index]
        security_control_cost_effectiveness.append(asset_specific_security_control_cost_effectiveness)
    # Utitilities.printSelectedSecurityControls(security_control_list,selected_security_controls,security_control_cost_effectiveness)
    Utitilities.prune_security_controls_list(classified_selected_security_controls_threat_action,security_control_list,selected_security_controls,security_control_cost_effectiveness,max_sec_control_threat_action_index)
    # Utitilities.printSelectedSecurityControls(security_control_list, selected_security_controls,security_control_cost_effectiveness)

    env_variables = PreProcessingSMTModels.PreprocessingSMT_Environment(security_control_list,selected_security_controls,threat_action_name_list,threat_action_list,
                    threat_action_id_list_for_all_assets,threat_id_for_all_assets,threat_list,asset_enterprise_list,affordable_risk,budget,cost_effectiveness_sc,risk_ratio_threat_action,
                                 risk_list,risk_asset_specific,threat_action_id_to_position_roll,threat_id_to_position_roll,
                                 minimum_threat_specific_risk,minimum_affordable_risk,global_risk_related_variable)
    units_cost_distribution = Utitilities.printPrunedSelectedSecurityControlsWithProperties(security_control_list,selected_security_controls)
    # print("Cost Distribution %s" % (units_cost_distribution))
    global_sec_control_CDM_index_Asset_freq = []
    if len(env_variables)==0:
        return env_variables
    global_sec_control_CDM_index_Asset_freq = env_variables[1]
    sec_control_CDM_index = env_variables[2]
    # print("CDm Frequency %s" % (sec_control_CDM_index))
    all_constraints_properties = {}
    all_constraints_properties[ProjectConfigFile.COST_DISTRIBUTION_PROPERTIES] = units_cost_distribution[0]
    all_constraints_properties[ProjectConfigFile.ASSET_BASED_DISTRIBUTION_PROPERTIES] = units_cost_distribution[1]
    all_smt_constraints = Utitilities.build_constraints(asset_enterprise_list,selected_security_controls)
    # print "SMT Constraints %s" % (all_smt_constraints)
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
                                                                                                minimum_threat_specific_risk,minimum_affordable_risk,risk_elimination,max_sec_control_threat_action_index))

    # recommended_CDM_Different_Approach.append(
    #     BinarySearchCost_Constraints.SMT_Environment(security_control_list,selected_security_controls,global_sec_control_CDM_index_Asset_freq,sec_control_CDM_index,threat_action_name_list,
    #                                                                                   threat_action_list,threat_action_id_list_for_all_assets,threat_id_for_all_assets,
    #                                                                                   threat_list,asset_enterprise_list,affordable_risk, budget,cost_effectiveness_sc,
    #                                                                                   risk_ratio_threat_action,risk_list,
    #                                                                                   global_risk_related_variable[ProjectConfigFile.GLOBAL_TOTAL_COST_KEY],
    #                                                                                   global_risk_related_variable[ProjectConfigFile.GLOBAL_ESTIMATED_RISK_KEY],
    #                                                                                   global_risk_related_variable[ProjectConfigFile.GLOBAL_MIN_RISK_KEY],
    #                                                                                   risk_asset_specific,global_risk_related_variable[ProjectConfigFile.MIN_SEC_CONTROL_COST_KEY],
    #                                                                                   threat_action_id_to_position_roll,threat_id_to_position_roll,
    #                                                                                   minimum_threat_specific_risk,minimum_affordable_risk,risk_elimination,max_sec_control_threat_action_index,
    #                                                                                   all_smt_constraints,all_constraints_properties))



    # recommended_CDM_Different_Approach.append(
    #     DistributedCDMOptimizationTestThreshold_RiskList_TacticBinarySearchCost.SMT_Environment(security_control_list,selected_security_controls,threat_action_name_list,
    #                                                                                             threat_action_list,threat_action_id_list_for_all_assets,threat_id_for_all_assets,
    #                                                                                             threat_list,asset_enterprise_list,affordable_risk,budget,cost_effectiveness_sc,
    #                                                                                             risk_ratio_threat_action,risk_list,
    #                                                                                             global_risk_related_variable[ProjectConfigFile.GLOBAL_TOTAL_COST_KEY],
    #                                                                                             global_risk_related_variable[ProjectConfigFile.GLOBAL_ESTIMATED_RISK_KEY],
    #                                                                                             global_risk_related_variable[ProjectConfigFile.GLOBAL_MIN_RISK_KEY],
    #                                                                                             risk_asset_specific,global_risk_related_variable[ProjectConfigFile.MIN_SEC_CONTROL_COST_KEY],
    #                                                                                             threat_action_id_to_position_roll,threat_id_to_position_roll,
    #                                                                                             minimum_threat_specific_risk,minimum_affordable_risk,risk_elimination,max_sec_control_threat_action_index))

    recommended_CDM_Different_Approach.append(
        DistributedCDMOptimizationTestThresholdTacticIterativeCost.SMT_Environment(security_control_list,selected_security_controls,threat_action_name_list,
                                                                                   threat_action_list,threat_action_id_list_for_all_assets,threat_id_for_all_assets,
                                                                                   threat_list,asset_enterprise_list,affordable_risk,budget,cost_effectiveness_sc,risk_ratio_threat_action,
                                                                                   global_risk_related_variable[ProjectConfigFile.GLOBAL_TOTAL_COST_KEY],
                                                                                   global_risk_related_variable[ProjectConfigFile.GLOBAL_ESTIMATED_RISK_KEY],
                                                                                   global_risk_related_variable[ProjectConfigFile.GLOBAL_MIN_RISK_KEY],
                                                                                   risk_asset_specific,global_risk_related_variable[ProjectConfigFile.MIN_SEC_CONTROL_COST_KEY],
                                                                                   threat_action_id_to_position_roll,threat_id_to_position_roll,minimum_threat_specific_risk,
                                                                                   minimum_affordable_risk,risk_elimination,max_sec_control_threat_action_index))

    # # recommended_CDM_Different_Approach.append(
    # #     DistributedCDMOptimizationTestThresholdTacticIterativeCost_CostAllocation.SMT_Environment(security_control_list,
    # #                                                                                selected_security_controls,
    # #                                                                                threat_action_name_list,
    # #                                                                                threat_action_list,
    # #                                                                                threat_action_id_list_for_all_assets,
    # #                                                                                threat_id_for_all_assets,
    # #                                                                                threat_list, asset_enterprise_list,
    # #                                                                                affordable_risk, budget,
    # #                                                                                cost_effectiveness_sc,
    # #                                                                                risk_ratio_threat_action,
    # #                                                                                global_risk_related_variable[
    # #                                                                                    ProjectConfigFile.GLOBAL_TOTAL_COST_KEY],
    # #                                                                                global_risk_related_variable[
    # #                                                                                    ProjectConfigFile.GLOBAL_ESTIMATED_RISK_KEY],
    # #                                                                                global_risk_related_variable[
    # #                                                                                    ProjectConfigFile.GLOBAL_MIN_RISK_KEY],
    # #                                                                                risk_asset_specific,
    # #                                                                                global_risk_related_variable[
    # #                                                                                    ProjectConfigFile.MIN_SEC_CONTROL_COST_KEY],
    # #                                                                                threat_action_id_to_position_roll,
    # #                                                                                threat_id_to_position_roll,
    # #                                                                                minimum_threat_specific_risk,
    # #                                                                                minimum_affordable_risk))
    # # ProjectConfigFile.OUTPUT_FILE_NAME_ITERATIVE_COST_ALLOCATION_SEARCH.close()
    return recommended_CDM_Different_Approach




