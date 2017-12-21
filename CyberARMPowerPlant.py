import ThreatStatisticsSingle,ThreatPrioritization,Utitilities,ProjectConfigFile, ThreatPrioritizationExperience
import ThreatActionToSecurityControl,CyberARMEngine,CyberARMEngineDistribution

# write_output_file = open("CyberARMOutput",'w')
threat_threatAction_asset_veris = {}
asset_name_list = []
threat_threat_action_possible_pair = {}
prob_threat_action_threat = {}
prob_threat_threat_action = {}
prob_threat = {}
security_control_list = []
security_control_version_to_id = {}

###################### These variable are introduced in this file for convenience though it may be different in the web application###################################
send_data = {}

def init_power_plant(asset_enterprise_list,enterprise_asset_list_given):
    asset_index = 0
    for i in range(len(asset_enterprise_list)):
        for asset in asset_enterprise_list[i]:
            asset_name = asset[0]
            if asset_name not in enterprise_asset_list_given:
                enterprise_asset_list_given.append(asset_name)
            asset_index += 1
    return asset_index
    # ProjectConfigFile.init_conf()

def cyberarm_init_main(asset_enterprise_list_input,affordable_risk,budget,risk_elimination):
    print "The Power Plant has started :: Affordable Risk --> %s Budget --> %s" % (affordable_risk,budget)
    asset_enterprise_list = asset_enterprise_list_input
    ###################################################################################### GLobal Variables ############################################################
    threat_threatAction_asset = []
    prob_threat_threat_action_alternative = {}
    risk_threat = [[] for i in range(2)]
    risk_threat_action = [[] for i in range(2)]
    threat_action_list = []
    threat_action_name_to_id = {}
    threat_action_id_to_name = {}
    threat_list = []
    threat_name_to_id = {}
    prob_threat_action_threat_experience = {}
    prob_threat_threat_action_experience = {}
    prob_threat_experience = {}
    ###################################################################################### End GLobal Variables ############################################################

    ###################################################################################### Inputs #######################################################################
    enterprise_asset_list_given = []
    ##################################################################################### End of Inputs #################################################################
    # Utitilities.printAssetList(asset_enterprise_list)
    number_of_asset = init_power_plant(asset_enterprise_list,enterprise_asset_list_given)
    # ThreatStatisticsSingle.find_threat_statistics_all(threat_threatAction_asset_veris,asset_name_list,threat_threat_action_possible_pair)
    # print "Asset Enterprise List %s" % (enterprise_asset_list_given)
    # print "Threat Threat Action Asset Veris %s" % (threat_threatAction_asset_veris)
    # print "Asset List %s" % (asset_name_list)
    # print "Threat Threat Action Possible Pair %s" % (threat_threat_action_possible_pair)

    ######### ***************************************** Check the number of prioritized Threat Actions ****************************##############################################
    from RiskThreatActionDistribution import generate_risk_distribution,printGlobalRiskThreatAction
    threat_actions_frequency = -1
    global_risk_threat_action = []
    threat_actions_frequency = generate_risk_distribution(risk_elimination,send_data['global_risk_threat_action'])
    print "Frequency Threat Actions %s" % (threat_actions_frequency)
    global_risk_threat_action = send_data['global_risk_threat_action'][0:threat_actions_frequency]
    # printGlobalRiskThreatAction(global_risk_threat_action)
    ######### ***************************************** end of Check the number of prioritized Threat Actions ****************************##############################################

    threat_threatAction_asset.append(threat_threatAction_asset_veris)
    # Utitilities.printNumberStatisticsThreatThreatAction(threat_threatAction_asset)
    # print "Asset Statistics %s" % (threat_threatAction_asset[0])
    # print "asset list %s" % (asset_name_list)
    # print "Threat Threat Action Possible Pair %s" % (threat_threat_action_possible_pair)

    ################################ Threat Prioritization ####################################################################
    ThreatPrioritization.threat_prioritization_main(prob_threat,prob_threat_threat_action,prob_threat_threat_action_alternative,prob_threat_action_threat,risk_threat_action[ProjectConfigFile.VERIS_LIST],risk_threat[ProjectConfigFile.VERIS_LIST],threat_threatAction_asset[0],asset_enterprise_list[ProjectConfigFile.VERIS_LIST])
    # print "Threat Statistics %s" % (prob_threat_action_threat)

    ######################################## This is the experience part #######################################################
    ThreatPrioritizationExperience.threat_prioritization_main(prob_threat_experience,prob_threat_threat_action_experience,prob_threat_action_threat_experience,risk_threat_action[ProjectConfigFile.EXPERIENCE_LIST],risk_threat[ProjectConfigFile.EXPERIENCE_LIST],asset_enterprise_list[ProjectConfigFile.EXPERIENCE_LIST])
    # print "Threat Experience %s" % (prob_threat_experience)
    # print "Threat Action given Threat Experience %s" % (prob_threat_action_threat_experience)
    # print "Threat given Threat Action Experience %s" % (prob_threat_threat_action_experience)
    for asset_type in range(len(risk_threat)):
        for i in range(len(risk_threat[asset_type])):
            print " Risk of Asset (Type,Index) (%s,%s) :: %s" % (asset_type,i,risk_threat[asset_type][i])
    # print "Risk Threat Action %s" % (risk_threat_action[1])
    # Utitilities.printAssetProbThreatActionVeris(prob_threat,prob_threat_threat_action,prob_threat_action_threat,enterprise_asset_list_given)
    # Utitilities.printAssetProbThreatActionExperience(prob_threat_experience,prob_threat_threat_action_experience,prob_threat_action_threat_experience,enterprise_asset_list_given)

    ######################################################### Check the output ##############################################################################
    # Utitilities.printAllStatistics(prob_threat,threat_threatAction_asset[0],prob_threat_action_threat,threat_threat_action_possible_pair)
    # Utitilities.printAllStatisticsGivenAssets(prob_threat, threat_threatAction_asset, prob_threat_action_threat,threat_threat_action_possible_pair,enterprise_asset_list_given)
    # Utitilities.printNumberStatisticsThreatThreatActionWithProb(prob_threat,threat_threatAction_asset,prob_threat_action_threat)
    # Utitilities.printThreatThreatActionStatistics(threat_threatAction_asset[0],prob_threat_threat_action)
    # Utitilities.printThreatImpact()
    # Utitilities.printRiskThreatThreatAction(risk_threat_action,risk_threat,enterprise_asset_list_given)
    # Utitilities.printKillChainPhases(enterprise_asset_list_given)
    # Utitilities.printThreatAction(risk_threat,risk_threat_action,prob_threat_experience,prob_threat_action_threat_experience)
    # Utitilities.printRiskThreatAction(risk_threat_action,asset_enterprise_list)

    ########################################################## List of Security Controls, Threat Action and Mappings ##########################################
    ThreatActionToSecurityControl.parseAllScAndTAFiles(security_control_list,security_control_version_to_id,prob_threat_action_threat,prob_threat_action_threat_experience,
                                                       threat_action_list,threat_action_name_to_id,risk_threat,threat_list,
                                                       threat_name_to_id,enterprise_asset_list_given,threat_action_id_to_name,number_of_asset,asset_enterprise_list)
    # print "Threat Action ID to Name %s" % (threat_action_id_to_name)
    # Utitilities.printThreatActionNameToId(threat_action_name_to_id)
    # Utitilities.printSecurityControls(security_control_list,security_control_version_to_id)
    # Utitilities.printThreatActionList(threat_action_list,threat_action_name_to_id)
    # Utitilities.printThreatProperties(threat_list)
    # Utitilities.printSecurityControlThreatmapping(security_control_list,security_control_version_to_id,threat_action_list)
    # Utitilities.printThreatSecurityControlMapping(threat_action_list,threat_action_name_to_id,security_control_list,risk_threat_action,enterprise_asset_list_given)
    recommendedCDM = []
    # affordable_risk = 900000
    if threat_actions_frequency == -1:
        recommendedCDM = CyberARMEngine.select_security_controls(security_control_list,threat_action_list,threat_action_name_to_id,risk_threat_action,
                                                                 asset_enterprise_list,threat_list,threat_name_to_id,float(affordable_risk),float(budget),threat_action_id_to_name)
    # write_output_file.close()
    else:
        recommendedCDM = CyberARMEngineDistribution.select_security_controls(security_control_list, threat_action_list,
                                                                 threat_action_name_to_id, risk_threat_action,
                                                                 asset_enterprise_list, threat_list, threat_name_to_id,
                                                                 float(affordable_risk), float(budget),global_risk_threat_action,threat_action_id_to_name)
    for iter_index in range(len(recommendedCDM)):
        print "ROI %s" % (recommendedCDM[iter_index][2])
    # if len(recommendedCDM[ProjectConfigFile.CYBERARM_CDM_MATRIX]) == 0:
    #     roi_row = {}
    #     roi_row[ProjectConfigFile.MITIGATED_RISK] = 0
    #     roi_row[ProjectConfigFile.ROI] = 0
    #     roi_row[ProjectConfigFile.IMPOSED_RISK] = round(recommendedCDM[ProjectConfigFile.CYBERARM_ROI],3)
    #     roi_row[ProjectConfigFile.RESIDUAL_RISK] = roi_row[ProjectConfigFile.IMPOSED_RISK]
    #     roi_row[ProjectConfigFile.TOTAL_IMPLEMENTATION_COST] = 0
    #     recommendedCDM.insert(ProjectConfigFile.CYBERARM_ROI, roi_row)
    return recommendedCDM