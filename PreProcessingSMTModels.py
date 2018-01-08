import ProjectConfigFile
def PreprocessingSMT_Environment(security_control_list,selected_security_controls,threat_action_name_list,threat_action_list,
                    threat_action_id_list_for_all_assets,threat_id_for_all_assets,threat_list,asset_enterprise_list,affordable_risk,budget,cost_effectiveness_sc,risk_ratio_threat_action,
                                 risk_list,risk_asset_specific,threat_action_id_to_position_roll,threat_id_to_position_roll,
                                 minimum_threat_specific_risk,minimum_affordable_risk,global_risk_related_variable):

    number_of_unique_asset = len(threat_action_id_list_for_all_assets)
    # print "Enterprise Given Asset List %s \nEnterprise Given Asset List Length: %s" % (
    # asset_enterprise_list, number_of_unique_asset)
    # print "Asset Selected Threat Action Specific Risk Ratio %s" % (risk_ratio_threat_action)

    #########################################  Create the environment for all the selected security controls ##############################
    for asset_index in range(len(selected_security_controls)):
        for sec_control in selected_security_controls[asset_index]:
            security_control_list[sec_control].prepare_global_asset_threat_action_list(
                threat_action_id_list_for_all_assets)

    # print "############################################ Security Controls Properties ########################################################"
    # for asset_index in range(len(selected_security_controls)):
    #     for sec_control in selected_security_controls[asset_index]:
    #         security_control_list[sec_control].printGlobalAssetThreatActionProperties()

    ########################################## Create the environment for all the threat action #############################################

    for asset_index in range(len(threat_action_id_list_for_all_assets)):
        for threat_action in threat_action_id_list_for_all_assets[asset_index]:
            threat_action_list[threat_action].prepare_global_asset_applicable_security_controls(
                selected_security_controls)

    # print "############################################ Threat Action Properties ########################################################"
    # for asset_index in range(len(threat_action_id_list_for_all_assets)):
    #     for threat_action in threat_action_id_list_for_all_assets[asset_index]:
    #         threat_action_list[threat_action].printGlobalAssetThreatActionProperties()

    ################################################## Create the environment for threat properties ####################################
    for asset_index in range(len(threat_id_for_all_assets)):
        for threat in threat_id_for_all_assets[asset_index]:
            threat_list[threat].globalCreateAssetThreatAction(threat_action_id_list_for_all_assets,
                                                              asset_enterprise_list, threat_action_list)

    for threat in threat_list:
        threat.considerResidualThreatAction()

    # print "########################################## Threat Properties ########################################################"
    # for threat in threat_list:
    #         threat.printGlobalProperties()

    ############################################################ Give rank to threat action ##########################################
    # threat_action_id_to_position_roll = []
    for asset_index in range(len(threat_id_for_all_assets)):
        threat_action_id_to_position_roll.append({})
        num_threat_action = 0
        for threat_action_id in threat_action_id_list_for_all_assets[asset_index]:
            threat_action_id_to_position_roll[asset_index][threat_action_id] = num_threat_action
            num_threat_action += 1
    # print threat_action_id_to_position_roll

    ############################################################ Give rank to threat ##########################################
    # threat_id_to_position_roll = []
    for asset_index in range(len(threat_id_for_all_assets)):
        threat_id_to_position_roll.append({})
        num_threat_action = 0
        for threat_id in threat_id_for_all_assets[asset_index]:
            threat_id_to_position_roll[asset_index][threat_id] = num_threat_action
            num_threat_action += 1
    # print threat_id_to_position_roll

    ####################################################### Determine the minimum value of the Affordable Risk ##################
    global_estimated_risk = 0
    for threat in threat_list:
        for asset_index in range(len(threat.maximum_risk)):
            global_estimated_risk += threat.maximum_risk[asset_index]
            risk_asset_specific[asset_index] += threat.maximum_risk[asset_index]
    print "Global Estimated Risk %s" % (global_estimated_risk)
    # print "Asset Specific Estimated Risk %s \n \t ------> Where Total Risk %s" % (
    # risk_asset_specific, sum(risk_asset_specific))
    for asset_index in range(number_of_unique_asset):
        risk_asset_specific[asset_index] /= global_estimated_risk
        # alloted_cost_asset_specific[asset_index] = budget * risk_asset_specific[asset_index]
    # print "Asset Specific Estimated Risk Proportion %s" % (risk_asset_specific)
    # print "Asset Specific Alloted Cost Proportion %s" % (alloted_cost_asset_specific)

    # print "################################################################# ALl the Problem Specific List #################################################"
    # print "Candidate Selected Threat Action %s" % (threat_action_id_list_for_all_assets)
    # print "Candidate Threat Action Roll %s" % (threat_action_id_to_position_roll)
    # print "Candidate Selected Security Controls %s" % (selected_security_controls)
    # print "Candidate Selected Threat %s" % (threat_id_for_all_assets)
    # print "Candidate Threat Roll %s" % (threat_id_to_position_roll)
    # print "Candiadet Security Control Set Cost Effectiveness %s" % (cost_effectiveness_sc)

    ###################################################### Design All Heuristics Here ############################################
    ###################################################### 1.1 Minimum Affordable Risk ###########################################

    # minimum_affordable_risk = []
    # minimum_threat_specific_risk = []
    # print "******************************** Minimum Affordable Risk *************************************************"
    asset_index = 0
    for i in range(len(asset_enterprise_list)):
        for j in range(len(asset_enterprise_list[i])):
            minimum_affordable_risk.append(0.0)
            minimum_threat_specific_risk.append([1 for threat in threat_id_for_all_assets[asset_index]])
            threat_action_survive = [1.0 for i in threat_action_id_list_for_all_assets[asset_index]]
            for sec_id in selected_security_controls[asset_index]:
                for threat_action_id in security_control_list[sec_id].global_asset_threat_action_list[asset_index]:
                    threat_action_survive[threat_action_id_to_position_roll[asset_index][threat_action_id]] *= (1
                                                                                                                -
                                                                                                                security_control_list[
                                                                                                                    sec_id].threat_action_effectiveness[
                                                                                                                    threat_action_id])
            for threat_id in threat_id_for_all_assets[asset_index]:
                # print "Threat ID %s : Ignored %s" % (threat_list[threat_id].primary_key,threat_list[threat_id].ignored_threat_action[asset_index])
                # print "Threat Action %s" % (threat_list[threat_id].global_asset_threat_action[asset_index])
                # print "Threat Action Prob %s" % (threat_list[threat_id].global_asset_threat_action_prob[asset_index])
                # print "Threat Action Position %s" % (threat_list[threat_id].global_threat_action_id_to_place_map[asset_index])
                # print "Threat Action Index %s" % (threat_action_id_list_for_all_assets[asset_index])
                # print "Threat Action ID to Position %s" % (threat_action_id_to_position_roll[asset_index])
                threat_index = threat_id_to_position_roll[asset_index][threat_id]
                minimum_threat_specific_risk[asset_index][threat_index] = 1 - \
                                                                          threat_list[threat_id].ignored_threat_action[
                                                                              asset_index]
                if len(threat_list[threat_id].global_asset_threat_action[asset_index]) == 0:
                    pass
                    # print "No Threat Action in %s by %s Ignored: %s" %(asset_index,threat_list[threat_id].threat_name,1-minimum_threat_specific_risk[asset_index][threat_index])
                for threat_action_id in threat_list[threat_id].global_asset_threat_action[asset_index]:
                    minimum_threat_specific_risk[asset_index][threat_index] \
                        *= (
                    1 - threat_action_survive[threat_action_id_to_position_roll[asset_index][threat_action_id]] *
                    threat_list[threat_id].global_asset_threat_action_prob[asset_index][
                        threat_list[threat_id].global_threat_action_id_to_place_map[asset_index][threat_action_id]])
                minimum_threat_specific_risk[asset_index][threat_index] = (
                                                                          1 - minimum_threat_specific_risk[asset_index][
                                                                              threat_index]) * \
                                                                          threat_list[threat_id].threat_effect[
                                                                              asset_index]
            minimum_affordable_risk[asset_index] = sum(minimum_threat_specific_risk[asset_index])
            asset_index += 1
    global_min_risk = sum(minimum_affordable_risk)

    # ######################################################### Print the Minimum Affordable Risk ##################################
    # print "\nMininum Risk for Selected Security Controls Candidate Set"
    # for i in range(number_of_unique_asset):
    #     print "\t Asset Index : %s -------- Minimum Risk : %s Maximum Risk Proportion Risk %s" % (i,minimum_affordable_risk[i],affordable_risk * float(risk_asset_specific[i]))
    # ######################################################### End of Print the Minimum Affordable Risk ##################################

    print "Global Minimum Risk %s" % (global_min_risk)
    if global_min_risk > affordable_risk:
        max_risk_initial = 0
        for i in range(len(threat_id_for_all_assets)):
            for threat_id in threat_id_for_all_assets[i]:
                max_risk_initial += threat_list[threat_id].maximum_risk[i]
        # recommended_CDM = []
        # recommended_CDM.insert(ProjectConfigFile.CYBERARM_CDM_MATRIX, [])
        # recommended_CDM.insert(ProjectConfigFile.CYBERARM_RISK, [])
        # recommended_CDM.insert(ProjectConfigFile.CYBERARM_ROI, max_risk_initial)
        # return recommended_CDM
        return []


    # print "Asset List for SMT %s" % (asset_list_for_smt)
    ################################################# Min Security Control Cost #############################################################
    min_sec_control_cost = -1
    max_sec_control_cost = -1
    global_Total_Cost = 0.0
    for i in range(len(selected_security_controls)):
        for sec_control in selected_security_controls[i]:
            if security_control_list[sec_control].investment_cost > max_sec_control_cost:
                max_sec_control_cost = security_control_list[sec_control].investment_cost
            if min_sec_control_cost < 0:
                min_sec_control_cost = security_control_list[sec_control].investment_cost
            if security_control_list[sec_control].investment_cost < min_sec_control_cost:
                min_sec_control_cost = security_control_list[sec_control].investment_cost
            global_Total_Cost += security_control_list[sec_control].investment_cost
    max_security_control_number = int(budget / min_sec_control_cost)
    highest_risk_mitigation = global_estimated_risk - global_min_risk
    if budget >= global_Total_Cost:
        probable_risk_threshold = global_min_risk
    else:
        probable_risk_threshold = global_estimated_risk - (highest_risk_mitigation * budget / global_Total_Cost)
    print "Global Total Cost %s" % (global_Total_Cost)
    print "Budget %s" % (budget)
    print "Global Risk Threshold %s" % (probable_risk_threshold)
    print "Global Minimum Risk %s" % (global_min_risk)
    ################################################# Append All The Risks ##########################################################################
    # risk_list.append(global_estimated_risk)
    risk_list.append(affordable_risk)
    risk_list.append(probable_risk_threshold)
    if probable_risk_threshold > global_min_risk:
        risk_list.append(global_min_risk)
    # print "Before Sort: Risk List : %s" % (risk_list)
    # risk_list.sort()
    print "After Sort: Risk List : %s" % (risk_list)
    ################################################# Max Security Control Cost #############################################################

    ###################################################### End of Design of All Heuristics Here ############################################

    ################################################## Send The Global Risk Related Variables #################################################
    global_risk_related_variable[ProjectConfigFile.GLOBAL_ESTIMATED_RISK_KEY] = global_estimated_risk
    global_risk_related_variable[ProjectConfigFile.GLOBAL_TOTAL_COST_KEY] = global_Total_Cost
    global_risk_related_variable[ProjectConfigFile.GLOBAL_MIN_RISK_KEY] = global_min_risk
    global_risk_related_variable[ProjectConfigFile.MIN_SEC_CONTROL_COST_KEY] = min_sec_control_cost