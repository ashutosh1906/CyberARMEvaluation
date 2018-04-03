import ProjectConfigFile
from math import sqrt,pow

def determineCostEffectiveness(selected_security_controls,security_control_list,risk_threat_action,threat_action_id_list_for_all_assets,
                               threat_action_id_to_name,cost_effectiveness_sc):
    asset_index = 0
    # print threat_action_id_list_for_all_assets
    for asset_type in range(len(risk_threat_action)):
        for index in range(len(risk_threat_action[asset_type])):
            # print "Asset Index %s" % (asset_index)
            # print "Risk Threat Action %s" % (risk_threat_action[asset_type][index])
            cost_effectiveness_sc.append(0.0)
            asset_specific_sc_cost = 0.0
            for security_control_id in selected_security_controls[asset_index]:
                for threat_action_id in security_control_list[security_control_id].threat_action:
                    if threat_action_id in threat_action_id_list_for_all_assets[asset_index]:
                        cost_effectiveness_sc[asset_index] += security_control_list[security_control_id].threat_action_effectiveness[threat_action_id]\
                                         *risk_threat_action[asset_type][index][threat_action_id_to_name[threat_action_id]]
                asset_specific_sc_cost += security_control_list[security_control_id].investment_cost
            if asset_specific_sc_cost <> 0:
                cost_effectiveness_sc[asset_index] /= asset_specific_sc_cost
            else:
                cost_effectiveness_sc[asset_index] = 0.0
            asset_index += 1
    # printSecurityControlsEnforcementEffectiveness(selected_security_controls, security_control_list, threat_action_id_list_for_all_assets,
    #                       threat_action_id_to_name,risk_threat_action)
    # printCostEffectiveness(cost_effectiveness_sc)

def printSecurityControlsEnforcementEffectiveness(selected_security_controls,security_control_list,threat_action_id_list_for_all_assets,threat_action_id_to_name,risk_threat_action):
    print "********** Security Control Against The Selected Threat Actions************************"
    asset_index = 0
    for asset_type in range(len(risk_threat_action)):
        for index in range(len(risk_threat_action[asset_type])):
            print "\t Asset Index --> %s" % (asset_index)
            for security_control_id in selected_security_controls[asset_index]:
                print "\t\t Sc ID: %s Cost: %s" % (security_control_id,security_control_list[security_control_id].investment_cost)
                for threat_action_id in security_control_list[security_control_id].threat_action:
                    if threat_action_id in threat_action_id_list_for_all_assets[asset_index]:
                        print "\t\t\t TA ID: %s Name: %s Effect: %s Risk: %s" % (threat_action_id,threat_action_id_to_name[threat_action_id],
                                                                 security_control_list[security_control_id].threat_action_effectiveness[threat_action_id],
                                                                                 risk_threat_action[asset_type][index][threat_action_id_to_name[threat_action_id]])
            asset_index += 1

def printCostEffectiveness(cost_effectiveness_sc):
    print "****************Cost Effectiveness*************************************"
    for i in range(len(cost_effectiveness_sc)):
        print "\t\t Asset Index: %s Effectiveness: %s" %(i,cost_effectiveness_sc[i])

def printThreat(threat_list,threat_name_to_id):
    for threat in threat_list:
        print "ID : %s ---> Name : (%s,%s)" % (threat.primary_key,threat.threat_name,threat_name_to_id[threat.threat_name])
        for asset_value in threat.threat_impact_asset:
            print "                 --------> %s" % (asset_value)

def printThreatObject(threat_list,threat_id_for_specific_assets,asset_index):
    print "Asset Index : %s" % (asset_index)
    for threat in threat_id_for_specific_assets:
        threat_list[threat].printProperties()

def printSecurityControlObject(selected_security_controls,security_control_list):
    for sec_id in selected_security_controls:
        security_control_list[sec_id].printProperties()

def printThreatActionObject(threat_action_list,threat_action_id_list_for_specific_assets,asset_name):
    print "******************************************************************* Threat Action ******************************************************************************************"
    for threat_action_id in threat_action_id_list_for_specific_assets:
        threat_action_list[threat_action_id].printProperties(asset_name)

def printSecurityControls(security_control_list,security_control_version_to_id):
    print "***************************** Security Controls ********************************"
    for sec_con in security_control_list:
        print "Primary Key : %s" % (sec_con.primary_key)
        print "Name : %s ## Version : %s"%(sec_con.sc_name,sec_con.sc_version)
        print "%s %s %s" % (sec_con.kc_phase,sec_con.en_level,sec_con.sc_function)
        print " Version : %s to ID ---> %s\n" % (sec_con.sc_version,security_control_version_to_id[sec_con.sc_version])
        print "Threat Action Effectiveness %s" % (sec_con.threat_action_effectiveness)

def printThreatActionList(threat_action_list,threat_action_name_to_id):
    for threat_action in threat_action_list:
        print "Name %s ---------> " % (threat_action.threat_action_name)
        print "Id %s : "%(threat_action.primary_key)
        print "Name: %s to ID : %s" % (threat_action.threat_action_name,threat_action_name_to_id[threat_action.threat_action_name])
        print "Prob given threat against asset "
        for asset in threat_action.prob_given_threat_asset.keys():
            print "  Asset : %s" % (asset)
            print "    Threats : %s\n" % (threat_action.prob_given_threat_asset[asset])

def printKillChainPhases(enterprise_asset_list_given):
    print "All Dimension Description"
    print "Kill Chain Phase ---->"
    print ProjectConfigFile.KILL_CHAIN_PHASE_LIST
    print ProjectConfigFile.KILL_CHAIN_PHASE_TO_ID
    print ProjectConfigFile.ID_TO_KILL_CHAIN_PHASE

    print "Enforcement Level ---->"
    print ProjectConfigFile.ENFORCEMENT_LEVEL_LIST
    print ProjectConfigFile.ENFORCEMENT_LEVEL_TO_ID
    print ProjectConfigFile.ID_TO_ENFORCEMENT_LEVEL

    print "Security Function ---->"
    print ProjectConfigFile.SECURITY_FUNCTION_LIST
    print ProjectConfigFile.SECURITY_FUNCTION_TO_ID
    print ProjectConfigFile.ID_TO_SECURITY_FUNCTION

    print "Asset Unique List ---->"
    print enterprise_asset_list_given

def printRiskThreatThreatAction(risk_threat_action,risk_threat,enterprise_asset_list_given):
    asset_index = 0
    for i in range(len(risk_threat)):
        for j in range(len(risk_threat[i])):
            print "Asset Name %s" % (enterprise_asset_list_given[asset_index])
            print "Risk Threat %s" % (risk_threat[i][j])
            print "Risk Threat Action %s" % (risk_threat_action[i][j])
            asset_index += 1



def printThreatImpact():
    print "hacking : %s " % (ProjectConfigFile.HACKING_COST)
    print "malware : %s " % (ProjectConfigFile.MALWARE_COST)
    print "social : %s " % (ProjectConfigFile.MALWARE_COST)
    print "error : %s " % (ProjectConfigFile.MALWARE_COST)
    print "physical : %s " % (ProjectConfigFile.MALWARE_COST)
    print "environmental : %s " % (ProjectConfigFile.MALWARE_COST)
    print "misuse : %s " % (ProjectConfigFile.MALWARE_COST)

def printAllStatistics(prob_threat,threat_threatAction_asset,prob_threat_action_threat,threat_threat_action_possible_pair):
    for threat in threat_threat_action_possible_pair.keys():
        print "___________________________All Possible threat action for this threat _____________________________"
        print threat_threat_action_possible_pair

    for asset in threat_threatAction_asset.keys():
        print "%s -----> "%(asset)
        for threat in threat_threatAction_asset[asset].keys():
            print "<--------  %s -----> " % (threat)
            print "Threat Probability : %s" % (prob_threat[asset][threat])
            print threat_threatAction_asset[asset][threat]
            print prob_threat_action_threat[asset][threat]
            print threat_threat_action_possible_pair[threat]

def printAllStatisticsGivenAssets(prob_threat,threat_threatAction_asset,prob_threat_action_threat,threat_threat_action_possible_pair,enterprise_asset_list_given):
    for threat in threat_threat_action_possible_pair.keys():
        print "___________________________All Possible threat action for this threat _____________________________"
        print threat_threat_action_possible_pair

    for asset in enterprise_asset_list_given:
        print "\n%s -----> \n"%(asset)
        for threat in threat_threatAction_asset[asset].keys():
            print "<--------  %s -----> " % (threat)
            print "Threat Probability : %s" % (prob_threat[asset][threat])
            print threat_threatAction_asset[asset][threat]
            print prob_threat_action_threat[asset][threat]
            print threat_threat_action_possible_pair[threat]


def printThreatThreatActionStatistics(threat_threatAction_asset,prob_threat_threat_action):
    for asset in threat_threatAction_asset.keys():
        print "%s -----> "%(asset)
        for threat_action in prob_threat_threat_action[asset].keys():
            print " %s -----> " % (threat_action)
            for threat in prob_threat_threat_action[asset][threat_action].keys():
                print "    %s -----> " % (threat)
                print "             (%s,%s)" %(threat_threatAction_asset[asset][threat][threat_action],prob_threat_threat_action[asset][threat_action][threat])
    print "Unknown Threat Action %s" % (prob_threat_threat_action[asset][ProjectConfigFile.THREAT_ACTION_UNKNOWN_TAG])


def printNumberStatisticsThreatThreatAction(threat_threatAction_asset):
    for asset in threat_threatAction_asset:
        print "\nAsset Name : %s" % (asset)
        for threat in threat_threatAction_asset[asset].keys():
            print "   Threat : %s ---> %s"%(threat,threat_threatAction_asset[asset][threat])
            if len(threat_threatAction_asset[asset][threat]) ==1 and (ProjectConfigFile.THREAT_ACTION_UNKNOWN_TAG in threat_threatAction_asset[asset][threat].keys()):
                print "************************* Alarm **************************************************************************"

def printNumberStatisticsThreatThreatActionWithProb(prob_threat,threat_threatAction_asset,prob_threat_action_threat):
    for asset in threat_threatAction_asset:
        print "\nAsset Name : %s" % (asset)
        for threat in threat_threatAction_asset[asset].keys():
            print "   Threat : %s ---> %s"%(threat,prob_threat[asset][threat])
            print "                     %s" % (threat_threatAction_asset[asset][threat])
            print "                     %s" % (prob_threat_action_threat[asset][threat])
            if len(threat_threatAction_asset[asset][threat]) ==1 and (ProjectConfigFile.THREAT_ACTION_UNKNOWN_TAG in threat_threatAction_asset[asset][threat].keys()):
                print "************************* Alarm **************************************************************************"

def printSecurityControlThreatmapping(security_control_list,security_control_version_to_id,threat_action_list):
    for sec_control in security_control_list:
        print "\nPrimary Key : %s == ID : %s" % (sec_control.primary_key,security_control_version_to_id[sec_control.sc_version])
        print "Version : %s" % (sec_control.sc_version)
        print "Expense : %s" % (sec_control.investment_cost)
        print "Number of Threat Action : %s" % (sec_control.number_threat_action)
        print "Threat Action --> "
        for i in range(sec_control.number_threat_action):
            print "                    ",
            print "ID : %s --> TA_Name : %s" % (sec_control.threat_action[i],threat_action_list[sec_control.threat_action[i]].threat_action_name)

def printThreatSecurityControlMapping(threat_action_list,threat_action_name_to_id,security_control_list,risk_threat_action,enterprise_asset_list_given):
    zero_security_control = []
    for threat in threat_action_list:
        print "\nPrimary Key : %s === ID : %s" % (threat.primary_key,threat_action_name_to_id[threat.threat_action_name])
        print "Threat Action Name : %s" % (threat.threat_action_name)
        print "Risk Imposed on Asset -->"
        for i in range(len(enterprise_asset_list_given)):
            if threat.threat_action_name not in risk_threat_action[i]:
                continue
            print "                         ",
            print "Asset Name : %s Risk Value : %s " % (
            enterprise_asset_list_given[i], risk_threat_action[i][threat.threat_action_name])
        if len(threat.applicable_security_controls) == 0:
            zero_security_control.append(threat.threat_action_name)
            continue
        print "Security Control -->"
        for i in range(len(threat.applicable_security_controls)):
            print "                         ",
            print "ID : %s ---> Security Control Version : %s %s" % (threat.applicable_security_controls[i],security_control_list[threat.applicable_security_controls[i]].sc_version,threat.security_control_index[threat.applicable_security_controls[i]])


    print "No Security Control Assigned Yet : ---> "
    print zero_security_control

def printSelectThreatActionName(threat_action_name_list,threat_action_list):
    for i in range(len(threat_action_name_list)):
        print "\nAsset ID ----> %s\n" % (i)
        for threat_action in threat_action_name_list[i]:
            print "                                 ",
            print "ID %s : %s ---> Risk Value: %s" %(threat_action[0],threat_action_list[threat_action[0]].threat_action_name,threat_action[1])

def printSelectedSecurityControls(security_control_list,selected_security_controls,security_control_cost_effectiveness):
    for asset in range(len(selected_security_controls)):
        print "\nName of the asset ::: %s ------> " % (asset)
        for sec_con in selected_security_controls[asset]:
            print "                              ",
            print "Security Control ID : %s ---> Cost : %s" % (sec_con,security_control_list[sec_con].investment_cost)
            # print "\t \t \tThreat Action Coverage %s" % (security_control_list[sec_con].global_asset_threat_action_list[asset])
            # print "\t \t \tThreat Action Effectiveness %s" % (security_control_list[sec_con].threat_action_effectiveness)
            # print "\t \t \tSecurity Control Cost Effectiveness %s == %s" % (security_control_list[sec_con].global_asset_effectiveness[asset]
            #                                                                 ,security_control_cost_effectiveness[asset][sec_con])

        print ""

def printAssetList(asset_eneterprise_list):
    for i in range(len(asset_eneterprise_list)):
        if i == ProjectConfigFile.VERIS_LIST:
            print "*************************** VERIS LIST ***************************"
        if i == ProjectConfigFile.EXPERIENCE_LIST:
            print "*************************** Experience LIST ***********************"
        for asset in asset_eneterprise_list[i]:
            print asset


def printThreatAction(risk_threat,risk_threat_action,prob_threat_experience,prob_threat_action_threat_experience):
    print "Prob Threat Experience %s" % (prob_threat_experience)
    print "Prob Threat Action Experience %s" % (prob_threat_action_threat_experience)
    for i in range(2):
        print "Risk %s" % (risk_threat[i])
        print "Risk Threat Action %s" % (risk_threat_action[i])

def printAssetProbThreatActionVeris(prob_threat,prob_threat_threat_action,prob_threat_action_threat,enterprise_asset_list_given):
    for asset in enterprise_asset_list_given:
        if asset in prob_threat_threat_action.keys():
            print "Prob Threat %s" % (prob_threat[asset])
            print "Prob Threat Action Given Threat %s" % (prob_threat_action_threat[asset])
            print "Prob Threat Given Threat Action %s" % (prob_threat_threat_action[asset])

def printAssetProbThreatActionExperience(prob_threat_experience,prob_threat_threat_action_experience,prob_threat_action_threat_experience,enterprise_asset_list_given):
    for asset in enterprise_asset_list_given:
        if asset in prob_threat_action_threat_experience.keys():
            print "Prob Threat Experience %s" % (prob_threat_experience[asset])
            print "Prob Threat Action Given Threat Experience %s" % (prob_threat_action_threat_experience[asset])
            print "Prob Threat Given Threat Action Experience %s" % (prob_threat_threat_action_experience[asset])

def printThreatActionNameToId(threat_action_name_to_id):
    for threat_action in threat_action_name_to_id.keys():
        print "Threat Action Name %s : ID %s" % (threat_action,threat_action_name_to_id[threat_action])

def printThreatProperties(threat_list):
    for threat in threat_list:
        print "Threat Name %s" % (threat.threat_name)
        print threat.asset_threat_action_distribution

def printThreatActionNameListIter(threat_action_name_list):
    print "Threat Action List"
    for i in range(len(threat_action_name_list)):
        print "Asset Index %s" % (i)
        # print "Threat Action List\n %s" % (threat_action_name_list[i])
        for j in range(len(threat_action_name_list[i])):
            print "Threat Action %s ----> %s" % (j,threat_action_name_list[i][j])

def printThreatIdForAllAssets(threat_id_for_all_assets,threat_list):
    for i in threat_list:
        print "Key %s : %s" % (i.primary_key,i.threat_name)
    print "Selected Threat ID"
    for i in range(len(threat_id_for_all_assets)):
        print "Asset Index %s : %s" % (i,threat_id_for_all_assets[i])

def printAssetList(asset_list):
    for i in range(len(asset_list)):
        print "Asset Index %s -----> " % (i)
        print asset_list[i]

def printRiskPerThreatStatistics(risk):
    for risk_row in risk:
            print "Asset name %s" % (risk_row['asset_name'])
            print "Residual Risk %s" % (risk_row['res_risk'])
            print "Implementation Cost %s" % (risk_row['imp_cost'])
            print "Threat Action %s" % (risk_row['threat_list'])

def printThreatActionList(threat_action_id_list_for_all_assets):
    for asset_index in range(len(threat_action_id_list_for_all_assets)):
        print "\t Asset Index :%s \n\t \tThreat Actoin List %s" % (asset_index,threat_action_id_list_for_all_assets[asset_index])

def printRiskThreatAction(risk_threat_action,asset_enterprise_list):
    for i in range(len(asset_enterprise_list)):
        for j in range(len(asset_enterprise_list[i])):
            print "Asset Name : %s" % (asset_enterprise_list[i][j])
            for threat_action in risk_threat_action[i][j].keys():
                print "    Threat Action %s ----> %s" % (threat_action,risk_threat_action[i][j][threat_action])


def calculateRiskRatioBasedOnSelectedThreatAction(threat_action_id_list_for_all_assets,risk_threat_action,threat_action_id_to_name):
    asset_index = 0
    risk_ratio_threat_action = []
    total_risk = 0.0
    for i in range(len(risk_threat_action)):
        for j in range(len(risk_threat_action[i])):
            risk_ratio_threat_action.append(0.0)
            for threat_action_id in threat_action_id_list_for_all_assets[asset_index]:
                if threat_action_id_to_name[threat_action_id] not in risk_threat_action[i][j].keys():
                    print "(^_^)(^_^)(^_^)(^_^)Error: Why %s (threat action id: %s) not in the risk_threat_action_list" % (threat_action_id_to_name[threat_action_id],threat_action_id)
                risk_ratio_threat_action[asset_index] += risk_threat_action[i][j][threat_action_id_to_name[threat_action_id]]
            # print risk_ratio_threat_action[asset_index]
            total_risk += risk_ratio_threat_action[asset_index]
            asset_index += 1

    number_of_asset = asset_index

    for asset_index in range(number_of_asset):
        risk_ratio_threat_action[asset_index] /= total_risk
    return risk_ratio_threat_action

def calculateKConstant(risk_ratio_threat_action, cost_effectiveness_sc,resource_available,max_cost_asset,k_based_cost_allocation,updated_risk_ratio):
    print "Updated Risk Ratio %s" % (updated_risk_ratio)
    constant_k_list = []
    for asset_index in range(len(max_cost_asset)):
        if cost_effectiveness_sc[asset_index] == 0 or\
                        risk_ratio_threat_action[asset_index]==0 or\
                        max_cost_asset[asset_index] ==0 or k_based_cost_allocation[asset_index] >= max_cost_asset[asset_index]:
            constant_k_list.append(0.0)
            continue
        constant_k_list.append(pow(risk_ratio_threat_action[asset_index]/updated_risk_ratio,2) * sqrt(max_cost_asset[asset_index]-k_based_cost_allocation[asset_index])/cost_effectiveness_sc[asset_index])
    constant_k = sum(constant_k_list)
    if constant_k <> 0 :
        constant_k = resource_available / constant_k
    print "Value of Constant K %s" % (constant_k)
    for asset_index in range(len(max_cost_asset)):
        k_based_cost_allocation[asset_index] += constant_k * constant_k_list[asset_index]
    print "Resource Provided %s Total Distribution %s" % (resource_available,sum(k_based_cost_allocation))
    return constant_k

def rationalCostAllocation(security_control_list,selected_security_controls,risk_ratio_threat_action,cost_effectiveness_sc,alloted_cost_asset_specific,budget):
    max_cost_asset = []
    for asset_index in range(len(selected_security_controls)):
        max_cost_asset.append(0.0)
        for sec_control in selected_security_controls[asset_index]:
            max_cost_asset[asset_index] += security_control_list[sec_control].investment_cost

    k_based_cost_allocation = [0.0 for i in range(len(selected_security_controls))]
    updated_risk_ratio = 1.0
    resource_available = budget
    contant_k = calculateKConstant(risk_ratio_threat_action, cost_effectiveness_sc, resource_available, max_cost_asset,k_based_cost_allocation,updated_risk_ratio)
    updated_risk_ratio = 0.0
    rest_cost = 0
    cost_starving = []
    rest_cost_k_based = 0
    for asset_index in range(len(selected_security_controls)):
        # print "Alloted Cost %s <------> Max Cost %s" % (alloted_cost_asset_specific[asset_index],max_cost_asset[asset_index])
        # print "Risk Ratio %s <-------> Cost Effectiveness %s" % (risk_ratio_threat_action[asset_index],cost_effectiveness_sc[asset_index])
        if max_cost_asset[asset_index] < alloted_cost_asset_specific[asset_index]:
            rest_cost += alloted_cost_asset_specific[asset_index] - max_cost_asset[asset_index]
            cost_starving.append(asset_index)
        # print "K Based Cost Allocation ::::: %s" % (k_based_cost_allocation[asset_index])
        if max_cost_asset[asset_index] < k_based_cost_allocation[asset_index]:
            rest_cost_k_based += k_based_cost_allocation[asset_index] - max_cost_asset[asset_index]
            k_based_cost_allocation[asset_index] = max_cost_asset[asset_index]
        elif max_cost_asset[asset_index] > k_based_cost_allocation[asset_index]:
            updated_risk_ratio += risk_ratio_threat_action[asset_index]
    print "Unnecessary K Cost Allocation %s" % (rest_cost_k_based)

    if rest_cost_k_based > ProjectConfigFile.K_THRESHOLD:
        while(True):
            resource_available = rest_cost_k_based
            rest_cost_k_based = 0
            constant_k_updated = calculateKConstant(risk_ratio_threat_action,cost_effectiveness_sc,resource_available,max_cost_asset,k_based_cost_allocation,updated_risk_ratio)
            updated_risk_ratio = 0.0
            for asset_index in range(len(selected_security_controls)):
                if max_cost_asset[asset_index] < k_based_cost_allocation[asset_index]:
                    rest_cost_k_based += k_based_cost_allocation[asset_index] - max_cost_asset[asset_index]
                    k_based_cost_allocation[asset_index] = max_cost_asset[asset_index]
                elif max_cost_asset[asset_index] > k_based_cost_allocation[asset_index]:
                    updated_risk_ratio += risk_ratio_threat_action[asset_index]
            print "Unnecessary K Cost Allocation %s" % (rest_cost_k_based)
            if abs(resource_available-rest_cost_k_based) <= ProjectConfigFile.K_THRESHOLD or rest_cost_k_based <= ProjectConfigFile.K_THRESHOLD:
                break


    print "Unnecessary Allocation %s" % (rest_cost)
    print "Unnecessary Allocation K Based %s" % (rest_cost_k_based)
    print "Cost Starving %s" % (cost_starving)
    for asset_index in range(len(selected_security_controls)):
        print "Alloted Cost %s <------> Max Cost %s K Based Cost %s" % (alloted_cost_asset_specific[asset_index], max_cost_asset[asset_index],k_based_cost_allocation[asset_index])

def appendStatsInFile(components):
    """ Components should be in (Asset,Total Risk,Maximum Achievable Risk,Residual Risk,Implementation Cost,Computation Time in Sec) Format"""
    append_file_iteration_index = open(ProjectConfigFile.OUTPUT_STATISTICAL_FILE_NAME,'a')
    # print "Components %s" % (components)
    for comp in components[:-1]:
        append_file_iteration_index.write("%s,"%(comp))
    # append_file_iteration_index.write("%s," % (ProjectConfigFile.RISK_ELIMINATION))
    append_file_iteration_index.write("%s\n" % (components[-1]))
    append_file_iteration_index.close()

def appendTimeRiskStatsInFile(components,max_sec_control_threat_action_index):
    """ Components should be in (Assets,Total Risk,Maximum Achievable Risk,Budget,Implementation Cost,Residual Risk,Time,Threat Elimination,Security Controls) Format"""
    # print "()() Components %s" % (components)
    append_file_iteration_index = open(ProjectConfigFile.OUTPUT_TIME_MIN_RISK_FILE_NAME, 'a')
    # print "Components %s" % (components)
    for comp in components[:-1]:
        append_file_iteration_index.write("%s," % (comp))
    append_file_iteration_index.write("%s,"%(max_sec_control_threat_action_index))
    append_file_iteration_index.write("%s\n" % (components[-1]))
    append_file_iteration_index.close()

def determineSizeCandidateSet(selected_security_controls):
    total_size = 0
    for i in range(len(selected_security_controls)):
        total_size += len(selected_security_controls[i])
    return total_size

def chosen_security_controls_threat_action_classified(selected_security_controls_length,threat_action_name_list,threat_action_list,security_control_list):
    classified_selected_security_controls_threat_action = []
    for asset_index in range(selected_security_controls_length):
        classified_selected_security_controls_threat_action_asset_specific = {}
        threat_action_index = 0
        for threat_action in threat_action_name_list[asset_index]:
            classified_selected_security_controls_threat_action_asset_specific[threat_action[0]] = [threat_action[1]]
            for security_control in threat_action_list[threat_action[0]].applicable_security_controls:
                if threat_action[1] < security_control_list[security_control].investment_cost:
                    continue
                if security_control not in classified_selected_security_controls_threat_action_asset_specific:
                    classified_selected_security_controls_threat_action_asset_specific[threat_action[0]].append(security_control)
            threat_action_index += 1


        classified_selected_security_controls_threat_action.append(classified_selected_security_controls_threat_action_asset_specific)
    # printClassifiedSecurityControl_ThreatAction(classified_selected_security_controls_threat_action)
    return classified_selected_security_controls_threat_action

def printClassifiedSecurityControl_ThreatAction(classified_selected_security_controls_threat_action,threat_action_id_to_name):
    asset_index = 0
    for sc_asset_specific in classified_selected_security_controls_threat_action:
        print "Asset Index %s" % (asset_index)
        for threat_action_id in sc_asset_specific.keys():
            print "\t Threat Action ID %s :: %s ---> " % (threat_action_id,threat_action_id_to_name[threat_action_id])
            print "\t \t \t Security Controls %s" % (sc_asset_specific[threat_action_id])
            if len(sc_asset_specific[threat_action_id])==0:
                print "Threat Action Error : ******* \t \t &&&&&&&&&&&&& %s &&&&&&&&&&&&& \t \t *******" % (threat_action_id_to_name[threat_action_id])
        asset_index += 1

def prune_security_controls_list(classified_selected_security_controls_threat_action,security_control_list,
                                 selected_security_controls,security_control_cost_effectiveness,max_sec_control_threat_action_index):
    number_of_asset = len(selected_security_controls)
    for asset_index in range(number_of_asset):
        number_ta_asset = len(classified_selected_security_controls_threat_action[asset_index])
        ta_frequency = {ta:0 for ta in classified_selected_security_controls_threat_action[asset_index]}

        sorted_sec_control_by_effectivenes = sorted(security_control_cost_effectiveness[asset_index],
                                                 key=security_control_cost_effectiveness[asset_index].__getitem__,reverse=True)
        # print "Asset Index %s" % (asset_index)
        # for sec_con in sorted_sec_control_by_effectivenes:
        #     print "\t \tSecurity Control ID %s : %s" % (sec_con,security_control_cost_effectiveness[asset_index][sec_con])

        pruned_selected_security_controls_asset = []
        for index in range(len(sorted_sec_control_by_effectivenes)):
            sec_con = sorted_sec_control_by_effectivenes[index]
            if index < max_sec_control_threat_action_index:
                pruned_selected_security_controls_asset.append(sorted_sec_control_by_effectivenes[index])
                for ta in security_control_list[sec_con].global_asset_threat_action_list[asset_index]:
                    if ta in ta_frequency.keys():
                        ta_frequency[ta] += 1
            else:
                ta_sec_length = len(security_control_list[sec_con].global_asset_threat_action_list[asset_index])
                for ta_index in range(ta_sec_length):
                     ta = security_control_list[sec_con].global_asset_threat_action_list[asset_index][ta_index]
                     if ta not in ta_frequency.keys():
                         continue
                     if ta_frequency[ta] < max_sec_control_threat_action_index:
                         pruned_selected_security_controls_asset.append(sec_con)
                         for change_ta_index in range(ta_index,ta_sec_length):
                             change_ta = security_control_list[sec_con].global_asset_threat_action_list[asset_index][change_ta_index]
                             if change_ta in ta_frequency.keys():
                                 ta_frequency[change_ta] += 1

        # print "TA Frequency %s" % (ta_frequency)
        # print "Previous Selected Security Controls %s" % (selected_security_controls[asset_index])
        selected_security_controls[asset_index] = pruned_selected_security_controls_asset
        # print "Pruned Selected Security Controls %s" % (selected_security_controls[asset_index])

def printPrunedSelectedSecurityControlsWithProperties(security_control_list,selected_security_controls):
    security_function_cost = [0.0 for i in range(len(ProjectConfigFile.SECURITY_FUNCTION_TO_ID))]
    en_level_cost = [0.0 for i in range(len(ProjectConfigFile.ENFORCEMENT_LEVEL_TO_ID))]
    kc_phase_cost = [0.0 for i in range(len(ProjectConfigFile.KILL_CHAIN_PHASE_TO_ID))]
    security_function_cost_Asset_Specific = [[0.0 for i in range(len(ProjectConfigFile.SECURITY_FUNCTION_TO_ID))] for i in range(len(selected_security_controls))]
    en_level_cost_Asset_Specific = [[0.0 for i in range(len(ProjectConfigFile.ENFORCEMENT_LEVEL_TO_ID))] for i in range(len(selected_security_controls))]
    kc_phase_cost_Asset_Specific = [[0.0 for i in range(len(ProjectConfigFile.KILL_CHAIN_PHASE_TO_ID))] for i in range(len(selected_security_controls))]
    total_cost = 0.0
    for asset_index in range(len(selected_security_controls)):
        # print "\nAsset Index %s --> %s"%(asset_index,selected_security_controls[asset_index])
        for sec_id in selected_security_controls[asset_index]:
            security_control_obj = security_control_list[sec_id]
            # security_control_list[sec_id].printCDMProperties()
            ################################################ Global Cost ##############################################
            security_function_cost[security_control_obj.sc_function] += security_control_obj.investment_cost
            en_level_cost[security_control_obj.en_level] += security_control_obj.investment_cost
            kc_phase_cost[security_control_obj.kc_phase] += security_control_obj.investment_cost

            ################################################# Asset Specific Dimension Based Cost ##############################
            security_function_cost_Asset_Specific[asset_index][security_control_obj.sc_function] += security_control_obj.investment_cost
            en_level_cost_Asset_Specific[asset_index][security_control_obj.en_level] += security_control_obj.investment_cost
            kc_phase_cost_Asset_Specific[asset_index][security_control_obj.kc_phase] += security_control_obj.investment_cost
            total_cost += security_control_obj.investment_cost

    security_function_cost_distribution = [security_function_cost[i]/sum(security_function_cost) for i in range(len(ProjectConfigFile.SECURITY_FUNCTION_TO_ID))]
    en_level_cost_distribution = [en_level_cost[i]/sum(en_level_cost) for i in range(len(ProjectConfigFile.ENFORCEMENT_LEVEL_TO_ID))]
    kc_phase_cost_distribution = [kc_phase_cost[i]/sum(kc_phase_cost) for i in range(len(ProjectConfigFile.KILL_CHAIN_PHASE_TO_ID))]

    # print("************************************** Check the cost Distribution*****************************************")
    # print("$$$$$$$$$$$$$$$ Global Total Costs : %s $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" % (total_cost))
    # print("\t\t Global Security Function Cost : %s" % (security_function_cost))
    # print("\t\t Global Security Function Cost Distribution : %s" % (security_function_cost_distribution))
    # print("\t\t Global Enforcement Level Cost : %s" % (en_level_cost))
    # print("\t\t Global Enforcement Level Cost Distribution : %s" % (en_level_cost_distribution))
    # print("\t\t Global Kill Chain Phase Cost : %s" % (kc_phase_cost))
    # print("\t\t Global Kill Chain Phase Cost Distribution : %s" % (kc_phase_cost_distribution))
    return [[security_function_cost,en_level_cost,kc_phase_cost],
            [kc_phase_cost_Asset_Specific,en_level_cost_Asset_Specific,security_function_cost_Asset_Specific]]

def build_constraints(asset_enterprise_list,selected_security_controls):
    all_smt_constraints = {}
    if ProjectConfigFile.COST_DISTRIBUTION_CONSTRAINT_ENABLED:
        all_smt_constraints[ProjectConfigFile.COST_DISTRIBUTION_PROPERTIES] = ProjectConfigFile.cost_constraint_development()
    if ProjectConfigFile.ASSET_BASED_DISTRIBUTION_CONSTRAINT_ENABLED:
        all_smt_constraints[ProjectConfigFile.ASSET_BASED_DISTRIBUTION_PROPERTIES] = \
            ProjectConfigFile.asset_based_distribution_development(asset_enterprise_list,selected_security_controls)
    return all_smt_constraints

def verify_cost_reult(cost_distribution_CDM):
    print "Cost Distribution SMT Output %s" % (cost_distribution_CDM)
    for i in range(3):
        print "Total Implementaion Cost from Distribution %s" % (sum(cost_distribution_CDM[i]))

def build_Dynamic_Constraint(all_smt_constraints,asset_specific_constraints_asset_id):
    dynamic_constraint_builder = {}
    for property_constraint_name in all_smt_constraints.keys():
        dynamic_constraint_builder[property_constraint_name] = []
        if property_constraint_name == ProjectConfigFile.COST_DISTRIBUTION_PROPERTIES:
            for axis_name in range(ProjectConfigFile.NUMBER_OF_AXIS):
                constraints_placements = [index_non_zero for index_non_zero, val in
                                          enumerate(all_smt_constraints[property_constraint_name][axis_name]) if
                                          val != 0.0]
                for rank_cons in constraints_placements:
                    print "Axis : %s --> Rank : %s" % (axis_name, rank_cons)
                    dynamic_constraint_builder[property_constraint_name].append((axis_name, rank_cons,all_smt_constraints[property_constraint_name][axis_name][rank_cons]))
        if property_constraint_name == ProjectConfigFile.ASSET_BASED_DISTRIBUTION_PROPERTIES:
            print "Asset Specific Constraints %s" % (asset_specific_constraints_asset_id)
            all_asset_specific_cons = all_smt_constraints[ProjectConfigFile.ASSET_BASED_DISTRIBUTION_PROPERTIES]
            for asset_specific_cons in asset_specific_constraints_asset_id:
                for asset_specific_cons_iter in all_asset_specific_cons[asset_specific_cons]:
                    dynamic_constraint_builder[property_constraint_name].append(asset_specific_cons_iter)
    return dynamic_constraint_builder

def test_properties_smt_constraints(smt_properties,constraint_properties):
    print("SMT Properties %s" % (smt_properties))
    print("Constraint properties %s" % (constraint_properties))
    for asset_index in smt_properties.keys():
        print("Asset Name %s " % (asset_index))
        print "Maximum Cost %s" % (constraint_properties[0][asset_index])
        cons_proper = smt_properties[asset_index]
        for cons_prop_iter in cons_proper:
            print "Property %s" % (cons_proper)
            print "Alloted Cost For Specific One %s : Cons Value %s" % (constraint_properties[0][asset_index],cons_prop_iter[2])
            print "Alloted Cost For Specific One %s : Cons Value %s" % (
            constraint_properties[1][asset_index], cons_prop_iter[2])
            print "Alloted Cost For Specific One %s : Cons Value %s" % (
            constraint_properties[2][asset_index], cons_prop_iter[2])