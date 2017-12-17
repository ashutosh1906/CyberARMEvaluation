import ProjectConfigFile
######################################################### Calculate Risk ###########################################################
def calculateRiskExperience(prob_threat_experience,prob_threat_action_threat_experience,asset_enterprise_list,risk_threat_action_experience,risk_threat_experience):
    global_risk_threat = 0.0
    for asset_des in asset_enterprise_list:
        asset_name = asset_des[0]
        asset_value = asset_des[1]
        risk_threat_action_asset = {}
        risk_threat_asset = {}
        if asset_name not in prob_threat_action_threat_experience.keys():
            asset_name = ProjectConfigFile.OTHER_ASSET
        for threat in prob_threat_action_threat_experience[asset_name].keys():
            impact_threat = (float(asset_value[0]) * ((ProjectConfigFile.THREAT_MAP_COST[threat] & 1))) + (
            float(asset_value[1]) * ((ProjectConfigFile.THREAT_MAP_COST[threat] & 2) >> 1)) + \
                            (float(asset_value[2]) * ((ProjectConfigFile.THREAT_MAP_COST[threat] & 4) >> 2))
            ############################## Updated Line ##################################################
            risk_threat_asset[threat] = 1
            prob_threat_action_threat_asset_local = 0.0
            for threat_action in prob_threat_action_threat_experience[asset_name][threat].keys():
                risk_threat_asset[threat] *= (1 - prob_threat_action_threat_experience[asset_name][threat][threat_action])
            risk_threat_asset[threat] = (1 - risk_threat_asset[threat]) * impact_threat * prob_threat_experience[asset_name][
                threat]
            ############################## Updated Line ##################################################
            for threat_action in prob_threat_action_threat_experience[asset_name][threat].keys():
                if threat_action not in risk_threat_action_asset.keys():
                    risk_threat_action_asset[threat_action] = 0
                prob_threat_action_threat_asset_local += prob_threat_action_threat_experience[asset_name][threat][threat_action]

                risk_threat_action_asset[threat_action] += prob_threat_action_threat_experience[asset_name][threat][
                                                               threat_action] * risk_threat_asset[threat]
            # print "Probability Threat Action of Threat: %s against Asset: %s Values: %s" % (threat,asset_name,prob_threat_action_threat_asset_local)
            global_risk_threat += risk_threat_asset[threat]
        risk_threat_action_experience.append(risk_threat_action_asset)
        risk_threat_experience.append(risk_threat_asset)
    print "Experience Total Risk %s" % (global_risk_threat)


######################################################## Calculate threat action probability given threat ########################################################################

######################################################### Exclude the unknown ##################################################################
def distribute_Unknown(asset_name,threat_name,threat_action_distribution):
    threat_distribution = 0
    for threat_action in threat_action_distribution.keys():
        threat_distribution += threat_action_distribution[threat_action]
    # print "Sum ",
    # print threat_distribution
    if threat_distribution > float(1.000001):
        print "Caution :-----%s (GReater than 1 for threat: %s against Asset: %s)"%(threat_distribution,threat_name,asset_name)

    if ProjectConfigFile.THREAT_ACTION_UNKNOWN_TAG in threat_action_distribution.keys():
        unknown_dist = threat_action_distribution[ProjectConfigFile.THREAT_ACTION_UNKNOWN_TAG]
        threat_distribution -= unknown_dist
        if threat_distribution == 0:
            return
        threat_action_distribution[ProjectConfigFile.THREAT_ACTION_UNKNOWN_TAG] = float(0)
        for threat_action in threat_action_distribution.keys():
            threat_action_distribution[threat_action] += (threat_action_distribution[threat_action]/threat_distribution)*unknown_dist

    threat_distribution = 0
    for threat_action in threat_action_distribution.keys():
        threat_distribution += threat_action_distribution[threat_action]
    # print "Sum ",
    # print threat_distribution
    if threat_distribution > float(1.00001):
        print "Caution :-----%s (GReater than 1 for threat: %s against Asset: %s)" % (
        threat_distribution, threat_name, asset_name)


######################################################### Probability Distributor ##################################################################
def calculate_threatAction_threat_prob_distribution_experience(prob_threat_experience, prob_threat_action_threat_experience,asset_enterprise_list):
    for asset in asset_enterprise_list:
        print "Asset Index %s" % (asset[2])
        asset_name = asset[0]
        threat_threat_action_asset_experience = asset[2]
        prob_threat_action_threat_experience[asset_name] = {}
        prob_threat_experience[asset_name] = {}
        sum_threat_for_asset = 0
        ###################################################### Collect all threat threat action in probability distribution ############################################
        for threat in threat_threat_action_asset_experience.keys():
            total_threat = 0
            prob_threat_action_threat_experience[asset_name][threat] = {}
            for threat_action in threat_threat_action_asset_experience[threat].keys():
                prob_threat_action_threat_experience[asset_name][threat][threat_action] = float(threat_threat_action_asset_experience[threat][threat_action])
                total_threat += float(threat_threat_action_asset_experience[threat][threat_action])

            ######################################################## Now calculate the probability ###########################################################################
            for threat_action in threat_threat_action_asset_experience[threat].keys():
                prob_threat_action_threat_experience[asset_name][threat][threat_action] /= float(total_threat)
            # distribute_Unknown(asset_name,threat,prob_threat_action_threat[asset_name][threat])

            if threat not in prob_threat_experience[asset_name].keys():
                prob_threat_experience[asset_name][threat] = 0
            prob_threat_experience[asset_name][threat] += total_threat
            sum_threat_for_asset += total_threat

        for threat in prob_threat_experience[asset_name].keys():
            prob_threat_experience[asset_name][threat] /= float(sum_threat_for_asset)
######################################################## End of alculation of threat action probability given threat ########################################################################

######################################################################## Calculate threat given threat action and asset ###########################################################

######################################################### 1.2 Probability Distributor ##################################################################
def calculate_threat_threatAction_prob_distribution_experience(prob_threat_threat_action_experience, asset_enterprise_list):
    for asset in asset_enterprise_list:
        asset_name = asset[0]
        threat_threatAction_asset_experience = asset[2]
        if asset_name not in prob_threat_threat_action_experience.keys():
            prob_threat_threat_action_experience[asset_name] = {}
        for threat in threat_threatAction_asset_experience.keys():
            for threat_action in threat_threatAction_asset_experience[threat].keys():
                if threat_action not in prob_threat_threat_action_experience[asset_name]:
                    prob_threat_threat_action_experience[asset_name][threat_action] = {}
                if threat not in prob_threat_threat_action_experience[asset_name][threat_action].keys():
                    prob_threat_threat_action_experience[asset_name][threat_action][threat] = 0
                prob_threat_threat_action_experience[asset_name][threat_action][threat] += float(threat_threatAction_asset_experience[threat][threat_action])


        for threat_action in prob_threat_threat_action_experience[asset_name].keys():
            total_threat = 0
            for threat in prob_threat_threat_action_experience[asset_name][threat_action].keys():
                total_threat += prob_threat_threat_action_experience[asset_name][threat_action][threat]
            for threat in prob_threat_threat_action_experience[asset_name][threat_action].keys():
                prob_threat_threat_action_experience[asset_name][threat_action][threat] /= float(total_threat)


def threat_prioritization_main(prob_threat_experience,prob_threat_threat_action_experience,prob_threat_action_threat_experience,risk_threat_action_experience,risk_threat_experience,asset_enterprise_list):
    # print "Asset Enterprise List %s" % (asset_enterprise_list)
    calculate_threatAction_threat_prob_distribution_experience(prob_threat_experience, prob_threat_action_threat_experience, asset_enterprise_list)
    calculate_threat_threatAction_prob_distribution_experience(prob_threat_threat_action_experience, asset_enterprise_list)
    calculateRiskExperience(prob_threat_experience,prob_threat_action_threat_experience,asset_enterprise_list,risk_threat_action_experience,risk_threat_experience)